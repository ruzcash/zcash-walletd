use crate::account::{Account, AccountBalance, SubAccount};
use crate::lwd_rpc::BlockId;
use crate::network::Network;
use crate::scan::{ScanEvent, POOL_ORCHARD, POOL_SAPLING};
use crate::transaction::{SubAddress, Transfer};
use crate::{notify_tx, Client, Hash};
use anyhow::Result;
use sqlx::sqlite::{SqliteConnectOptions, SqliteRow};
use sqlx::{Acquire, Row, SqliteConnection, SqlitePool};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tonic::Request;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

/// Schema of `received_notes`. Kept in one place because the pool migration rebuilds the table
/// from it (SQLite cannot alter a table constraint in place).
const RECEIVED_NOTES_DDL: &str = "CREATE TABLE IF NOT EXISTS received_notes (
    id_note INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    account INTEGER,
    sub_account INTEGER,
    id_tx INTEGER NOT NULL,
    pool INTEGER NOT NULL,
    position INTEGER NOT NULL,
    height INTEGER NOT NULL,
    diversifier BLOB NOT NULL,
    value INTEGER NOT NULL,
    rcm BLOB NOT NULL,
    nf BLOB NOT NULL,
    rho BLOB,
    memo TEXT,
    spent_height INTEGER,
    CONSTRAINT tx_output UNIQUE (pool, position),
    CONSTRAINT note_nullifier UNIQUE (pool, nf))";
const IRONWOOD_REPLAY_KEY: &str = "ironwood_replay_complete";

pub struct Db {
    network: Network,
    pool: SqlitePool,
    ufvk: UnifiedFullViewingKey,
    notify_tx_url: String,
    address_creation_lock: Mutex<()>,
    scan_lock: Mutex<()>,
}

impl Db {
    pub async fn new(
        network: Network,
        db_path: &str,
        ufvk: &UnifiedFullViewingKey,
        notify_tx_url: &str,
    ) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await?;
        Ok(Db {
            network,
            pool,
            ufvk: ufvk.clone(),
            notify_tx_url: notify_tx_url.to_string(),
            address_creation_lock: Mutex::new(()),
            scan_lock: Mutex::new(()),
        })
    }

    /// Migrate a pre-NU6.3 `received_notes` table to the pool-aware schema.
    ///
    /// Note positions are only unique *within* a pool's commitment tree, and Ironwood's tree
    /// starts from zero when NU6.3 activates — so its early positions collide head-on with the
    /// low Sapling/Orchard positions a wallet may already hold, and the old
    /// `UNIQUE (position)` constraint would reject the insert and wedge the scan. Record the
    /// note's pool and key the constraint on `(pool, position)` instead.
    ///
    /// SQLite can't alter a table constraint in place, so rebuild the table. The pool of an
    /// existing row is recoverable without rescanning: `rho` is only ever set for
    /// Orchard-family notes, so a NULL `rho` means Sapling. No pre-migration row can be
    /// Ironwood — the pool did not exist.
    async fn migrate_received_notes_pool(connection: &mut SqliteConnection) -> Result<bool> {
        let has_pool =
            sqlx::query("SELECT 1 FROM pragma_table_info('received_notes') WHERE name = 'pool'")
                .fetch_optional(&mut *connection)
                .await?
                .is_some();
        let has_spent_height = sqlx::query(
            "SELECT 1 FROM pragma_table_info('received_notes') WHERE name = 'spent_height'",
        )
        .fetch_optional(&mut *connection)
        .await?
        .is_some();
        if has_pool && has_spent_height {
            return Ok(false);
        }
        log::info!("Migrating received_notes to the pool-aware (NU6.3) schema");

        let mut db_transaction = connection.begin().await?;
        let db_tx = db_transaction.acquire().await?;
        let (before_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM received_notes")
            .fetch_one(&mut *db_tx)
            .await?;
        sqlx::query(&RECEIVED_NOTES_DDL.replace("received_notes", "received_notes_new"))
            .execute(&mut *db_tx)
            .await?;
        let pool = if has_pool {
            "pool"
        } else {
            "CASE WHEN rho IS NULL THEN ?1 ELSE ?2 END"
        };
        let spent_height = if has_spent_height {
            "spent_height"
        } else {
            "CASE WHEN spent IS NULL OR spent = 0 THEN NULL ELSE 0 END"
        };
        let copy = format!(
            "INSERT INTO received_notes_new
            (id_note, address, account, sub_account, id_tx, pool, position, height,
            diversifier, value, rcm, nf, rho, memo, spent_height)
            SELECT id_note, address, account, sub_account, id_tx, {pool},
            position, height, diversifier, value, rcm, nf, rho, memo, {spent_height}
            FROM received_notes"
        );
        let mut copy = sqlx::query(&copy);
        if !has_pool {
            copy = copy.bind(POOL_SAPLING).bind(POOL_ORCHARD);
        }
        copy.execute(&mut *db_tx).await?;
        sqlx::query("DROP TABLE received_notes")
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("ALTER TABLE received_notes_new RENAME TO received_notes")
            .execute(&mut *db_tx)
            .await?;
        let (after_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM received_notes")
            .fetch_one(&mut *db_tx)
            .await?;
        anyhow::ensure!(
            before_count == after_count,
            "received_notes migration lost rows"
        );
        db_transaction.commit().await?;

        Ok(true)
    }

    pub async fn new_account(&self, name: &str) -> Result<Account> {
        let _guard = self.address_creation_lock.lock().await;
        let mut connection = self.pool.acquire().await?;
        let (id_account,): (Option<u32>,) = sqlx::query_as("SELECT MAX(account) FROM addresses")
            .fetch_one(&mut *connection)
            .await?;
        let id_account = id_account.map(|id| id + 1).unwrap_or(0);
        let (diversifier_index, address) = self.next_diversifier(&mut connection).await?;
        self.store_receivers(
            &mut connection,
            name,
            id_account,
            0,
            diversifier_index,
            &address,
        )
        .await?;

        let account = Account {
            account_index: id_account,
            address,
        };
        Ok(account)
    }

    pub async fn new_sub_account(&self, id_account: u32, name: &str) -> Result<SubAccount> {
        let _guard = self.address_creation_lock.lock().await;
        let mut connection = self.pool.acquire().await?;
        let (id_sub_account,): (u32,) =
            sqlx::query_as("SELECT MAX(sub_account) FROM addresses WHERE account = ?1")
                .bind(id_account)
                .fetch_one(&mut *connection)
                .await?;
        let id_sub_account = id_sub_account + 1;
        let (diversifier_index, address) = self.next_diversifier(&mut connection).await?;
        self.store_receivers(
            &mut connection,
            name,
            id_account,
            id_sub_account,
            diversifier_index,
            &address,
        )
        .await?;

        let sub_account = SubAccount {
            account_index: id_account,
            sub_account_index: id_sub_account,
            address,
        };
        Ok(sub_account)
    }

    async fn store_receivers(
        &self,
        connection: &mut SqliteConnection,
        name: &str,
        id_account: u32,
        id_sub_account: u32,
        diversifier_index: u64,
        address: &str,
    ) -> Result<()> {
        let r = sqlx::query("INSERT INTO addresses(label, account, sub_account, address, diversifier_index) VALUES (?1,?2,?3,?4,?5)")
            .bind(name)
            .bind(id_account)
            .bind(id_sub_account)
            .bind(address)
            .bind(diversifier_index as i64)
            .execute(&mut *connection)
            .await?;
        let id_address = r.last_insert_rowid() as u32;

        let ua = UnifiedAddress::decode(&self.network, address).unwrap();
        if let Some(address) = ua.sapling() {
            sqlx::query(
                "INSERT INTO receivers(pool, id_address, receiver_address)
                VALUES (1, ?1, ?2)",
            )
            .bind(id_address)
            .bind(address.encode(&self.network))
            .execute(&mut *connection)
            .await?;
        }
        if let Some(address) = ua.orchard() {
            let ua = UnifiedAddress::from_receivers(Some(*address), None, None).unwrap();
            sqlx::query(
                "INSERT INTO receivers(pool, id_address, receiver_address)
                VALUES (2, ?1, ?2)",
            )
            .bind(id_address)
            .bind(ua.encode(&self.network))
            .execute(&mut *connection)
            .await?;
        }

        Ok(())
    }

    pub async fn get_accounts(
        &self,
        height: u32,
        confirmations: u32,
    ) -> Result<Vec<AccountBalance>> {
        let mut connection = self.pool.acquire().await?;
        let confirmed_height = height.saturating_sub(confirmations.saturating_sub(1));
        let sub_accounts = sqlx::query(
            "WITH base AS (SELECT account, address FROM addresses WHERE sub_account = 0), \
                balances AS (SELECT account, SUM(value) AS total from received_notes WHERE spent_height IS NULL GROUP BY account), \
                unlocked_balances AS (SELECT account, SUM(value) AS unlocked from received_notes WHERE spent_height IS NULL AND height <= ?1 GROUP BY account) \
                SELECT a.account, a.label, b.total, COALESCE(u.unlocked, 0) AS unlocked, base.address as base_address \
                FROM addresses a JOIN balances b ON a.account = b.account LEFT JOIN unlocked_balances u ON u.account = a.account JOIN base ON base.account = a.account GROUP BY a.account")
            .bind(confirmed_height)
            .map(|row: SqliteRow| {
                let id_account: u32 = row.get(0);
                let label: String = row.get(1);
                let balance: u64 = row.get(2);
                let unlocked: u64 = row.get(3);
                let base_address: String = row.get(4);
                AccountBalance {
                    account_index: id_account,
                    label,
                    balance,
                    unlocked_balance: unlocked,
                    base_address,
                    tag: "".to_string(),
                }
            })
            .fetch_all(&mut *connection)
            .await?;

        Ok(sub_accounts)
    }

    pub async fn get_synced_height(&self) -> Result<u32> {
        let mut connection = self.pool.acquire().await?;
        let height = sqlx::query("SELECT MAX(height) FROM blocks")
            .map(|row: SqliteRow| {
                let h: Option<u32> = row.get(0);
                h.unwrap_or_else(|| {
                    u32::from(
                        self.network
                            .activation_height(NetworkUpgrade::Sapling)
                            .unwrap(),
                    )
                })
            })
            .fetch_one(&mut *connection)
            .await?;
        Ok(height)
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<Option<[u8; 32]>> {
        let mut connection = self.pool.acquire().await?;

        let hash = sqlx::query("SELECT hash FROM blocks WHERE height = ?1")
            .bind(height)
            .map(|row: SqliteRow| {
                let hash_vec: Vec<u8> = row.get(0);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_vec);
                hash
            })
            .fetch_optional(&mut *connection)
            .await?;
        Ok(hash)
    }

    fn row_to_transfer(
        row: SqliteRow,
        latest_height: u32,
        account_index: u32,
        confirmations: u32,
    ) -> Transfer {
        let address: String = row.get(0);
        let value: u64 = row.get(1);
        let sub_account: u32 = row.get(2);
        let mut txid: Vec<u8> = row.get(3);
        txid.reverse();
        let memo: String = row.get(4);
        let height: u32 = row.get(5);
        Transfer {
            address,
            amount: value,
            confirmations: latest_height.saturating_sub(height).saturating_add(1),
            height,
            fee: 0,
            note: memo,
            payment_id: "".to_string(),
            subaddr_index: SubAddress {
                major: account_index,
                minor: sub_account,
            },
            suggested_confirmations_threshold: confirmations,
            timestamp: 0, // TODO: Check if needed
            txid: hex::encode(txid),
            r#type: "in".to_string(),
            unlock_time: 0,
        }
    }

    pub async fn get_transfers(
        &self,
        latest_height: u32,
        account_index: u32,
        sub_accounts: &[u32],
        confirmations: u32,
    ) -> Result<Vec<Transfer>> {
        let mut connection = self.pool.acquire().await?;

        let transfers = sqlx::query(
            "SELECT address, n.value, sub_account, txid, memo, n.height \
            FROM received_notes n JOIN transactions t ON n.id_tx = t.id_tx WHERE \
            account = ?1 ORDER BY n.height",
        )
        .bind(account_index)
        .map(|row| Self::row_to_transfer(row, latest_height, account_index, confirmations))
        .fetch_all(&mut *connection)
        .await?;

        let transfers = transfers
            .into_iter()
            .filter(|transfer| sub_accounts.contains(&transfer.subaddr_index.minor))
            .collect::<Vec<_>>();
        Ok(transfers)
    }

    pub async fn get_transfers_by_txid(
        &self,
        latest_height: u32,
        txid: &str,
        account_index: u32,
        confirmations: u32,
    ) -> Result<Vec<Transfer>> {
        let mut connection = self.pool.acquire().await?;

        let mut txid = hex::decode(txid)?;
        txid.reverse();
        let transfers = sqlx::query(
            "SELECT a.address, n.value, n.sub_account, txid, memo, n.height
            FROM received_notes n
			JOIN transactions t ON n.id_tx = t.id_tx
			JOIN receivers r ON n.address = r.receiver_address
			JOIN addresses a ON a.id_address = r.id_address
            WHERE txid = ?1
			ORDER BY n.height",
        )
        .bind(txid)
        .map(|row| Self::row_to_transfer(row, latest_height, account_index, confirmations))
        .fetch_all(&mut *connection)
        .await?;
        Ok(transfers)
    }

    pub async fn truncate_height(&self, height: u32) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        Self::truncate_to_checkpoint(&mut connection, height).await?;
        Ok(())
    }

    async fn truncate_to_checkpoint(connection: &mut SqliteConnection, height: u32) -> Result<u32> {
        let mut transaction = connection.begin().await?;
        let db_tx = transaction.acquire().await?;
        let (checkpoint,): (Option<u32>,) = sqlx::query_as(
            "SELECT COALESCE(
                (SELECT MAX(height) FROM blocks WHERE height < ?1),
                (SELECT MIN(height) FROM blocks))",
        )
        .bind(height)
        .fetch_one(&mut *db_tx)
        .await?;
        let checkpoint = checkpoint
            .ok_or_else(|| anyhow::anyhow!("no wallet checkpoint exists below height {height}"))?;

        sqlx::query("DELETE FROM received_notes WHERE height > ?1")
            .bind(checkpoint)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("DELETE FROM transactions WHERE height > ?1")
            .bind(checkpoint)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("DELETE FROM blocks WHERE height > ?1")
            .bind(checkpoint)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("UPDATE received_notes SET spent_height = NULL WHERE spent_height > ?1")
            .bind(checkpoint)
            .execute(&mut *db_tx)
            .await?;

        transaction.commit().await?;
        Ok(checkpoint)
    }

    pub async fn rewind_for_ironwood(&self, height: u32, hash: &Hash) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await?;
        let db_tx = transaction.acquire().await?;

        sqlx::query("DELETE FROM received_notes WHERE height > ?1")
            .bind(height)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("UPDATE transactions SET value = 0 WHERE height > ?1")
            .bind(height)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("DELETE FROM blocks WHERE height > ?1")
            .bind(height)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query("UPDATE received_notes SET spent_height = NULL WHERE spent_height > ?1")
            .bind(height)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query(
            "INSERT INTO blocks(height, hash) VALUES (?1, ?2)
             ON CONFLICT(height) DO UPDATE SET hash = excluded.hash",
        )
        .bind(height)
        .bind(hash.as_slice())
        .execute(&mut *db_tx)
        .await?;
        sqlx::query("INSERT OR REPLACE INTO wallet_metadata(key, value) VALUES (?1, '1')")
            .bind(IRONWOOD_REPLAY_KEY)
            .execute(&mut *db_tx)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn complete_ironwood_replay(&self) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO wallet_metadata(key, value) VALUES (?1, '1')")
            .bind(IRONWOOD_REPLAY_KEY)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn fetch_block_hash(&self, client: &mut Client, height: u32) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        if sqlx::query("SELECT 1 FROM blocks WHERE height = ?1")
            .bind(height)
            .fetch_optional(&mut *connection)
            .await?
            .is_none()
        {
            let hash = Self::fetch_canonical_block_hash(client, height).await?;
            sqlx::query(
                "INSERT INTO blocks(hash, height)
            VALUES (?1, ?2)",
            )
            .bind(hash.as_slice())
            .bind(height)
            .execute(&mut *connection)
            .await?;
        }
        Ok(())
    }

    pub async fn fetch_canonical_block_hash(client: &mut Client, height: u32) -> Result<Hash> {
        let block = client
            .get_block(Request::new(BlockId {
                height: u64::from(height),
                hash: vec![],
            }))
            .await?
            .into_inner();
        anyhow::ensure!(block.height == u64::from(height), "unexpected block height");
        block.hash.try_into().map_err(|hash: Vec<u8>| {
            anyhow::anyhow!(
                "block hash must contain exactly 32 bytes, got {}",
                hash.len()
            )
        })
    }

    pub async fn get_nfs(&self) -> Result<HashMap<(u8, [u8; 32]), u64>> {
        let mut connection = self.pool.acquire().await?;
        let rows = sqlx::query(
            "SELECT pool, nf, value FROM received_notes
                 WHERE spent_height IS NULL OR spent_height = 0",
        )
        .fetch_all(&mut *connection)
        .await?;
        let mut nf_map = HashMap::new();
        for row in rows {
            let pool: u8 = row.try_get(0)?;
            let nf: Vec<u8> = row.try_get(1)?;
            let value: u64 = row.try_get(2)?;
            let nf: Hash = nf.try_into().map_err(|nf: Vec<u8>| {
                anyhow::anyhow!(
                    "stored nullifier must contain exactly 32 bytes, got {}",
                    nf.len()
                )
            })?;
            nf_map.insert((pool, nf), value);
        }
        Ok(nf_map)
    }

    async fn next_diversifier(&self, connection: &mut SqliteConnection) -> Result<(u64, String)> {
        let di = sqlx::query("SELECT MAX(diversifier_index) FROM addresses")
            .map(|r: SqliteRow| r.get::<Option<u64>, _>(0))
            .fetch_one(&mut *connection)
            .await?
            .map(|di| di + 1)
            .unwrap_or_default();
        let (ua, ndi) = self
            .ufvk
            .find_address(di.into(), UnifiedAddressRequest::AllAvailableKeys)?;
        let ua = ua.encode(&self.network);
        let ndi: u64 = ndi.try_into().unwrap();
        Ok((ndi, ua))
    }

    pub async fn create(&self) -> Result<(bool, bool)> {
        let mut connection = self.pool.acquire().await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS wallet_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            hash BLOB NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS addresses (
            id_address INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            account INTEGER NOT NULL,
            sub_account INTEGER NOT NULL,
            address TEXT NOT NULL,
            diversifier_index INTEGER NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS receivers (
            id_receiver INTEGER PRIMARY KEY,
            pool INTEGER NOT NULL,
            id_address INTEGER NOT NULL,
            receiver_address TEXT NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS transactions (
            id_tx INTEGER PRIMARY KEY,
            txid BLOB NOT NULL UNIQUE,
            height INTEGER NOT NULL,
            value INTEGER NOT NULL)",
        )
        .execute(&mut *connection)
        .await?;

        sqlx::query(RECEIVED_NOTES_DDL)
            .execute(&mut *connection)
            .await?;

        if sqlx::query("SELECT 1 FROM pragma_table_info('received_notes') WHERE name = 'rho'")
            .fetch_optional(&mut *connection)
            .await?
            .is_none()
        {
            panic!("Old database schema. This version is not compatible with it.");
        }

        Self::migrate_received_notes_pool(&mut connection).await?;
        let ironwood_replay_pending = sqlx::query("SELECT 1 FROM wallet_metadata WHERE key = ?1")
            .bind(IRONWOOD_REPLAY_KEY)
            .fetch_optional(&mut *connection)
            .await?
            .is_none();

        let r = sqlx::query("SELECT 1 FROM addresses")
            .map(|r: SqliteRow| r.get::<u32, _>(0))
            .fetch_optional(&mut *connection)
            .await?;

        Ok((r.is_some(), ironwood_replay_pending))
    }

    pub async fn store_events(&self, events: &[ScanEvent]) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        let mut db_transaction = connection.begin().await?;
        let db_tx = db_transaction.acquire().await?;
        let mut notify_txids = vec![];

        for event in events {
            match event {
                ScanEvent::Received(received_note) => {
                    let (id_tx, is_new) = self
                        .create_tx_if_not_exists(
                            received_note.height,
                            received_note.txid.as_slice(),
                            db_tx,
                        )
                        .await?;
                    if is_new {
                        notify_txids.push(received_note.txid);
                    }

                    let (account, sub_account) = match sqlx::query(
                        "SELECT a.account, a.sub_account FROM addresses a
                        JOIN receivers r ON a.id_address = r.id_address
                        WHERE r.receiver_address = ?1",
                    )
                    .bind(&received_note.address)
                    .map(|r: SqliteRow| {
                        let account: u32 = r.get(0);
                        let sub_account: u32 = r.get(1);
                        (account, sub_account)
                    })
                    .fetch_optional(&mut *db_tx)
                    .await?
                    {
                        Some(x) => x,
                        None => {
                            let account = sqlx::query("SELECT MAX(account) FROM addresses")
                                .map(|r: SqliteRow| {
                                    let account: Option<u32> = r.get(0);
                                    account.unwrap_or_default()
                                })
                                .fetch_one(&mut *db_tx)
                                .await?;
                            let sub_account = sqlx::query(
                                "SELECT MAX(sub_account) FROM addresses WHERE account = ?1",
                            )
                            .bind(account)
                            .map(|r: SqliteRow| {
                                let sub_account: Option<u32> = r.get(0);
                                sub_account.map(|x| x + 1).unwrap_or_default()
                            })
                            .fetch_optional(&mut *db_tx)
                            .await?
                            .unwrap_or_default();

                            let r = sqlx::query(
                                "INSERT INTO addresses
                            (label, account, sub_account, address, diversifier_index)
                            VALUES ('', ?1, ?2, ?3, ?4)",
                            )
                            .bind(account)
                            .bind(sub_account)
                            .bind(&received_note.address)
                            .bind(received_note.diversifier_index.unwrap_or_default() as u32)
                            .execute(&mut *db_tx)
                            .await?;
                            let id_address = r.last_insert_rowid() as u32;

                            sqlx::query(
                                "INSERT INTO receivers(pool, id_address, receiver_address)
                                VALUES (?1, ?2, ?3)",
                            )
                            .bind(received_note.pool)
                            .bind(id_address)
                            .bind(&received_note.address)
                            .execute(&mut *db_tx)
                            .await?;

                            (account, sub_account)
                        }
                    };

                    sqlx::query(
                        "INSERT INTO received_notes
                        (address, account, sub_account, id_tx, pool, position, height,
                        diversifier, value, rcm, nf, rho, memo, spent_height)
                        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'',NULL)",
                    )
                    .bind(&received_note.address)
                    .bind(account)
                    .bind(sub_account)
                    .bind(id_tx)
                    .bind(received_note.pool)
                    .bind(received_note.position)
                    .bind(received_note.height)
                    .bind(received_note.diversifier.as_slice())
                    .bind(received_note.value as i64)
                    .bind(received_note.rcm.as_slice())
                    .bind(received_note.nf.as_slice())
                    .bind(received_note.rho.map(|r| r.to_vec()))
                    .execute(&mut *db_tx)
                    .await?;
                    sqlx::query("UPDATE transactions SET value = value + ?2 WHERE txid = ?1")
                        .bind(received_note.txid.as_slice())
                        .bind(received_note.value as i64)
                        .execute(&mut *db_tx)
                        .await?;
                }
                ScanEvent::Spent(spent_note) => {
                    let (_, is_new) = self
                        .create_tx_if_not_exists(
                            spent_note.height,
                            spent_note.txid.as_slice(),
                            db_tx,
                        )
                        .await?;
                    if is_new {
                        notify_txids.push(spent_note.txid);
                    }
                    sqlx::query(
                        "UPDATE received_notes SET spent_height = ?3
                         WHERE pool = ?1 AND nf = ?2",
                    )
                    .bind(spent_note.pool)
                    .bind(spent_note.nf.as_slice())
                    .bind(spent_note.height)
                    .execute(&mut *db_tx)
                    .await?;
                    sqlx::query("UPDATE transactions SET value = value - ?2 WHERE txid = ?1")
                        .bind(spent_note.txid.as_slice())
                        .bind(spent_note.value as i64)
                        .execute(&mut *db_tx)
                        .await?;
                }
                ScanEvent::Memo(memo_note) => {
                    sqlx::query("UPDATE received_notes SET memo = ?3 WHERE pool = ?1 AND nf = ?2")
                        .bind(memo_note.pool)
                        .bind(memo_note.nf.as_slice())
                        .bind(&memo_note.memo)
                        .execute(&mut *db_tx)
                        .await?;
                }
                ScanEvent::Block(height, hash) => {
                    sqlx::query(
                        "INSERT INTO blocks(height, hash)
                        VALUES (?1, ?2)",
                    )
                    .bind(*height)
                    .bind(hash.as_slice())
                    .execute(&mut *db_tx)
                    .await?;
                }
            }
        }
        db_transaction.commit().await?;

        // Once committed, we can notify our listeners of the new received
        // txs
        for txid in notify_txids {
            notify_tx(&txid, &self.notify_tx_url).await?;
        }

        Ok(())
    }

    pub async fn create_tx_if_not_exists(
        &self,
        height: u32,
        txid: &[u8],
        db_tx: &mut SqliteConnection,
    ) -> Result<(u32, bool)> {
        // let txid = &received_note.txid;
        let result = match sqlx::query("SELECT id_tx FROM transactions WHERE txid = ?1")
            .bind(txid)
            .map(|r: SqliteRow| r.get::<u32, _>(0))
            .fetch_optional(&mut *db_tx)
            .await?
        {
            Some(id_tx) => (id_tx, false),
            None => {
                let r =
                    sqlx::query("INSERT INTO transactions(txid, height, value) VALUES (?1, ?2, 0)")
                        .bind(txid)
                        .bind(height)
                        .execute(db_tx)
                        .await?;
                let id_tx = r.last_insert_rowid();

                (id_tx as u32, true)
            }
        };

        Ok(result)
    }

    pub fn ufvk(&self) -> &UnifiedFullViewingKey {
        &self.ufvk
    }

    pub async fn lock_scan(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.scan_lock.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::POOL_IRONWOOD;
    use sqlx::Connection;

    /// The pre-NU6.3 `received_notes` schema: no `pool` column, and note positions constrained
    /// to be unique across every pool.
    const LEGACY_DDL: &str = "CREATE TABLE received_notes (
        id_note INTEGER PRIMARY KEY,
        address TEXT NOT NULL,
        account INTEGER,
        sub_account INTEGER,
        id_tx INTEGER NOT NULL,
        position INTEGER NOT NULL,
        height INTEGER NOT NULL,
        diversifier BLOB NOT NULL,
        value INTEGER NOT NULL,
        rcm BLOB NOT NULL,
        nf BLOB NOT NULL UNIQUE,
        rho BLOB,
        memo TEXT,
        spent INTEGER,
        CONSTRAINT tx_output UNIQUE (position))";

    const PR63_DDL: &str = "CREATE TABLE received_notes (
        id_note INTEGER PRIMARY KEY,
        address TEXT NOT NULL,
        account INTEGER,
        sub_account INTEGER,
        id_tx INTEGER NOT NULL,
        pool INTEGER NOT NULL,
        position INTEGER NOT NULL,
        height INTEGER NOT NULL,
        diversifier BLOB NOT NULL,
        value INTEGER NOT NULL,
        rcm BLOB NOT NULL,
        nf BLOB NOT NULL UNIQUE,
        rho BLOB,
        memo TEXT,
        spent INTEGER,
        CONSTRAINT tx_output UNIQUE (pool, position))";

    async fn insert_legacy_note(
        connection: &mut SqliteConnection,
        position: u32,
        nf: &[u8],
        rho: Option<&[u8]>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO received_notes
            (address, account, sub_account, id_tx, position, height,
            diversifier, value, rcm, nf, rho, memo, spent)
            VALUES ('addr',0,0,1,?1,100,x'00',1000,x'00',?2,?3,'',0)",
        )
        .bind(position)
        .bind(nf)
        .bind(rho)
        .execute(&mut *connection)
        .await?;
        Ok(())
    }

    async fn insert_note(
        connection: &mut SqliteConnection,
        pool: u8,
        position: u32,
        nf: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO received_notes
            (address, account, sub_account, id_tx, pool, position, height,
            diversifier, value, rcm, nf, rho, memo, spent_height)
            VALUES ('addr',0,0,1,?1,?2,100,x'00',1000,x'00',?3,NULL,'',NULL)",
        )
        .bind(pool)
        .bind(position)
        .bind(nf)
        .execute(&mut *connection)
        .await?;
        Ok(())
    }

    /// The migration must (a) recover each existing note's pool without a rescan and (b) key the
    /// uniqueness constraint on `(pool, position)`. Ironwood's commitment tree restarts note
    /// positions from zero at the NU6.3 activation height, so under the legacy
    /// `UNIQUE (position)` constraint the first Ironwood receives would collide with the
    /// wallet's low Sapling/Orchard positions and fail the whole scan batch.
    #[tokio::test]
    async fn migration_backfills_pools_and_rekeys_the_position_constraint() -> Result<()> {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
        sqlx::query(LEGACY_DDL).execute(&mut connection).await?;
        // `rho` is set only on Orchard-family notes, which is what makes the pool of a
        // pre-migration row recoverable.
        insert_legacy_note(&mut connection, 7, b"sapling-nf", None).await?;
        insert_legacy_note(&mut connection, 9, b"orchard-nf", Some(b"rho")).await?;

        assert!(Db::migrate_received_notes_pool(&mut connection).await?);

        let pools: Vec<(Vec<u8>, u8)> = sqlx::query("SELECT nf, pool FROM received_notes")
            .map(|r: SqliteRow| (r.get(0), r.get(1)))
            .fetch_all(&mut connection)
            .await?;
        assert_eq!(
            pools,
            vec![
                (b"sapling-nf".to_vec(), POOL_SAPLING),
                (b"orchard-nf".to_vec(), POOL_ORCHARD),
            ]
        );

        // An Ironwood note at a position already used by another pool is now accepted...
        insert_note(&mut connection, POOL_IRONWOOD, 7, b"ironwood-nf").await?;
        insert_note(&mut connection, POOL_SAPLING, 8, b"ironwood-nf").await?;
        // ...while a genuine duplicate within one pool is still rejected.
        assert!(
            insert_note(&mut connection, POOL_IRONWOOD, 7, b"ironwood-nf-2")
                .await
                .is_err()
        );

        // Re-running the migration is a no-op.
        assert!(!Db::migrate_received_notes_pool(&mut connection).await?);
        let (count,): (u32,) = sqlx::query_as("SELECT COUNT(*) FROM received_notes")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(count, 4);

        Ok(())
    }

    #[tokio::test]
    async fn pr63_upgrade_rewinds_once_and_preserves_replay_state() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "zcash-walletd-pr63-upgrade-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &Network::Main,
            &[0; 32],
            zip32::AccountId::ZERO,
        )?
        .to_unified_full_viewing_key();
        let db = Db::new(Network::Main, &path.to_string_lossy(), &ufvk, "").await?;
        let activation_height = u32::from(
            Network::Main
                .activation_height(NetworkUpgrade::Nu6_3)
                .unwrap(),
        );
        let rewind_height = activation_height - 1;

        {
            let mut connection = db.pool.acquire().await?;
            sqlx::query(PR63_DDL).execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash BLOB NOT NULL)")
                .execute(&mut *connection)
                .await?;
            sqlx::query(
                "CREATE TABLE addresses (
                    id_address INTEGER PRIMARY KEY, label TEXT NOT NULL,
                    account INTEGER NOT NULL, sub_account INTEGER NOT NULL,
                    address TEXT NOT NULL, diversifier_index INTEGER NOT NULL)",
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "CREATE TABLE transactions (
                    id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL UNIQUE,
                    height INTEGER NOT NULL, value INTEGER NOT NULL)",
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query("INSERT INTO addresses VALUES (1, '', 0, 0, 'addr', 0)")
                .execute(&mut *connection)
                .await?;
            sqlx::query("INSERT INTO blocks VALUES (?1, x'01'), (?2, x'02')")
                .bind(rewind_height)
                .bind(activation_height + 10)
                .execute(&mut *connection)
                .await?;
            sqlx::query(
                "INSERT INTO transactions VALUES
                    (1, x'01', ?1, 1000), (2, x'02', ?2, 2000)",
            )
            .bind(rewind_height - 1)
            .bind(activation_height + 5)
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "INSERT INTO received_notes
                (address, account, sub_account, id_tx, pool, position, height,
                diversifier, value, rcm, nf, rho, memo, spent)
                VALUES
                ('addr',0,0,1,2,7,?1,x'00',1000,x'00',
                    x'0101010101010101010101010101010101010101010101010101010101010101',
                    x'02','',1),
                ('addr',0,0,2,3,8,?2,x'00',2000,x'00',
                    x'0303030303030303030303030303030303030303030303030303030303030303',
                    x'04','',0)",
            )
            .bind(rewind_height - 1)
            .bind(activation_height + 5)
            .execute(&mut *connection)
            .await?;
        }

        assert_eq!(db.create().await?, (true, true));
        assert_eq!(db.get_nfs().await?.len(), 2);

        let canonical_hash = [9; 32];
        db.rewind_for_ironwood(rewind_height, &canonical_hash)
            .await?;

        let mut connection = db.pool.acquire().await?;
        let blocks: Vec<(u32, Vec<u8>)> = sqlx::query("SELECT height, hash FROM blocks")
            .map(|row: SqliteRow| (row.get(0), row.get(1)))
            .fetch_all(&mut *connection)
            .await?;
        assert_eq!(blocks, vec![(rewind_height, canonical_hash.to_vec())]);
        let transactions: Vec<(u32, i64)> =
            sqlx::query("SELECT height, value FROM transactions ORDER BY id_tx")
                .map(|row: SqliteRow| (row.get(0), row.get(1)))
                .fetch_all(&mut *connection)
                .await?;
        assert_eq!(
            transactions,
            vec![(rewind_height - 1, 1000), (activation_height + 5, 0)]
        );
        let notes: Vec<(u8, u32, Option<u32>)> =
            sqlx::query("SELECT pool, height, spent_height FROM received_notes ORDER BY id_note")
                .map(|row: SqliteRow| (row.get(0), row.get(1), row.get(2)))
                .fetch_all(&mut *connection)
                .await?;
        assert_eq!(notes, vec![(POOL_ORCHARD, rewind_height - 1, Some(0))]);
        drop(connection);

        assert_eq!(db.create().await?, (true, false));
        assert_eq!(db.get_nfs().await?.len(), 1);

        db.pool.close().await;
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    async fn reorg_rewinds_to_an_existing_checkpoint_atomically() -> Result<()> {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
        sqlx::query("CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash BLOB NOT NULL)")
            .execute(&mut connection)
            .await?;
        sqlx::query(
            "CREATE TABLE transactions (
                id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL UNIQUE,
                height INTEGER NOT NULL, value INTEGER NOT NULL)",
        )
        .execute(&mut connection)
        .await?;
        sqlx::query(
            "CREATE TABLE received_notes (
                id_note INTEGER PRIMARY KEY, height INTEGER NOT NULL, spent_height INTEGER)",
        )
        .execute(&mut connection)
        .await?;
        sqlx::query("INSERT INTO blocks VALUES (100, x'01'), (200, x'02')")
            .execute(&mut connection)
            .await?;
        sqlx::query(
            "INSERT INTO transactions VALUES
                (1, x'01', 90, 1), (2, x'02', 120, 1)",
        )
        .execute(&mut connection)
        .await?;
        sqlx::query(
            "INSERT INTO received_notes VALUES
                (1, 90, 120), (2, 120, NULL)",
        )
        .execute(&mut connection)
        .await?;

        assert_eq!(Db::truncate_to_checkpoint(&mut connection, 150).await?, 100);
        let (block_height,): (u32,) = sqlx::query_as("SELECT MAX(height) FROM blocks")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(block_height, 100);
        let transactions: Vec<u32> = sqlx::query("SELECT height FROM transactions")
            .map(|row: SqliteRow| row.get(0))
            .fetch_all(&mut connection)
            .await?;
        assert_eq!(transactions, vec![90]);
        let notes: Vec<(u32, Option<u32>)> =
            sqlx::query("SELECT height, spent_height FROM received_notes")
                .map(|row: SqliteRow| (row.get(0), row.get(1)))
                .fetch_all(&mut connection)
                .await?;
        assert_eq!(notes, vec![(90, None)]);
        assert_eq!(Db::truncate_to_checkpoint(&mut connection, 50).await?, 100);

        Ok(())
    }
}
