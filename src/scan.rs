use std::collections::HashMap;

use anyhow::{ensure, Context, Result};
use orchard::{
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{
        CompactAction, DomainVersion, IronwoodVersion, NoteEncryptionDomain, OrchardVersion,
    },
    primitives::redpallas::{Signature, SpendAuth},
    Action, Address,
};
use sapling_crypto::{
    bundle::OutputDescription,
    note_encryption::{SaplingDomain, Zip212Enforcement},
    zip32::DiversifiableFullViewingKey,
    NullifierDerivingKey, PaymentAddress,
};
use thiserror::Error;
use tonic::{transport::Channel, Request};
use zcash_address::unified::{self, Encoding};
use zcash_keys::{encoding::AddressCodec, keys::UnifiedFullViewingKey};
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
};
use zcash_primitives::{
    merkle_tree::{read_commitment_tree, HashSer},
    transaction::Transaction,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
};

use crate::{
    lwd_rpc::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainMetadata,
        ChainSpec, CompactOrchardAction, CompactSaplingOutput, Empty, TxFilter,
    },
    network::Network,
    Client, Hash,
};

/// Pool codes recorded on a received note (and on the `receivers` row derived from it).
pub const POOL_SAPLING: u8 = 1;
pub const POOL_ORCHARD: u8 = 2;
/// Ironwood (NU6.3). Ironwood notes are received at ordinary Orchard addresses — the pool
/// distinction lives at the bundle / note-version level, not in the address encoding — but
/// they live in their own commitment tree, so they need their own pool code to keep note
/// positions unambiguous.
pub const POOL_IRONWOOD: u8 = 3;

pub async fn get_latest_height(client: &mut CompactTxStreamerClient<Channel>) -> Result<u32> {
    let latest_block_id = client
        .get_latest_block(Request::new(ChainSpec {}))
        .await?
        .into_inner();
    u32::try_from(latest_block_id.height).context("latest block height exceeds u32")
}

fn chain_name_matches(network: &Network, chain_name: &str) -> bool {
    match network {
        Network::Main => chain_name.eq_ignore_ascii_case("main"),
        Network::Regtest => chain_name.eq_ignore_ascii_case("regtest"),
    }
}

fn parse_branch_id(branch_id: &str) -> Result<u32> {
    let branch_id = branch_id.trim();
    let branch_id = branch_id
        .strip_prefix("0x")
        .or_else(|| branch_id.strip_prefix("0X"))
        .unwrap_or(branch_id);
    u32::from_str_radix(branch_id, 16)
        .with_context(|| format!("invalid consensus branch id {branch_id:?}"))
}

fn validate_tree_sizes(
    metadata: &ChainMetadata,
    sapling: u32,
    orchard: u32,
    ironwood: u32,
    height: u32,
) -> Result<()> {
    ensure!(
        metadata.sapling_commitment_tree_size == sapling,
        "Sapling tree size mismatch at height {height}"
    );
    ensure!(
        metadata.orchard_commitment_tree_size == orchard,
        "Orchard tree size mismatch at height {height}"
    );
    ensure!(
        metadata.ironwood_commitment_tree_size == ironwood,
        "Ironwood tree size mismatch at height {height}"
    );
    Ok(())
}

pub async fn verify_lightwalletd_capability(
    network: &Network,
    client: &mut Client,
    height: u32,
) -> Result<()> {
    let info = client
        .get_lightd_info(Request::new(Empty {}))
        .await?
        .into_inner();
    ensure!(
        chain_name_matches(network, info.chain_name.trim()),
        "lightwalletd chain mismatch: {:?}",
        info.chain_name
    );
    let server_height = u32::try_from(info.block_height).context("block height exceeds u32")?;
    ensure!(
        server_height >= height,
        "lightwalletd is behind requested height {height}"
    );
    let expected_branch = u32::from(BranchId::for_height(
        network,
        BlockHeight::from_u32(server_height),
    ));
    ensure!(
        parse_branch_id(&info.consensus_branch_id)? == expected_branch,
        "lightwalletd consensus branch mismatch at height {server_height}"
    );

    if network.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(height)) {
        let block = client
            .get_block(Request::new(BlockId {
                height: u64::from(height),
                hash: vec![],
            }))
            .await?
            .into_inner();
        ensure!(
            block.height == u64::from(height),
            "unexpected capability block height"
        );
        let metadata = block
            .chain_metadata
            .context("lightwalletd did not return chain metadata")?;
        let tree_state = client
            .get_tree_state(Request::new(BlockId {
                height: u64::from(height),
                hash: vec![],
            }))
            .await?
            .into_inner();
        ensure!(
            tree_state.height == u64::from(height),
            "unexpected capability tree height"
        );
        ensure!(
            chain_name_matches(network, tree_state.network.trim()),
            "capability tree state is from a different chain"
        );
        ensure!(
            parse_display_hash("capability tree hash", &tree_state.hash)?
                == parse_hash("capability block hash", &block.hash)?,
            "capability block and tree state do not match"
        );
        validate_tree_sizes(
            &metadata,
            get_tree_size(&tree_state.sapling_tree)?,
            get_tree_size(&tree_state.orchard_tree)?,
            get_tree_size(&tree_state.ironwood_tree)?,
            height,
        )?;
    }

    Ok(())
}

/// The per-pool trial-decryption state carried across a scan.
pub struct Decoders {
    pub sapling: Option<Decoder<Sapling>>,
    pub orchard: Option<Decoder<Orchard>>,
    pub ironwood: Option<Decoder<Ironwood>>,
}

impl Decoders {
    /// Build the per-pool decoders for `ufvk`, seeded with the wallet's known nullifiers.
    pub fn new(ufvk: &UnifiedFullViewingKey, nfs: &HashMap<(u8, Hash), u64>) -> Self {
        let pool_nfs = |pool| {
            nfs.iter()
                .filter_map(|((note_pool, nf), value)| {
                    (*note_pool == pool).then_some((*nf, *value))
                })
                .collect::<HashMap<_, _>>()
        };
        let sapling_nfs = pool_nfs(POOL_SAPLING);
        let orchard_nfs = pool_nfs(POOL_ORCHARD);
        let ironwood_nfs = pool_nfs(POOL_IRONWOOD);
        let sapling = ufvk.sapling().map(|fvk| {
            let nk = fvk.fvk().vk.nk;
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Sapling>::new(nk, fvk.clone(), pivk, &sapling_nfs)
        });
        let orchard = ufvk.orchard().map(|fvk| {
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = orchard::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Orchard>::new(fvk.clone(), ivk, pivk, &orchard_nfs)
        });
        // Ironwood is received at the account's Orchard receivers and derives from the same
        // Orchard key material — only the note plaintext version and the commitment tree
        // differ — so its decoder is built from the very same FVK.
        let ironwood = ufvk.orchard().map(|fvk| {
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = orchard::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Ironwood>::new(fvk.clone(), ivk, pivk, &ironwood_nfs)
        });
        Decoders {
            sapling,
            orchard,
            ironwood,
        }
    }
}

fn parse_hash(field: &str, bytes: &[u8]) -> Result<Hash> {
    bytes
        .try_into()
        .with_context(|| format!("{field} must be exactly 32 bytes, got {}", bytes.len()))
}

fn parse_display_hash(field: &str, encoded: &str) -> Result<Hash> {
    let mut bytes = hex::decode(encoded).with_context(|| format!("invalid {field}"))?;
    bytes.reverse();
    parse_hash(field, &bytes)
}

fn verify_checkpoint_hash(encoded: &str, expected: &Hash) -> Result<(), ScanError> {
    let actual = parse_display_hash("pre-scan tree hash", encoded)?;
    if actual != *expected {
        return Err(ScanError::Reorganization);
    }
    Ok(())
}

fn position_with_offset(position: u32, offset: usize, pool: &str) -> Result<u32> {
    position
        .checked_add(u32::try_from(offset).context("output count exceeds u32")?)
        .with_context(|| format!("{pool} note position overflow"))
}

fn validate_compact_sapling_output(output: &CompactSaplingOutput) -> Result<()> {
    parse_hash("Sapling commitment", &output.cmu)?;
    parse_hash("Sapling ephemeral key", &output.epk)?;
    ensure!(
        output.ciphertext.len() == 52,
        "Sapling compact ciphertext must contain 52 bytes"
    );
    Ok(())
}

pub async fn scan(
    network: &Network,
    client: &mut Client,
    start: u32,
    end: u32,
    prev_hash: &Hash,
    decoders: &mut Decoders,
) -> Result<Vec<ScanEvent>, ScanError> {
    if start > end {
        return Err(anyhow::anyhow!("invalid scan range {start}..{end}").into());
    }
    verify_lightwalletd_capability(network, client, end).await?;

    let tree_height = start
        .checked_sub(1)
        .context("cannot scan from block zero")?;
    let tree_state = client
        .get_tree_state(Request::new(BlockId {
            height: u64::from(tree_height),
            hash: vec![],
        }))
        .await
        .map_err(|e| ScanError::Other(anyhow::Error::new(e)))?
        .into_inner();
    if tree_state.height != u64::from(tree_height) {
        return Err(anyhow::anyhow!("unexpected pre-scan tree height").into());
    }
    if !chain_name_matches(network, tree_state.network.trim()) {
        return Err(anyhow::anyhow!("pre-scan tree state is from a different chain").into());
    }
    verify_checkpoint_hash(&tree_state.hash, prev_hash)?;

    let mut blocks = client
        .get_block_range(Request::new(BlockRange {
            start: Some(BlockId {
                height: u64::from(start),
                hash: vec![],
            }),
            end: Some(BlockId {
                height: u64::from(end),
                hash: vec![],
            }),
            pool_types: vec![],
        }))
        .await
        .map_err(|e| ScanError::Other(anyhow::Error::new(e)))?
        .into_inner();
    let mut prev_hash = *prev_hash;
    let mut sap_position = get_tree_size(&tree_state.sapling_tree)?;
    let mut orc_position = get_tree_size(&tree_state.orchard_tree)?;
    let mut irw_position = get_tree_size(&tree_state.ironwood_tree)?;

    let mut events = vec![];
    let mut new_txids = vec![];
    let mut expected_height = u64::from(start);
    let mut last_height = None;
    while let Some(block) = blocks
        .message()
        .await
        .map_err(|e| ScanError::Other(anyhow::Error::new(e)))?
    {
        if block.height != expected_height {
            return Err(
                anyhow::anyhow!("expected block {expected_height}, got {}", block.height).into(),
            );
        }
        let height = u32::try_from(block.height).context("block height exceeds u32")?;
        let block_prev_hash = parse_hash("block previous hash", &block.prev_hash)?;
        if prev_hash != block_prev_hash {
            info!("Reorg at {} {}", block.height, hex::encode(block_prev_hash));
            return Err(ScanError::Reorganization);
        }
        prev_hash = parse_hash("block hash", &block.hash)?;

        for vtx in block.vtx.iter() {
            if !vtx.ironwood_actions.is_empty()
                && !network.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(height))
            {
                return Err(anyhow::anyhow!("Ironwood actions appeared before NU6.3").into());
            }
            let txid = parse_hash("transaction id", &vtx.hash)?;
            let mut found = false;
            if let Some(sap_dec) = decoders.sapling.as_mut() {
                for i in vtx.spends.iter() {
                    let nf = parse_hash("Sapling nullifier", &i.nf)?;
                    if let Some(value) = sap_dec.nfs.get(&nf) {
                        events.push(ScanEvent::Spent(SpentNote {
                            pool: POOL_SAPLING,
                            height,
                            nf,
                            txid,
                            value: *value,
                        }));
                    }
                }

                for (vout, o) in vtx.outputs.iter().enumerate() {
                    validate_compact_sapling_output(o)?;
                    if let Some(n) = sap_dec.try_compact_note_decryption(
                        network,
                        height,
                        &txid,
                        position_with_offset(sap_position, vout, "Sapling")?,
                        o,
                    )? {
                        sap_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            if let Some(orc_dec) = decoders.orchard.as_mut() {
                for (vout, a) in vtx.actions.iter().enumerate() {
                    let nf = parse_hash("Orchard nullifier", &a.nullifier)?;
                    if let Some(value) = orc_dec.nfs.get(&nf) {
                        events.push(ScanEvent::Spent(SpentNote {
                            pool: POOL_ORCHARD,
                            height,
                            nf,
                            txid,
                            value: *value,
                        }));
                    }
                    if let Some(n) = orc_dec.try_compact_note_decryption(
                        network,
                        height,
                        &txid,
                        position_with_offset(orc_position, vout, "Orchard")?,
                        a,
                    )? {
                        orc_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            if let Some(irw_dec) = decoders.ironwood.as_mut() {
                for (vout, a) in vtx.ironwood_actions.iter().enumerate() {
                    let nf = parse_hash("Ironwood nullifier", &a.nullifier)?;
                    if let Some(value) = irw_dec.nfs.get(&nf) {
                        events.push(ScanEvent::Spent(SpentNote {
                            pool: POOL_IRONWOOD,
                            height,
                            nf,
                            txid,
                            value: *value,
                        }));
                    }
                    if let Some(n) = irw_dec.try_compact_note_decryption(
                        network,
                        height,
                        &txid,
                        position_with_offset(irw_position, vout, "Ironwood")?,
                        a,
                    )? {
                        irw_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            if found {
                new_txids.push(WalletTx {
                    height,
                    txid,
                    sap_position,
                    orc_position,
                    irw_position,
                });
            }

            sap_position = position_with_offset(sap_position, vtx.outputs.len(), "Sapling")?;
            orc_position = position_with_offset(orc_position, vtx.actions.len(), "Orchard")?;
            irw_position =
                position_with_offset(irw_position, vtx.ironwood_actions.len(), "Ironwood")?;
        }

        let metadata = block
            .chain_metadata
            .as_ref()
            .context("compact block is missing chain metadata")?;
        validate_tree_sizes(metadata, sap_position, orc_position, irw_position, height)?;
        last_height = Some(height);
        expected_height += 1;
    }

    if last_height != Some(end) || expected_height != u64::from(end) + 1 {
        return Err(anyhow::anyhow!("compact block stream ended before block {end}").into());
    }

    for wtx in new_txids.iter() {
        let memos = scan_tx(network, client, wtx, decoders).await?;
        for m in memos {
            events.push(ScanEvent::Memo(m));
        }
    }
    events.push(ScanEvent::Block(end, prev_hash));

    Ok(events)
}

pub async fn scan_tx(
    network: &Network,
    client: &mut Client,
    wtx: &WalletTx,
    decoders: &Decoders,
) -> Result<Vec<MemoNote>> {
    let mut notes = vec![];
    let raw_tx = client
        .get_transaction(Request::new(TxFilter {
            hash: wtx.txid.to_vec(),
            ..TxFilter::default()
        }))
        .await?
        .into_inner();
    ensure!(
        raw_tx.height == u64::from(wtx.height),
        "raw transaction height does not match its compact block"
    );
    let branch_id = BranchId::for_height(network, BlockHeight::from_u32(wtx.height));
    let tx = Transaction::read(&*raw_tx.data, branch_id)?;
    ensure!(
        tx.txid().as_ref() == &wtx.txid,
        "raw transaction id does not match the compact transaction"
    );
    let tx = tx.into_data();

    if let Some(sap_dec) = decoders.sapling.as_ref() {
        if let Some(sapling_bundle) = tx.sapling_bundle() {
            for (vout, o) in sapling_bundle.shielded_outputs().iter().enumerate() {
                if let Some(note) = sap_dec.try_note_decryption(
                    position_with_offset(wtx.sap_position, vout, "Sapling")?,
                    o,
                )? {
                    notes.push(note);
                }
            }
        }
    }
    if let Some(orc_dec) = decoders.orchard.as_ref() {
        if let Some(orchard_bundle) = tx.orchard_bundle() {
            for (vout, a) in orchard_bundle.actions().iter().enumerate() {
                if let Some(note) = orc_dec.try_note_decryption(
                    position_with_offset(wtx.orc_position, vout, "Orchard")?,
                    a,
                )? {
                    notes.push(note);
                }
            }
        }
    }
    // A V6 transaction carries the Orchard and Ironwood bundles side by side; memos for
    // Ironwood notes are in the latter, decrypted with the Ironwood domain.
    if let Some(irw_dec) = decoders.ironwood.as_ref() {
        if let Some(ironwood_bundle) = tx.ironwood_bundle() {
            for (vout, a) in ironwood_bundle.actions().iter().enumerate() {
                if let Some(note) = irw_dec.try_note_decryption(
                    position_with_offset(wtx.irw_position, vout, "Ironwood")?,
                    a,
                )? {
                    notes.push(note);
                }
            }
        }
    }
    Ok(notes)
}

pub fn get_tree_size(tree: &str) -> Result<u32> {
    let tree = hex::decode(tree)?;
    if tree.is_empty() {
        return Ok(0);
    }
    let tree = read_commitment_tree::<DummyNode, _, 32>(&*tree)?;

    u32::try_from(tree.size()).context("commitment tree size exceeds u32")
}

pub trait Pool {
    type Address;
    type PreparedIncomingViewingKey;
    type NullifierKey;
    type DiversifierKey;
    type CompactOutput;
    type Output;
}

pub struct Sapling;

#[derive(Debug)]
pub struct ReceivedNote {
    pub txid: Hash,
    pub pool: u8,
    pub position: u32,
    pub height: u32,
    pub address: String,
    pub diversifier: [u8; 11],
    pub diversifier_index: Option<u64>,
    pub value: u64,
    pub rcm: Hash,
    pub nf: Hash,
    pub rho: Option<Hash>,
}

#[derive(Debug)]
pub struct MemoNote {
    pub pool: u8,
    pub nf: Hash,
    pub memo: String,
}

#[derive(Debug)]
pub struct SpentNote {
    pub pool: u8,
    pub height: u32,
    pub nf: Hash,
    pub txid: Hash,
    pub value: u64,
}

#[derive(Debug)]
pub enum ScanEvent {
    Block(u32, Hash),
    Received(ReceivedNote),
    Spent(SpentNote),
    Memo(MemoNote),
}

impl Pool for Sapling {
    type Address = PaymentAddress;
    type PreparedIncomingViewingKey = sapling_crypto::keys::PreparedIncomingViewingKey;
    type NullifierKey = NullifierDerivingKey;
    type DiversifierKey = DiversifiableFullViewingKey;
    type CompactOutput = CompactSaplingOutput;
    type Output = OutputDescription<[u8; 192]>;
}

pub trait Decode<P: Pool> {
    fn try_compact_note_decryption(
        &self,
        network: &Network,
        height: u32,
        txid: &[u8],
        position: u32,
        output: &P::CompactOutput,
    ) -> Result<Option<ReceivedNote>>;
    fn try_note_decryption(&self, position: u32, output: &P::Output) -> Result<Option<MemoNote>>;
    fn decrypt_diversifier(&self, address: &P::Address) -> Result<Option<u64>>;
}

pub struct Decoder<P: Pool> {
    pub nk: P::NullifierKey,
    pub dk: P::DiversifierKey,
    pub pivk: P::PreparedIncomingViewingKey,
    pub nfs: HashMap<Hash, u64>,
}

impl<P: Pool> Decoder<P> {
    pub fn new(
        nk: P::NullifierKey,
        dk: P::DiversifierKey,
        pivk: P::PreparedIncomingViewingKey,
        nfs: &HashMap<Hash, u64>,
    ) -> Self {
        Self {
            nk,
            dk,
            pivk,
            nfs: nfs.clone(),
        }
    }

    pub fn add_nf(&mut self, nf: Hash, value: u64) {
        self.nfs.insert(nf, value);
    }
}

impl Decode<Sapling> for Decoder<Sapling> {
    fn try_compact_note_decryption(
        &self,
        network: &Network,
        height: u32,
        txid: &[u8],
        position: u32,
        output: &CompactSaplingOutput,
    ) -> Result<Option<ReceivedNote>> {
        let domain = SaplingDomain::new(Zip212Enforcement::On);
        if let Some((note, pa)) = try_compact_note_decryption(&domain, &self.pivk, output) {
            let address = pa.encode(network);
            let diversifier = pa.diversifier().0;
            let value = note.value().inner();
            let rcm = note.rcm().to_bytes();
            let nf = note.nf(&self.nk, position as u64);
            let di = self.decrypt_diversifier(&pa)?;

            let note = ReceivedNote {
                txid: parse_hash("transaction id", txid)?,
                pool: POOL_SAPLING,
                position,
                height,
                address,
                diversifier,
                diversifier_index: di,
                value,
                rcm,
                nf: nf.to_vec().try_into().unwrap(),
                rho: None,
            };
            return Ok(Some(note));
        }
        Ok(None)
    }

    fn try_note_decryption(
        &self,
        position: u32,
        output: &OutputDescription<[u8; 192]>,
    ) -> Result<Option<MemoNote>> {
        let domain = SaplingDomain::new(Zip212Enforcement::On);
        if let Some((note, _pa, memo_bytes)) = try_note_decryption(&domain, &self.pivk, output) {
            let nf = note.nf(&self.nk, position as u64);
            let memo_note = MemoNote {
                pool: POOL_SAPLING,
                nf: nf.0,
                memo: memo_text(&memo_bytes)?,
            };
            return Ok(Some(memo_note));
        }
        Ok(None)
    }

    fn decrypt_diversifier(&self, address: &PaymentAddress) -> Result<Option<u64>> {
        if let Some((di, _)) = self.dk.decrypt_diversifier(address) {
            let di: u64 = di.try_into()?;
            return Ok(Some(di));
        }
        Ok(None)
    }
}

pub struct Orchard;

impl Pool for Orchard {
    type Address = Address;
    type NullifierKey = FullViewingKey;
    type DiversifierKey = orchard::keys::IncomingViewingKey;
    type PreparedIncomingViewingKey = orchard::keys::PreparedIncomingViewingKey;
    type CompactOutput = CompactOrchardAction;
    type Output = Action<Signature<SpendAuth>>;
}

/// Ironwood, the shielded pool introduced by NU6.3.
///
/// Ironwood reuses Orchard's keys, addresses and action encoding wholesale, so a wallet needs no
/// new key material and no new address type to receive into it: an Ironwood note is simply
/// received at an ordinary Orchard receiver. What differs is (a) the note plaintext version —
/// lead byte `0x03` instead of Orchard's `0x02`, so trial decryption needs the Ironwood domain —
/// and (b) the commitment tree, which is separate from Orchard's and therefore has its own
/// note positions. Once NU6.3 activates, payments to an Orchard receiver are *routed to this
/// pool*, so a wallet that only scans `CompactTx.actions` stops seeing its own incoming
/// payments.
pub struct Ironwood;

impl Pool for Ironwood {
    type Address = Address;
    type NullifierKey = FullViewingKey;
    type DiversifierKey = orchard::keys::IncomingViewingKey;
    type PreparedIncomingViewingKey = orchard::keys::PreparedIncomingViewingKey;
    type CompactOutput = CompactOrchardAction;
    type Output = Action<Signature<SpendAuth>>;
}

/// The account keys shared by the Orchard-family pools, plus the pool code to tag notes with.
struct OrchardFamilyKeys<'a> {
    nk: &'a FullViewingKey,
    dk: &'a orchard::keys::IncomingViewingKey,
    pivk: &'a orchard::keys::PreparedIncomingViewingKey,
    pool: u8,
}

/// Trial-decrypt a compact Orchard-family action under the note-plaintext version `V`
/// (`OrchardVersion` for the Orchard bundle, `IronwoodVersion` for the Ironwood bundle).
fn orchard_family_compact_decryption<V: DomainVersion>(
    keys: &OrchardFamilyKeys<'_>,
    network: &Network,
    height: u32,
    txid: &[u8],
    position: u32,
    action: &CompactOrchardAction,
) -> Result<Option<ReceivedNote>> {
    let nullifier_bytes = parse_hash("Orchard-family nullifier", &action.nullifier)?;
    let nullifier = Option::<Nullifier>::from(Nullifier::from_bytes(&nullifier_bytes))
        .context("invalid Orchard-family nullifier")?;
    let commitment_bytes = parse_hash("Orchard-family commitment", &action.cmx)?;
    let commitment = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
        &commitment_bytes,
    ))
    .context("invalid Orchard-family commitment")?;
    let epk = parse_hash("Orchard-family ephemeral key", &action.ephemeral_key)?;
    let ciphertext = action
        .ciphertext
        .as_slice()
        .try_into()
        .context("Orchard-family compact ciphertext must contain 52 bytes")?;
    let ca = CompactAction::from_parts(nullifier, commitment, EphemeralKeyBytes(epk), ciphertext);
    let domain = NoteEncryptionDomain::<V>::for_compact_action(&ca);
    if let Some((note, address)) = try_compact_note_decryption(&domain, keys.pivk, &ca) {
        let ua = unified::Receiver::Orchard(address.to_raw_address_bytes());
        let ua = unified::Address::try_from_items(vec![ua])?;
        let ua = ua.encode(&network.network_type());
        let diversifier = *address.diversifier().as_array();
        let value = note.value().inner();
        let rcm = *note.rseed().as_bytes();
        let nf = note.nullifier(keys.nk);
        let rho = note.rho().to_bytes();
        let di = orchard_family_diversifier(keys.dk, &address)?;

        let note = ReceivedNote {
            txid: parse_hash("transaction id", txid)?,
            pool: keys.pool,
            position,
            height,
            address: ua,
            diversifier,
            diversifier_index: di,
            value,
            rcm,
            nf: nf.to_bytes(),
            rho: Some(rho),
        };
        return Ok(Some(note));
    }
    Ok(None)
}

/// Full trial decryption of an Orchard-family action, to recover the note's memo.
fn orchard_family_note_decryption<V: DomainVersion>(
    keys: &OrchardFamilyKeys<'_>,
    action: &Action<Signature<SpendAuth>>,
) -> Result<Option<MemoNote>> {
    let domain = NoteEncryptionDomain::<V>::for_action(action);
    if let Some((note, _address, memo_bytes)) = try_note_decryption(&domain, keys.pivk, action) {
        let nf = note.nullifier(keys.nk);
        let memo_note = MemoNote {
            pool: keys.pool,
            nf: nf.to_bytes(),
            memo: memo_text(&memo_bytes)?,
        };
        return Ok(Some(memo_note));
    }

    Ok(None)
}

fn orchard_family_diversifier(
    dk: &orchard::keys::IncomingViewingKey,
    address: &Address,
) -> Result<Option<u64>> {
    if let Some(di) = dk.diversifier_index(address) {
        let di: u64 = di.try_into()?;
        return Ok(Some(di));
    }
    Ok(None)
}

impl Decoder<Orchard> {
    fn keys(&self) -> OrchardFamilyKeys<'_> {
        OrchardFamilyKeys {
            nk: &self.nk,
            dk: &self.dk,
            pivk: &self.pivk,
            pool: POOL_ORCHARD,
        }
    }
}

impl Decode<Orchard> for Decoder<Orchard> {
    fn try_compact_note_decryption(
        &self,
        network: &Network,
        height: u32,
        txid: &[u8],
        position: u32,
        action: &CompactOrchardAction,
    ) -> Result<Option<ReceivedNote>> {
        orchard_family_compact_decryption::<OrchardVersion>(
            &self.keys(),
            network,
            height,
            txid,
            position,
            action,
        )
    }

    fn try_note_decryption(
        &self,
        _position: u32,
        action: &Action<Signature<SpendAuth>>,
    ) -> Result<Option<MemoNote>> {
        orchard_family_note_decryption::<OrchardVersion>(&self.keys(), action)
    }

    fn decrypt_diversifier(&self, address: &Address) -> Result<Option<u64>> {
        orchard_family_diversifier(&self.dk, address)
    }
}

impl Decoder<Ironwood> {
    fn keys(&self) -> OrchardFamilyKeys<'_> {
        OrchardFamilyKeys {
            nk: &self.nk,
            dk: &self.dk,
            pivk: &self.pivk,
            pool: POOL_IRONWOOD,
        }
    }
}

impl Decode<Ironwood> for Decoder<Ironwood> {
    fn try_compact_note_decryption(
        &self,
        network: &Network,
        height: u32,
        txid: &[u8],
        position: u32,
        action: &CompactOrchardAction,
    ) -> Result<Option<ReceivedNote>> {
        orchard_family_compact_decryption::<IronwoodVersion>(
            &self.keys(),
            network,
            height,
            txid,
            position,
            action,
        )
    }

    fn try_note_decryption(
        &self,
        _position: u32,
        action: &Action<Signature<SpendAuth>>,
    ) -> Result<Option<MemoNote>> {
        orchard_family_note_decryption::<IronwoodVersion>(&self.keys(), action)
    }

    fn decrypt_diversifier(&self, address: &Address) -> Result<Option<u64>> {
        orchard_family_diversifier(&self.dk, address)
    }
}

// We don't need to know the commitment tree nodes because we are not
// making transactions. However, we have to pretend to read it so that
// we know how many nodes were used and derive the *position* of the
// notes we receive
pub struct DummyNode;

impl HashSer for DummyNode {
    fn read<R: std::io::Read>(mut reader: R) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(DummyNode {})
    }

    fn write<W: std::io::Write>(&self, _writer: W) -> std::io::Result<()> {
        unreachable!()
    }
}

impl ShieldedOutput<SaplingDomain, 52> for CompactSaplingOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        let hash: Hash = self.epk.clone().try_into().unwrap();
        EphemeralKeyBytes::from(hash)
    }

    fn cmstar_bytes(
        &self,
    ) -> <SaplingDomain as zcash_note_encryption::Domain>::ExtractedCommitmentBytes {
        let hash: Hash = self.cmu.clone().try_into().unwrap();
        hash
    }

    fn enc_ciphertext(&self) -> &[u8; 52] {
        self.ciphertext.as_slice().try_into().unwrap()
    }
}

#[derive(Debug)]
pub struct WalletTx {
    pub height: u32,
    pub txid: Hash,
    pub sap_position: u32,
    pub orc_position: u32,
    pub irw_position: u32,
}

pub fn memo_text(memo_bytes: &[u8]) -> Result<String> {
    let memo_bytes = MemoBytes::from_bytes(memo_bytes)?;
    let memo = Memo::try_from(memo_bytes)?;
    let memo = if let Memo::Text(memo) = memo {
        memo.to_string()
    } else {
        String::new()
    };
    Ok(memo)
}

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Blockchain Reorganization")]
    Reorganization,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const FVK: &str = "uview1s5ranpd74zd2pseylw0fmt0cnudf9765mwjjd9mqf8tvjq2nlw9vgypzqayfvs7aeedguwl4r7exz50nrw6llfs3n9xfd4sm2slaay7smysc4yjyuwu3z7n5ccvyw70qkw28yt6xwra6c8d20ewpjeqq4enmftyly3fmn78hwwkyffp2y4x2vk8050vcly8y5fuse5s9e5j4wmwuldemxahrp4zrgatj63mnpqlpacvcudqfsm5ee29pj8lr5wt93eyrx3fwa64m6505cge6n46c7eqw59e0n3m9rmsntcflfmu9wyjgfk2pmjf4npkml93vyq0fps2rh4mdwpz4ld059m6mamjht99j7sdypwx52lj6lvrfgwja4uf7qy2g8d6gkmvkh7u4dksq5gazxvye4gtwfgwmuygg2sqmkkf4fjd3ymf0mq99rhf0trsl0lpddw64r4n7jj7mxy6fcpj64vkx0pre2lla9p8nknrt2c33zy3vaczd";

    #[test]
    fn compact_fields_are_validated_before_decryption() {
        let output = CompactSaplingOutput {
            cmu: vec![0; 32],
            epk: vec![0; 31],
            ciphertext: vec![0; 52],
        };
        assert!(validate_compact_sapling_output(&output).is_err());

        let action = CompactOrchardAction {
            nullifier: vec![0; 31],
            cmx: vec![0; 32],
            ephemeral_key: vec![0; 32],
            ciphertext: vec![0; 52],
        };
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&Network::Main, FVK).unwrap();
        let decoder = Decoders::new(&ufvk, &HashMap::new()).orchard.unwrap();
        assert!(decoder
            .try_compact_note_decryption(&Network::Main, 1, &[0; 32], 0, &action)
            .is_err());
    }

    #[test]
    fn nullifiers_are_scoped_by_pool() {
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&Network::Main, FVK).unwrap();
        let decoders = Decoders::new(
            &ufvk,
            &HashMap::from([
                ((POOL_SAPLING, [1; 32]), 1),
                ((POOL_ORCHARD, [2; 32]), 2),
                ((POOL_IRONWOOD, [3; 32]), 3),
            ]),
        );

        assert_eq!(decoders.sapling.unwrap().nfs, HashMap::from([([1; 32], 1)]));
        assert_eq!(decoders.orchard.unwrap().nfs, HashMap::from([([2; 32], 2)]));
        assert_eq!(
            decoders.ironwood.unwrap().nfs,
            HashMap::from([([3; 32], 3)])
        );
    }

    #[test]
    fn ironwood_v3_notes_use_the_ironwood_domain() {
        use orchard::{
            keys::{Scope, SpendingKey},
            note::{Note, NoteVersion, RandomSeed, Rho},
            note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
            value::NoteValue,
        };
        use zcash_note_encryption::Domain;

        let spending_key = (0u32..)
            .find_map(|counter| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&counter.to_le_bytes());
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .unwrap();
        let fvk = FullViewingKey::from(&spending_key);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut nf_bytes = [0; 32];
        nf_bytes[0] = 1;
        let nf_old = Option::<Nullifier>::from(Nullifier::from_bytes(&nf_bytes)).unwrap();
        let rho = Option::<Rho>::from(Rho::from_bytes(&nf_old.to_bytes())).unwrap();
        let note = (0u32..)
            .find_map(|counter| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&counter.to_le_bytes());
                let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho))?;
                Option::<Note>::from(Note::from_parts(
                    recipient,
                    NoteValue::from_raw(123_456),
                    rho,
                    rseed,
                    NoteVersion::V3,
                ))
            })
            .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let encryptor =
            IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, [0; 512]);
        let ephemeral_key = IronwoodDomain::epk_bytes(encryptor.epk());
        let ciphertext = encryptor.encrypt_note_plaintext();
        let action = CompactOrchardAction {
            nullifier: nf_old.to_bytes().to_vec(),
            cmx: cmx.to_bytes().to_vec(),
            ephemeral_key: ephemeral_key.0.to_vec(),
            ciphertext: ciphertext[..52].to_vec(),
        };

        let ivk = fvk.to_ivk(Scope::External);
        let orchard_decoder = Decoder::<Orchard>::new(
            fvk.clone(),
            ivk.clone(),
            orchard::keys::PreparedIncomingViewingKey::new(&ivk),
            &HashMap::new(),
        );
        let ironwood_decoder = Decoder::<Ironwood>::new(
            fvk,
            ivk.clone(),
            orchard::keys::PreparedIncomingViewingKey::new(&ivk),
            &HashMap::new(),
        );
        let txid = [9; 32];

        assert!(orchard_decoder
            .try_compact_note_decryption(&Network::Main, 3_428_143, &txid, 7, &action)
            .unwrap()
            .is_none());
        let received = ironwood_decoder
            .try_compact_note_decryption(&Network::Main, 3_428_143, &txid, 7, &action)
            .unwrap()
            .unwrap();
        assert_eq!(received.pool, POOL_IRONWOOD);
        assert_eq!(received.value, 123_456);
        assert_eq!(received.position, 7);
    }

    #[test]
    fn chain_metadata_mismatch_is_rejected() {
        let metadata = ChainMetadata {
            sapling_commitment_tree_size: 10,
            orchard_commitment_tree_size: 20,
            ironwood_commitment_tree_size: 30,
        };
        assert!(validate_tree_sizes(&metadata, 10, 20, 30, 1).is_ok());
        assert!(validate_tree_sizes(&metadata, 10, 20, 29, 1).is_err());
    }

    #[test]
    fn checkpoint_hash_mismatch_is_a_reorganization() {
        let mut display_hash = [1; 32];
        display_hash.reverse();
        assert!(verify_checkpoint_hash(&hex::encode(display_hash), &[1; 32]).is_ok());
        assert!(matches!(
            verify_checkpoint_hash(&hex::encode(display_hash), &[2; 32]),
            Err(ScanError::Reorganization)
        ));
    }

    #[tokio::test]
    #[ignore = "requires a live public lightwalletd"]
    async fn live_ironwood_scan() -> Result<()> {
        let mut client = CompactTxStreamerClient::connect("https://zec.rocks".to_string()).await?;
        let start = u32::from(
            Network::Main
                .activation_height(NetworkUpgrade::Nu6_3)
                .context("mainnet NU6.3 activation is not configured")?,
        );
        let end = start
            .checked_add(9)
            .context("live scan range overflow")?
            .min(get_latest_height(&mut client).await?);
        let previous = client
            .get_block(Request::new(BlockId {
                height: u64::from(start - 1),
                hash: vec![],
            }))
            .await?
            .into_inner();
        let prev_hash = parse_hash("previous block hash", &previous.hash)?;
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&Network::Main, FVK).unwrap();
        let mut decoders = Decoders::new(&ufvk, &HashMap::new());

        let events = scan(
            &Network::Main,
            &mut client,
            start,
            end,
            &prev_hash,
            &mut decoders,
        )
        .await?;
        assert!(matches!(events.last(), Some(ScanEvent::Block(height, _)) if *height == end));

        Ok(())
    }
}
