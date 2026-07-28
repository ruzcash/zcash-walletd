use std::collections::HashMap;

use anyhow::Result;
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
    consensus::{BlockHeight, BranchId, Parameters},
    memo::{Memo, MemoBytes},
};

use crate::{
    lwd_rpc::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
        CompactOrchardAction, CompactSaplingOutput, Empty, PoolType, TxFilter,
    },
    network::Network, Client, Hash,
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
    let latest_height = latest_block_id.height;
    Ok(latest_height as u32)
}

/// The `BlockRange.poolTypes` selector to use against this server.
///
/// Ironwood actions only ride in compact blocks when they are explicitly requested, and the
/// field is part of the *versioned* lightwallet-protocol: a client must confirm the server
/// advertises `lightwalletProtocolVersion` before setting it, because a legacy server may
/// reject it or misinterpret tag 3. Against a legacy server we send an empty selector and get
/// the legacy default (Sapling + Orchard) — correct behaviour pre-NU6.3, and the operator
/// needs an upgraded lightwalletd to see Ironwood receives once NU6.3 activates.
pub async fn pool_types(client: &mut Client) -> Result<Vec<i32>> {
    let info = client
        .get_lightd_info(Request::new(Empty {}))
        .await?
        .into_inner();
    if info.lightwallet_protocol_version.is_empty() {
        log::warn!(
            "lightwalletd {} does not advertise a lightwallet-protocol version; \
             Ironwood (NU6.3) notes cannot be detected. Upgrade the server to scan NU6.3 blocks.",
            info.version
        );
        Ok(vec![])
    } else {
        Ok(vec![
            PoolType::Sapling as i32,
            PoolType::Orchard as i32,
            PoolType::Ironwood as i32,
        ])
    }
}

/// The per-pool trial-decryption state carried across a scan.
pub struct Decoders {
    pub sapling: Option<Decoder<Sapling>>,
    pub orchard: Option<Decoder<Orchard>>,
    pub ironwood: Option<Decoder<Ironwood>>,
}

impl Decoders {
    /// Build the per-pool decoders for `ufvk`, seeded with the wallet's known nullifiers.
    pub fn new(ufvk: &UnifiedFullViewingKey, nfs: &HashMap<Hash, u64>) -> Self {
        let sapling = ufvk.sapling().map(|fvk| {
            let nk = fvk.fvk().vk.nk;
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Sapling>::new(nk, fvk.clone(), pivk, nfs)
        });
        let orchard = ufvk.orchard().map(|fvk| {
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = orchard::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Orchard>::new(fvk.clone(), ivk, pivk, nfs)
        });
        // Ironwood is received at the account's Orchard receivers and derives from the same
        // Orchard key material — only the note plaintext version and the commitment tree
        // differ — so its decoder is built from the very same FVK.
        let ironwood = ufvk.orchard().map(|fvk| {
            let ivk = fvk.to_ivk(zip32::Scope::External);
            let pivk = orchard::keys::PreparedIncomingViewingKey::new(&ivk);
            Decoder::<Ironwood>::new(fvk.clone(), ivk, pivk, nfs)
        });
        Decoders {
            sapling,
            orchard,
            ironwood,
        }
    }

    /// Look a nullifier up against both Orchard-family decoders.
    ///
    /// Orchard and Ironwood derive nullifiers from the same account key, and a note is nullified
    /// in whichever bundle owns its pool — an Orchard V2 note in the Orchard bundle, an Ironwood
    /// V3 note in the Ironwood bundle — so a spend must be matched against both sets regardless
    /// of which action list it was seen in.
    fn orchard_family_nf(&self, nf: &Hash) -> Option<u64> {
        self.orchard
            .as_ref()
            .and_then(|d| d.nfs.get(nf).copied())
            .or_else(|| self.ironwood.as_ref().and_then(|d| d.nfs.get(nf).copied()))
    }
}

pub async fn scan(
    network: &Network,
    client: &mut Client,
    start: u32,
    end: u32,
    prev_hash: &Hash,
    decoders: &mut Decoders,
) -> Result<Vec<ScanEvent>, ScanError> {
    let pool_types = pool_types(client).await.map_err(ScanError::Other)?;
    let tree_state = client
        .get_tree_state(Request::new(BlockId {
            height: start as u64,
            hash: vec![],
        }))
        .await
        .map_err(|e| ScanError::Other(anyhow::Error::new(e)))?
        .into_inner();

    let mut blocks = client
        .get_block_range(Request::new(BlockRange {
            start: Some(BlockId {
                height: start as u64,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end as u64,
                hash: vec![],
            }),
            pool_types,
        }))
        .await
        .map_err(|e| ScanError::Other(anyhow::Error::new(e)))?
        .into_inner();
    let mut prev_hash = *prev_hash;
    let mut sap_position = get_tree_size(&tree_state.sapling_tree).unwrap();
    let mut orc_position = get_tree_size(&tree_state.orchard_tree).unwrap();
    // Ironwood has its own commitment tree, so its note positions are tracked separately from
    // Orchard's. Empty (hence 0) before NU6.3 activates, and on servers that don't serve it.
    let mut irw_position = get_tree_size(&tree_state.ironwood_tree).unwrap();

    let mut events = vec![];
    let mut new_txids = vec![];
    while let Ok(Some(block)) = blocks.message().await {
        let height = block.height as u32;
        let block_prev_hash: Hash = block.prev_hash.try_into().unwrap();
        if prev_hash != block_prev_hash {
            info!("Reorg at {} {}", block.height, hex::encode(block_prev_hash));
            return Err(ScanError::Reorganization);
        }
        prev_hash = block.hash.try_into().unwrap();

        for vtx in block.vtx.iter() {
            let mut found = false;
            if let Some(sap_dec) = decoders.sapling.as_mut() {
                for i in vtx.spends.iter() {
                    let nf: &Hash = i.nf.as_slice().try_into().unwrap();
                    if let Some(value) = sap_dec.nfs.get(nf) {
                        events.push(ScanEvent::Spent(SpentNote {
                            height,
                            nf: *nf,
                            txid: vtx.hash.clone().try_into().unwrap(),
                            value: *value,
                        }));
                    }
                }

                for (vout, o) in vtx.outputs.iter().enumerate() {
                    if let Some(n) = sap_dec.try_compact_note_decryption(
                        network,
                        height,
                        &vtx.hash,
                        sap_position + vout as u32,
                        o,
                    )? {
                        sap_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            // Orchard and Ironwood actions are structurally identical and share the account's
            // Orchard keys; they differ in the note-plaintext version (so each needs its own
            // trial-decryption domain) and in which commitment tree positions them. A note is
            // nullified in whichever bundle owns its pool, so spends are looked up against both
            // decoders' nullifier sets.
            for (vout, a) in vtx.actions.iter().enumerate() {
                let nf: &Hash = a.nullifier.as_slice().try_into().unwrap();
                if let Some(value) = decoders.orchard_family_nf(nf) {
                    events.push(ScanEvent::Spent(SpentNote {
                        height,
                        nf: *nf,
                        txid: vtx.hash.clone().try_into().unwrap(),
                        value,
                    }));
                }
                if let Some(orc_dec) = decoders.orchard.as_mut() {
                    if let Some(n) = orc_dec.try_compact_note_decryption(
                        network,
                        height,
                        &vtx.hash,
                        orc_position + vout as u32,
                        a,
                    )? {
                        orc_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            for (vout, a) in vtx.ironwood_actions.iter().enumerate() {
                let nf: &Hash = a.nullifier.as_slice().try_into().unwrap();
                if let Some(value) = decoders.orchard_family_nf(nf) {
                    events.push(ScanEvent::Spent(SpentNote {
                        height,
                        nf: *nf,
                        txid: vtx.hash.clone().try_into().unwrap(),
                        value,
                    }));
                }
                if let Some(irw_dec) = decoders.ironwood.as_mut() {
                    if let Some(n) = irw_dec.try_compact_note_decryption(
                        network,
                        height,
                        &vtx.hash,
                        irw_position + vout as u32,
                        a,
                    )? {
                        irw_dec.add_nf(n.nf, n.value);
                        events.push(ScanEvent::Received(n));
                        found = true;
                    }
                }
            }

            if found {
                let txid: Hash = vtx.hash.clone().try_into().unwrap();
                new_txids.push(WalletTx {
                    height,
                    txid,
                    sap_position,
                    orc_position,
                    irw_position,
                });
            }

            sap_position += vtx.outputs.len() as u32;
            orc_position += vtx.actions.len() as u32;
            irw_position += vtx.ironwood_actions.len() as u32;
        }
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
    let branch_id = BranchId::for_height(network, BlockHeight::from_u32(wtx.height));
    let tx = Transaction::read(&*raw_tx.data, branch_id)?;
    let tx = tx.into_data();

    if let Some(sap_dec) = decoders.sapling.as_ref() {
        if let Some(sapling_bundle) = tx.sapling_bundle() {
            for (vout, o) in sapling_bundle.shielded_outputs().iter().enumerate() {
                if let Some(note) =
                    sap_dec.try_note_decryption(vout as u32 + wtx.sap_position, o)?
                {
                    notes.push(note);
                }
            }
        }
    }
    if let Some(orc_dec) = decoders.orchard.as_ref() {
        if let Some(orchard_bundle) = tx.orchard_bundle() {
            for (vout, a) in orchard_bundle.actions().iter().enumerate() {
                if let Some(note) =
                    orc_dec.try_note_decryption(vout as u32 + wtx.orc_position, a)?
                {
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
                if let Some(note) =
                    irw_dec.try_note_decryption(vout as u32 + wtx.irw_position, a)?
                {
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

    Ok(tree.size() as u32)
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
    pub nf: Hash,
    pub memo: String,
}

#[derive(Debug)]
pub struct SpentNote {
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
                txid: txid.try_into().unwrap(),
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
    let epk: &[u8; 32] = action.ephemeral_key.as_slice().try_into().unwrap();
    let ca = CompactAction::from_parts(
        Nullifier::from_bytes(action.nullifier.as_slice().try_into().unwrap()).unwrap(),
        ExtractedNoteCommitment::from_bytes(action.cmx.as_slice().try_into().unwrap()).unwrap(),
        EphemeralKeyBytes(*epk),
        action.ciphertext.as_slice().try_into().unwrap(),
    );
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
            txid: txid.try_into().unwrap(),
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
    use crate::db::Db;

    use super::*;
    use anyhow::Result;

    const FVK: &str = "uview1s5ranpd74zd2pseylw0fmt0cnudf9765mwjjd9mqf8tvjq2nlw9vgypzqayfvs7aeedguwl4r7exz50nrw6llfs3n9xfd4sm2slaay7smysc4yjyuwu3z7n5ccvyw70qkw28yt6xwra6c8d20ewpjeqq4enmftyly3fmn78hwwkyffp2y4x2vk8050vcly8y5fuse5s9e5j4wmwuldemxahrp4zrgatj63mnpqlpacvcudqfsm5ee29pj8lr5wt93eyrx3fwa64m6505cge6n46c7eqw59e0n3m9rmsntcflfmu9wyjgfk2pmjf4npkml93vyq0fps2rh4mdwpz4ld059m6mamjht99j7sdypwx52lj6lvrfgwja4uf7qy2g8d6gkmvkh7u4dksq5gazxvye4gtwfgwmuygg2sqmkkf4fjd3ymf0mq99rhf0trsl0lpddw64r4n7jj7mxy6fcpj64vkx0pre2lla9p8nknrt2c33zy3vaczd";

    #[tokio::test]
    async fn test() -> Result<()> {
        let mut client = CompactTxStreamerClient::connect("https://zec.rocks".to_string()).await?;

        let prev_hash =
            hex::decode("5f03d35ae940bb840564c3b7af7ab72255096d3eca15c910c0e40d0000000000")
                .unwrap();
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&Network::Main, FVK).unwrap();
        let mut decoders = Decoders::new(&ufvk, &HashMap::new());

        let events = scan(
            &Network::Main,
            &mut client,
            2_890_000,
            2_900_000,
            &prev_hash.try_into().unwrap(),
            &mut decoders,
        )
        .await?;

        println!("{events:?}");

        // Scratch database, recreated on each run: `store_events` is not idempotent (note
        // nullifiers are UNIQUE), and `Db::new` alone does not build the schema.
        let db_path = std::env::temp_dir().join("zec-wallet-test.db");
        let _ = std::fs::remove_file(&db_path);
        let db = Db::new(Network::Main, &db_path.to_string_lossy(), &ufvk, "").await?;
        db.create().await?;
        db.new_account("").await?;
        db.store_events(&events).await?;

        Ok(())
    }
}
