use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;
use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::primitives::{Batch, SignedBatch},
};

pub use serai_db::*;

use ::tributary::ReadWrite;
use crate::tributary::{TributarySpec, Transaction, scanner::RecognizedIdType};

create_db!(
  MainDb {
    HandledMessageDb: (network: NetworkId, id: u64) -> Vec<u8>,
    InTributaryDb: (set: ValidatorSet) -> Vec<u8>,
    ActiveTributaryDb: () -> Vec<u8>,
    RetiredTributaryDb: (set: ValidatorSet) -> Vec<u8>,
    SignedTransactionDb: (key: u32) -> Vec<u8>,
    FirstPreprocessDb: (
      network: NetworkId,
      id_type: RecognizedIdType,
      id: &[u8],
    ) -> Vec<Vec<u8>>,
    LastRecievedBatchDb: (network: NetworkId) -> u32,
    ExpectedBatchDb: (network: NetworkId, id: u32) -> [u8; 32],
    BatchDb: (network: NetworkId, id: u32)  -> SignedBatch,
    LastVerifiedBatchDb: (network: NetworkId) -> u32,
    HandoverBatchDb: (set: ValidatorSet) -> u32,
    LookupHandoverBatchDb: (network: NetworkId, batch: u32) -> Session,
    QueuedBatchesDb: (set: ValidatorSet) -> Vec<u8>
  }
);

impl ActiveTributaryDb {
  pub fn active_tributaries<G: Get>(getter: &G) -> (Vec<u8>, Vec<TributarySpec>) {
    let bytes =Self::get(getter).unwrap_or_default();
    let mut bytes_ref: &[u8] = bytes.as_ref();

    let mut tributaries = vec![];
    while !bytes_ref.is_empty() {
      tributaries.push(TributarySpec::read(&mut bytes_ref).unwrap());
    }

    (bytes, tributaries)
  }

  pub fn retire_tributary(txn: &mut impl DbTxn, set: ValidatorSet) {
    let mut active = Self::active_tributaries(txn).1;
    for i in 0 .. active.len() {
      if active[i].set() == set {
        active.remove(i);
        break;
      }
    }

    let mut bytes = vec![];
    for active in active {
      active.write(&mut bytes).unwrap();
    }
    Self::set(txn, &bytes);
    RetiredTributaryDb::set(txn, set, &vec![] as &Vec<u8>);
  }
}

pub fn add_participating_in_tributary(txn: &mut impl DbTxn, spec: &TributarySpec) {
  InTributaryDb::set(txn,  spec.set(), &vec![] as &Vec<u8>);

  let (mut existing_bytes, existing) = ActiveTributaryDb::active_tributaries(txn);
  for tributary in &existing {
    if tributary == spec {
      return;
    }
  }

  spec.write(&mut existing_bytes).unwrap();
  ActiveTributaryDb::set(txn, &existing_bytes);
}

impl SignedTransactionDb {
  pub fn take_signed_transaction(txn: &mut impl DbTxn, nonce: u32) -> Option<Transaction> {
    let res = SignedTransactionDb::get(txn, nonce).map(|bytes| Transaction::read(&mut bytes.as_slice()).unwrap());
    if res.is_some() {
      txn.del(Self::key(nonce));
    }
    res
  }
}

impl FirstPreprocessDb {
  pub fn save_first_preprocess(
    txn: &mut impl DbTxn,
    network: NetworkId,
    id_type: RecognizedIdType,
    id: &[u8],
    preprocess: Vec<Vec<u8>>,
  ) {
    if let Some(existing) = FirstPreprocessDb::get(txn, network, id_type, &id.to_vec()) {
      assert_eq!(existing, preprocess, "saved a distinct first preprocess");
      return;
    }
    FirstPreprocessDb::set(txn, network, id_type, &id.to_vec(), &preprocess);
  }
}

impl ExpectedBatchDb {
  pub fn save_expected_batch(txn: &mut impl DbTxn, batch: &Batch) {
    LastRecievedBatchDb::set(txn, batch.network, &batch.id);
    let hash: [u8; 32] = Blake2b::<U32>::digest(batch.instructions.encode()).into();
    Self::set(txn, batch.network, batch.id, &hash);
  }
}

impl HandoverBatchDb {
  pub fn set_handover_batch(txn: &mut impl DbTxn, set: ValidatorSet, batch: u32) {
    Self::set(txn, set, &batch);
    LookupHandoverBatchDb::set(txn, set.network, batch, &set.session);
  }
}
impl QueuedBatchesDb {
  pub fn queue(txn: &mut impl DbTxn, set: ValidatorSet, batch: Transaction) {
    let mut batches = Self::get(txn, set).unwrap_or_default();
    batches.extend(batch.serialize());
    Self::set(txn, set, &batches);
  }

  pub fn take(txn: &mut impl DbTxn, set: ValidatorSet) -> Vec<Transaction> {
    let batches_vec = Self::get(txn, set).unwrap_or_default();
    txn.del(&Self::key(set));
    let mut batches: &[u8] = &batches_vec;

    let mut res = vec![];
    while !batches.is_empty() {
      res.push(Transaction::read(&mut batches).unwrap());
    }
    res
  }
}
