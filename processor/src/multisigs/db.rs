use core::marker::PhantomData;

use ciphersuite::Ciphersuite;

pub use serai_db::*;

use scale::{Encode, Decode};
use serai_client::{
  primitives::{Balance, ExternalAddress},
  in_instructions::primitives::InInstructionWithBalance,
};

use crate::{
  Get, Db, Plan,
  networks::{Transaction, Network},
};

#[derive(Debug)]
pub struct MultisigsDb<N: Network, D: Db>(PhantomData<N>, PhantomData<D>);
impl<N: Network, D: Db> MultisigsDb<N, D> {
  fn multisigs_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MULTISIGS", dst, key)
  }

  fn next_batch_key() -> Vec<u8> {
    Self::multisigs_key(b"next_batch", [])
  }
  // Set the next batch ID to use
  pub fn set_next_batch_id(txn: &mut D::Transaction<'_>, batch: u32) {
    txn.put(Self::next_batch_key(), batch.to_le_bytes());
  }
  // Get the next batch ID
  pub fn next_batch_id<G: Get>(getter: &G) -> u32 {
    getter.get(Self::next_batch_key()).map_or(0, |v| u32::from_le_bytes(v.try_into().unwrap()))
  }

  fn plan_key(id: &[u8]) -> Vec<u8> {
    Self::multisigs_key(b"plan", id)
  }
  fn resolved_key(tx: &[u8]) -> Vec<u8> {
    Self::multisigs_key(b"resolved", tx)
  }
  fn signing_key(key: &[u8]) -> Vec<u8> {
    Self::multisigs_key(b"signing", key)
  }
  pub fn save_active_plan(
    txn: &mut D::Transaction<'_>,
    key: &[u8],
    block_number: u64,
    plan: &Plan<N>,
    operating_costs_at_time: u64,
  ) {
    let id = plan.id();

    {
      let mut signing = txn.get(Self::signing_key(key)).unwrap_or(vec![]);

      // If we've already noted we're signing this, return
      assert_eq!(signing.len() % 32, 0);
      for i in 0 .. (signing.len() / 32) {
        if signing[(i * 32) .. ((i + 1) * 32)] == id {
          return;
        }
      }

      signing.extend(&id);
      txn.put(Self::signing_key(key), id);
    }

    {
      let mut buf = block_number.to_le_bytes().to_vec();
      plan.write(&mut buf).unwrap();
      buf.extend(&operating_costs_at_time.to_le_bytes());
      txn.put(Self::plan_key(&id), &buf);
    }
  }

  pub fn active_plans<G: Get>(getter: &G, key: &[u8]) -> Vec<(u64, Plan<N>, u64)> {
    let signing = getter.get(Self::signing_key(key)).unwrap_or(vec![]);
    let mut res = vec![];

    assert_eq!(signing.len() % 32, 0);
    for i in 0 .. (signing.len() / 32) {
      let id = &signing[(i * 32) .. ((i + 1) * 32)];
      let buf = getter.get(Self::plan_key(id)).unwrap();

      let block_number = u64::from_le_bytes(buf[.. 8].try_into().unwrap());
      let plan = Plan::<N>::read::<&[u8]>(&mut &buf[8 ..]).unwrap();
      assert_eq!(id, &plan.id());
      let operating_costs = u64::from_le_bytes(buf[(buf.len() - 8) ..].try_into().unwrap());
      res.push((block_number, plan, operating_costs));
    }

    res
  }

  fn operating_costs_key() -> Vec<u8> {
    Self::multisigs_key(b"operating_costs", [])
  }
  pub fn take_operating_costs(txn: &mut D::Transaction<'_>) -> u64 {
    let existing = txn
      .get(Self::operating_costs_key())
      .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
      .unwrap_or(0);
    txn.del(Self::operating_costs_key());
    existing
  }
  pub fn set_operating_costs(txn: &mut D::Transaction<'_>, amount: u64) {
    if amount != 0 {
      txn.put(Self::operating_costs_key(), amount.to_le_bytes());
    }
  }

  pub fn resolved_plan<G: Get>(
    getter: &G,
    tx: <N::Transaction as Transaction<N>>::Id,
  ) -> Option<[u8; 32]> {
    getter.get(Self::resolved_key(tx.as_ref())).map(|id| id.try_into().unwrap())
  }
  pub fn plan_by_key_with_self_change<G: Get>(
    getter: &G,
    key: <N::Curve as Ciphersuite>::G,
    id: [u8; 32],
  ) -> bool {
    let plan =
      Plan::<N>::read::<&[u8]>(&mut &getter.get(Self::plan_key(&id)).unwrap()[8 ..]).unwrap();
    assert_eq!(plan.id(), id);
    (key == plan.key) && (Some(N::change_address(plan.key)) == plan.change)
  }
  pub fn resolve_plan(
    txn: &mut D::Transaction<'_>,
    key: &[u8],
    plan: [u8; 32],
    resolution: <N::Transaction as Transaction<N>>::Id,
  ) {
    let mut signing = txn.get(Self::signing_key(key)).unwrap_or(vec![]);
    assert_eq!(signing.len() % 32, 0);

    let mut found = false;
    for i in 0 .. (signing.len() / 32) {
      let start = i * 32;
      let end = i + 32;
      if signing[start .. end] == plan {
        found = true;
        signing = [&signing[.. start], &signing[end ..]].concat().to_vec();
        break;
      }
    }

    if !found {
      log::warn!("told to finish signing {} yet wasn't actively signing it", hex::encode(plan));
    }

    txn.put(Self::signing_key(key), signing);

    txn.put(Self::resolved_key(resolution.as_ref()), plan);
  }

  fn refund_key(id: &[u8]) -> Vec<u8> {
    Self::multisigs_key(b"refund", id)
  }
  pub fn set_refund(txn: &mut D::Transaction<'_>, id: &[u8], address: ExternalAddress) {
    txn.put(Self::refund_key(id), address.encode());
  }
  pub fn take_refund(txn: &mut D::Transaction<'_>, id: &[u8]) -> Option<ExternalAddress> {
    let key = Self::refund_key(id);
    let res = txn.get(&key).map(|address| ExternalAddress::decode(&mut address.as_ref()).unwrap());
    if res.is_some() {
      txn.del(key);
    }
    res
  }

  fn forwarded_output_key(balance: Balance) -> Vec<u8> {
    Self::multisigs_key(b"forwarded_output", balance.encode())
  }
  pub fn save_forwarded_output(
    txn: &mut D::Transaction<'_>,
    instruction: InInstructionWithBalance,
  ) {
    let key = Self::forwarded_output_key(instruction.balance);
    let mut existing = txn.get(&key).unwrap_or(vec![]);
    existing.extend(instruction.encode());
    txn.put(key, existing);
  }
  pub fn take_forwarded_output(
    txn: &mut D::Transaction<'_>,
    balance: Balance,
  ) -> Option<InInstructionWithBalance> {
    let key = Self::forwarded_output_key(balance);

    let outputs = txn.get(&key)?;
    let mut outputs_ref = outputs.as_slice();

    let res = InInstructionWithBalance::decode(&mut outputs_ref).unwrap();
    assert!(outputs_ref.len() < outputs.len());
    if outputs_ref.is_empty() {
      txn.del(&key);
    } else {
      txn.put(&key, outputs_ref);
    }
    Some(res)
  }

  fn delayed_output_keys() -> Vec<u8> {
    Self::multisigs_key(b"delayed_outputs", [])
  }
  pub fn save_delayed_output(txn: &mut D::Transaction<'_>, instruction: InInstructionWithBalance) {
    let key = Self::delayed_output_keys();
    let mut existing = txn.get(&key).unwrap_or(vec![]);
    existing.extend(instruction.encode());
    txn.put(key, existing);
  }
  pub fn take_delayed_outputs(txn: &mut D::Transaction<'_>) -> Vec<InInstructionWithBalance> {
    let key = Self::delayed_output_keys();

    let Some(outputs) = txn.get(&key) else { return vec![] };
    txn.del(key);

    let mut outputs_ref = outputs.as_slice();
    let mut res = vec![];
    while !outputs_ref.is_empty() {
      res.push(InInstructionWithBalance::decode(&mut outputs_ref).unwrap());
    }
    res
  }
}
