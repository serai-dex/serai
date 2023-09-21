use core::marker::PhantomData;

use ciphersuite::Ciphersuite;

pub use serai_db::*;

use crate::{
  Get, Db, Plan,
  networks::{Transaction, Network},
};

#[derive(Debug)]
pub struct MultisigsDb<N: Network, D: Db>(D, PhantomData<N>);
impl<N: Network, D: Db> MultisigsDb<N, D> {
  pub fn new(db: D) -> Self {
    Self(db, PhantomData)
  }

  fn multisigs_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MULTISIGS", dst, key)
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
      txn.put(Self::plan_key(&id), &buf);
    }
  }

  pub fn active_plans(&self, key: &[u8]) -> Vec<(u64, Plan<N>)> {
    let signing = self.0.get(Self::signing_key(key)).unwrap_or(vec![]);
    let mut res = vec![];

    assert_eq!(signing.len() % 32, 0);
    for i in 0 .. (signing.len() / 32) {
      let id = &signing[(i * 32) .. ((i + 1) * 32)];
      let buf = self.0.get(Self::plan_key(id)).unwrap();

      let block_number = u64::from_le_bytes(buf[.. 8].try_into().unwrap());
      let plan = Plan::<N>::read::<&[u8]>(&mut &buf[8 ..]).unwrap();
      assert_eq!(id, &plan.id());
      res.push((block_number, plan));
    }

    res
  }

  pub fn resolved_plan<G: Get>(
    getter: &G,
    tx: <N::Transaction as Transaction<N>>::Id,
  ) -> Option<[u8; 32]> {
    getter.get(tx.as_ref()).map(|id| id.try_into().unwrap())
  }
  pub fn plan_by_key_with_self_change<G: Get>(
    getter: &G,
    key: <N::Curve as Ciphersuite>::G,
    id: [u8; 32],
  ) -> bool {
    let plan =
      Plan::<N>::read::<&[u8]>(&mut &getter.get(Self::plan_key(&id)).unwrap()[8 ..]).unwrap();
    assert_eq!(plan.id(), id);
    (key == plan.key) && (Some(plan.key) == plan.change)
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
}
