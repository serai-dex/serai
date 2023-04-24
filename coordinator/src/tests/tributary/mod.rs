use core::fmt::Debug;
use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use frost::Participant;

use tributary::{ReadWrite, tests::random_signed};

use crate::tributary::{SignData, Transaction};

mod chain;
pub use chain::*;

mod tx;

mod dkg;
// TODO: Test the other transactions

mod handle_p2p;
mod sync;

fn random_u32<R: RngCore>(rng: &mut R) -> u32 {
  u32::try_from(rng.next_u64() >> 32).unwrap()
}

fn random_vec<R: RngCore>(rng: &mut R, limit: usize) -> Vec<u8> {
  let len = usize::try_from(rng.next_u64() % u64::try_from(limit).unwrap()).unwrap();
  let mut res = vec![0; len];
  rng.fill_bytes(&mut res);
  res
}

fn random_sign_data<R: RngCore>(rng: &mut R) -> SignData {
  let mut plan = [0; 32];
  rng.fill_bytes(&mut plan);

  SignData {
    plan,
    attempt: random_u32(&mut OsRng),

    data: random_vec(&mut OsRng, 512),

    signed: random_signed(&mut OsRng),
  }
}

fn test_read_write<RW: Eq + Debug + ReadWrite>(value: RW) {
  assert_eq!(value, RW::read::<&[u8]>(&mut value.serialize().as_ref()).unwrap());
}

#[test]
fn serialize_sign_data() {
  test_read_write(random_sign_data(&mut OsRng));
}

#[test]
fn serialize_transaction() {
  test_read_write(Transaction::DkgCommitments(
    random_u32(&mut OsRng),
    random_vec(&mut OsRng, 512),
    random_signed(&mut OsRng),
  ));

  {
    // This supports a variable share length, yet share length is expected to be constant among
    // shares
    let share_len = usize::try_from(OsRng.next_u64() % 512).unwrap();
    // Create a valid map of shares
    let mut shares = HashMap::new();
    // Create up to 512 participants
    for i in 0 .. (OsRng.next_u64() % 512) {
      let mut share = vec![0; share_len];
      OsRng.fill_bytes(&mut share);
      shares.insert(Participant::new(u16::try_from(i + 1).unwrap()).unwrap(), share);
    }

    test_read_write(Transaction::DkgShares(
      random_u32(&mut OsRng),
      shares,
      random_signed(&mut OsRng),
    ));
  }

  {
    let mut ext_block = [0; 32];
    OsRng.fill_bytes(&mut ext_block);
    test_read_write(Transaction::ExternalBlock(ext_block));
  }
  test_read_write(Transaction::SubstrateBlock(OsRng.next_u64()));

  test_read_write(Transaction::BatchPreprocess(random_sign_data(&mut OsRng)));
  test_read_write(Transaction::BatchShare(random_sign_data(&mut OsRng)));

  test_read_write(Transaction::SignPreprocess(random_sign_data(&mut OsRng)));
  test_read_write(Transaction::SignShare(random_sign_data(&mut OsRng)));
}
