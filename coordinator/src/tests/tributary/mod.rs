use core::fmt::Debug;

use rand_core::{RngCore, OsRng};

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

fn random_sign_data<R: RngCore, const N: usize>(rng: &mut R) -> SignData<N> {
  let mut plan = [0; N];
  rng.fill_bytes(&mut plan);

  SignData {
    plan,
    attempt: random_u32(&mut OsRng),

    data: {
      let mut res = vec![];
      for _ in 0 .. ((rng.next_u64() % 255) + 1) {
        res.push(random_vec(&mut OsRng, 512));
      }
      res
    },

    signed: random_signed(&mut OsRng),
  }
}

fn test_read_write<RW: Eq + Debug + ReadWrite>(value: RW) {
  assert_eq!(value, RW::read::<&[u8]>(&mut value.serialize().as_ref()).unwrap());
}

#[test]
fn tx_size_limit() {
  use serai_client::validator_sets::primitives::{MAX_KEY_SHARES_PER_SET, MAX_KEY_LEN};

  use tributary::TRANSACTION_SIZE_LIMIT;

  let max_dkg_coefficients = (MAX_KEY_SHARES_PER_SET * 2).div_ceil(3) + 1;
  let max_key_shares_per_individual = MAX_KEY_SHARES_PER_SET - max_dkg_coefficients;
  // Handwave the DKG Commitments size as the size of the commitments to the coefficients and
  // 1024 bytes for all overhead
  let handwaved_dkg_commitments_size = (max_dkg_coefficients * MAX_KEY_LEN) + 1024;
  assert!(
    u32::try_from(TRANSACTION_SIZE_LIMIT).unwrap() >=
      (handwaved_dkg_commitments_size * max_key_shares_per_individual)
  );

  // Encryption key, PoP (2 elements), message
  let elements_per_share = 4;
  let handwaved_dkg_shares_size =
    (elements_per_share * MAX_KEY_LEN * MAX_KEY_SHARES_PER_SET) + 1024;
  assert!(
    u32::try_from(TRANSACTION_SIZE_LIMIT).unwrap() >=
      (handwaved_dkg_shares_size * max_key_shares_per_individual)
  );
}

#[test]
fn serialize_sign_data() {
  test_read_write(random_sign_data::<_, 3>(&mut OsRng));
  test_read_write(random_sign_data::<_, 8>(&mut OsRng));
  test_read_write(random_sign_data::<_, 16>(&mut OsRng));
  test_read_write(random_sign_data::<_, 24>(&mut OsRng));
}

#[test]
fn serialize_transaction() {
  test_read_write(Transaction::RemoveParticipant(
    frost::Participant::new(u16::try_from(OsRng.next_u64() >> 48).unwrap().saturating_add(1))
      .unwrap(),
  ));

  {
    let mut commitments = vec![random_vec(&mut OsRng, 512)];
    for _ in 0 .. (OsRng.next_u64() % 100) {
      let mut temp = commitments[0].clone();
      OsRng.fill_bytes(&mut temp);
      commitments.push(temp);
    }
    test_read_write(Transaction::DkgCommitments(
      random_u32(&mut OsRng),
      commitments,
      random_signed(&mut OsRng),
    ));
  }

  {
    // This supports a variable share length, and variable amount of sent shares, yet share length
    // and sent shares is expected to be constant among recipients
    let share_len = usize::try_from((OsRng.next_u64() % 512) + 1).unwrap();
    let amount_of_shares = usize::try_from((OsRng.next_u64() % 3) + 1).unwrap();
    // Create a valid vec of shares
    let mut shares = vec![];
    // Create up to 150 participants
    for _ in 0 .. ((OsRng.next_u64() % 150) + 1) {
      // Give each sender multiple shares
      let mut sender_shares = vec![];
      for _ in 0 .. amount_of_shares {
        let mut share = vec![0; share_len];
        OsRng.fill_bytes(&mut share);
        sender_shares.push(share);
      }
      shares.push(sender_shares);
    }

    test_read_write(Transaction::DkgShares {
      attempt: random_u32(&mut OsRng),
      shares,
      confirmation_nonces: {
        let mut nonces = [0; 64];
        OsRng.fill_bytes(&mut nonces);
        nonces
      },
      signed: random_signed(&mut OsRng),
    });
  }

  for i in 0 .. 2 {
    test_read_write(Transaction::InvalidDkgShare {
      attempt: random_u32(&mut OsRng),
      accuser: frost::Participant::new(
        u16::try_from(OsRng.next_u64() >> 48).unwrap().saturating_add(1),
      )
      .unwrap(),
      faulty: frost::Participant::new(
        u16::try_from(OsRng.next_u64() >> 48).unwrap().saturating_add(1),
      )
      .unwrap(),
      blame: if i == 0 {
        None
      } else {
        Some(random_vec(&mut OsRng, 500)).filter(|blame| !blame.is_empty())
      },
      signed: random_signed(&mut OsRng),
    });
  }

  test_read_write(Transaction::DkgConfirmed(
    random_u32(&mut OsRng),
    {
      let mut share = [0; 32];
      OsRng.fill_bytes(&mut share);
      share
    },
    random_signed(&mut OsRng),
  ));

  {
    let mut block = [0; 32];
    OsRng.fill_bytes(&mut block);
    let mut batch = [0; 5];
    OsRng.fill_bytes(&mut batch);
    test_read_write(Transaction::Batch(block, batch));
  }
  test_read_write(Transaction::SubstrateBlock(OsRng.next_u64()));

  test_read_write(Transaction::BatchPreprocess(random_sign_data(&mut OsRng)));
  test_read_write(Transaction::BatchShare(random_sign_data(&mut OsRng)));

  test_read_write(Transaction::SignPreprocess(random_sign_data(&mut OsRng)));
  test_read_write(Transaction::SignShare(random_sign_data(&mut OsRng)));

  {
    let mut plan = [0; 32];
    OsRng.fill_bytes(&mut plan);
    let mut tx_hash = vec![0; (OsRng.next_u64() % 64).try_into().unwrap()];
    OsRng.fill_bytes(&mut tx_hash);
    test_read_write(Transaction::SignCompleted {
      plan,
      tx_hash,
      first_signer: random_signed(&mut OsRng).signer,
      signature: random_signed(&mut OsRng).signature,
    });
  }
}
