use core::fmt::Debug;

use rand_core::{RngCore, OsRng};

use ciphersuite::{group::Group, Ciphersuite, Ristretto};

use scale::{Encode, Decode};
use serai_client::{
  primitives::Signature,
  validator_sets::primitives::{MAX_KEY_SHARES_PER_SET, ValidatorSet, KeyPair},
};
use processor_messages::coordinator::SubstrateSignableId;

use tributary::{ReadWrite, tests::random_signed_with_nonce};

use crate::tributary::{Label, SignData, Transaction, scanner::PublishSeraiTransaction};

mod chain;
pub use chain::*;

mod tx;

mod dkg;
// TODO: Test the other transactions

mod handle_p2p;
mod sync;

#[async_trait::async_trait]
impl PublishSeraiTransaction for () {
  async fn publish_set_keys(
    &self,
    _db: &(impl Sync + serai_db::Get),
    _set: ValidatorSet,
    _key_pair: KeyPair,
    _signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
    _signature: Signature,
  ) {
    panic!("publish_set_keys was called in test")
  }
}

fn random_u32<R: RngCore>(rng: &mut R) -> u32 {
  u32::try_from(rng.next_u64() >> 32).unwrap()
}

fn random_vec<R: RngCore>(rng: &mut R, limit: usize) -> Vec<u8> {
  let len = usize::try_from(rng.next_u64() % u64::try_from(limit).unwrap()).unwrap();
  let mut res = vec![0; len];
  rng.fill_bytes(&mut res);
  res
}

fn random_sign_data<R: RngCore, Id: Clone + PartialEq + Eq + Debug + Encode + Decode>(
  rng: &mut R,
  plan: Id,
  label: Label,
) -> SignData<Id> {
  SignData {
    plan,
    attempt: random_u32(&mut OsRng),
    label,

    data: {
      let mut res = vec![];
      for _ in 0 ..= (rng.next_u64() % 255) {
        res.push(random_vec(&mut OsRng, 512));
      }
      res
    },

    signed: random_signed_with_nonce(&mut OsRng, label.nonce()),
  }
}

fn test_read_write<RW: Eq + Debug + ReadWrite>(value: &RW) {
  assert_eq!(value, &RW::read::<&[u8]>(&mut value.serialize().as_ref()).unwrap());
}

#[test]
fn tx_size_limit() {
  use serai_client::validator_sets::primitives::MAX_KEY_LEN;

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
  fn test_read_write<Id: Clone + PartialEq + Eq + Debug + Encode + Decode>(value: &SignData<Id>) {
    let mut buf = vec![];
    value.write(&mut buf).unwrap();
    assert_eq!(value, &SignData::read(&mut buf.as_slice()).unwrap())
  }

  let mut plan = [0; 3];
  OsRng.fill_bytes(&mut plan);
  test_read_write(&random_sign_data::<_, _>(
    &mut OsRng,
    plan,
    if (OsRng.next_u64() % 2) == 0 { Label::Preprocess } else { Label::Share },
  ));
  let mut plan = [0; 5];
  OsRng.fill_bytes(&mut plan);
  test_read_write(&random_sign_data::<_, _>(
    &mut OsRng,
    plan,
    if (OsRng.next_u64() % 2) == 0 { Label::Preprocess } else { Label::Share },
  ));
  let mut plan = [0; 8];
  OsRng.fill_bytes(&mut plan);
  test_read_write(&random_sign_data::<_, _>(
    &mut OsRng,
    plan,
    if (OsRng.next_u64() % 2) == 0 { Label::Preprocess } else { Label::Share },
  ));
  let mut plan = [0; 24];
  OsRng.fill_bytes(&mut plan);
  test_read_write(&random_sign_data::<_, _>(
    &mut OsRng,
    plan,
    if (OsRng.next_u64() % 2) == 0 { Label::Preprocess } else { Label::Share },
  ));
}

#[test]
fn serialize_transaction() {
  test_read_write(&Transaction::RemoveParticipant {
    participant: <Ristretto as Ciphersuite>::G::random(&mut OsRng),
    signed: random_signed_with_nonce(&mut OsRng, 0),
  });

  test_read_write(&Transaction::DkgParticipation {
    participation: random_vec(&mut OsRng, 4096),
    signed: random_signed_with_nonce(&mut OsRng, 0),
  });

  test_read_write(&Transaction::DkgConfirmationNonces {
    attempt: random_u32(&mut OsRng),
    confirmation_nonces: {
      let mut nonces = [0; 64];
      OsRng.fill_bytes(&mut nonces);
      nonces
    },
    signed: random_signed_with_nonce(&mut OsRng, 0),
  });

  test_read_write(&Transaction::DkgConfirmationShare {
    attempt: random_u32(&mut OsRng),
    confirmation_share: {
      let mut share = [0; 32];
      OsRng.fill_bytes(&mut share);
      share
    },
    signed: random_signed_with_nonce(&mut OsRng, 1),
  });

  {
    let mut block = [0; 32];
    OsRng.fill_bytes(&mut block);
    test_read_write(&Transaction::CosignSubstrateBlock(block));
  }

  {
    let mut block = [0; 32];
    OsRng.fill_bytes(&mut block);
    let batch = u32::try_from(OsRng.next_u64() >> 32).unwrap();
    test_read_write(&Transaction::Batch { block, batch });
  }
  test_read_write(&Transaction::SubstrateBlock(OsRng.next_u64()));

  {
    let batch = u32::try_from(OsRng.next_u64() >> 32).unwrap();
    test_read_write(&Transaction::SubstrateSign(random_sign_data(
      &mut OsRng,
      SubstrateSignableId::Batch(batch),
      Label::Preprocess,
    )));
  }
  {
    let batch = u32::try_from(OsRng.next_u64() >> 32).unwrap();
    test_read_write(&Transaction::SubstrateSign(random_sign_data(
      &mut OsRng,
      SubstrateSignableId::Batch(batch),
      Label::Share,
    )));
  }

  {
    let mut plan = [0; 32];
    OsRng.fill_bytes(&mut plan);
    test_read_write(&Transaction::Sign(random_sign_data(&mut OsRng, plan, Label::Preprocess)));
  }
  {
    let mut plan = [0; 32];
    OsRng.fill_bytes(&mut plan);
    test_read_write(&Transaction::Sign(random_sign_data(&mut OsRng, plan, Label::Share)));
  }

  {
    let mut plan = [0; 32];
    OsRng.fill_bytes(&mut plan);
    let mut tx_hash = vec![0; (OsRng.next_u64() % 64).try_into().unwrap()];
    OsRng.fill_bytes(&mut tx_hash);
    test_read_write(&Transaction::SignCompleted {
      plan,
      tx_hash,
      first_signer: random_signed_with_nonce(&mut OsRng, 2).signer,
      signature: random_signed_with_nonce(&mut OsRng, 2).signature,
    });
  }

  test_read_write(&Transaction::SlashReport(
    {
      let amount =
        usize::try_from(OsRng.next_u64() % u64::from(MAX_KEY_SHARES_PER_SET - 1)).unwrap();
      let mut points = vec![];
      for _ in 0 .. amount {
        points.push((OsRng.next_u64() >> 32).try_into().unwrap());
      }
      points
    },
    random_signed_with_nonce(&mut OsRng, 0),
  ));
}
