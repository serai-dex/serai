use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use crate::{hash, hash_to_scalar, serialize::write_varint, transaction::Input};

pub mod address;

mod scan;
pub use scan::SpendableOutput;

pub(crate) mod decoys;
pub(crate) use decoys::Decoys;

mod send;
pub use send::{Fee, TransactionError, SignableTransaction};
#[cfg(feature = "multisig")]
pub use send::TransactionMachine;

fn key_image_sort(x: &EdwardsPoint, y: &EdwardsPoint) -> std::cmp::Ordering {
  x.compress().to_bytes().cmp(&y.compress().to_bytes()).reverse()
}

// https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
pub(crate) fn uniqueness(inputs: &[Input]) -> [u8; 32] {
  let mut u = b"uniqueness".to_vec();
  for input in inputs {
    match input {
      // If Gen, this should be the only input, making this loop somewhat pointless
      // This works and even if there were somehow multiple inputs, it'd be a false negative
      Input::Gen(height) => {
        write_varint(&(*height).try_into().unwrap(), &mut u).unwrap();
      }
      Input::ToKey { key_image, .. } => u.extend(key_image.compress().to_bytes()),
    }
  }
  hash(&u)
}

// Hs(8Ra || o) with https://github.com/monero-project/research-lab/issues/103 as an option
#[allow(non_snake_case)]
pub(crate) fn shared_key(
  uniqueness: Option<[u8; 32]>,
  s: Scalar,
  P: &EdwardsPoint,
  o: usize,
) -> Scalar {
  // uniqueness
  let mut shared = uniqueness.map_or(vec![], |uniqueness| uniqueness.to_vec());
  // || 8Ra
  shared.extend((s * P).mul_by_cofactor().compress().to_bytes().to_vec());
  // || o
  write_varint(&o.try_into().unwrap(), &mut shared).unwrap();
  // Hs()
  hash_to_scalar(&shared)
}

pub(crate) fn amount_encryption(amount: u64, key: Scalar) -> [u8; 8] {
  let mut amount_mask = b"amount".to_vec();
  amount_mask.extend(key.to_bytes());
  (amount ^ u64::from_le_bytes(hash(&amount_mask)[0..8].try_into().unwrap())).to_le_bytes()
}

fn amount_decryption(amount: [u8; 8], key: Scalar) -> u64 {
  u64::from_le_bytes(amount_encryption(u64::from_le_bytes(amount), key))
}

pub(crate) fn commitment_mask(shared_key: Scalar) -> Scalar {
  let mut mask = b"commitment_mask".to_vec();
  mask.extend(shared_key.to_bytes());
  hash_to_scalar(&mask)
}

#[derive(Clone, Copy)]
pub struct ViewPair {
  pub spend: EdwardsPoint,
  pub view: Scalar,
}
