use ethereum_serai::{crypto};
use frost::{curve::Secp256k1, FrostKeys};
use k256::ProjectivePoint;
use ethers::{
  prelude::*,
  utils::{keccak256},
};
use std::collections::HashMap;

pub async fn generate_keys() -> (HashMap<u16, FrostKeys<Secp256k1>>, ProjectivePoint) {
  use frost::{tests::key_gen};
  use rand_core::OsRng;

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&1].group_key();
  (keys, group_key)
}

pub async fn hash_and_sign(
  message: &[u8],
  keys: &HashMap<u16, FrostKeys<Secp256k1>>,
  group_key: &ProjectivePoint,
  chain_id: ethers::prelude::U256,
) -> crypto::ProcessedSignature {
  use frost::{
    algorithm::Schnorr,
    tests::{algorithm_machines, sign},
  };
  use k256::{elliptic_curve::bigint::ArrayEncoding, Scalar, U256};
  use rand_core::OsRng;

  let hashed_message = keccak256(message);
  let chain_id = U256::from(Scalar::from(chain_id.as_u32()));

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, crypto::EthereumHram>::new(), &keys),
    full_message,
  );
  crypto::process_signature_for_contract(hashed_message, &sig.R, sig.s, &group_key, chain_id)
}
