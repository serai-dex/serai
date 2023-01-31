use ethereum_serai::{crypto::*};
use frost::{
  algorithm::Schnorr,
  curve::Secp256k1,
  ThresholdKeys,
  tests::{algorithm_machines, key_gen, sign},
};
use k256::{elliptic_curve::bigint::ArrayEncoding, ProjectivePoint, Scalar, U256};
use ethers::{
  prelude::*,
  utils::{keccak256},
};
use rand_core::OsRng;
use std::collections::HashMap;

pub(crate) async fn generate_keys() -> (HashMap<u16, ThresholdKeys<Secp256k1>>, ProjectivePoint) {
  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&1].group_key();
  (keys, group_key)
}

pub async fn hash_and_sign(
  message: &[u8],
  keys: HashMap<u16, ThresholdKeys<Secp256k1>>,
  group_key: &ProjectivePoint,
  chain_id: ethers::prelude::U256,
) -> ProcessedSignature {
  let hashed_message = keccak256(message);
  let chain_id = U256::from(Scalar::from(chain_id.as_u32()));

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let algo = Schnorr::<Secp256k1, EthereumHram>::new();
  let sig = sign(
    &mut OsRng,
    algo.clone(),
    keys.clone(),
    algorithm_machines(&mut OsRng, algo, &keys),
    full_message,
  );
  process_signature_for_contract(hashed_message, &sig.R, sig.s, &group_key, chain_id)
}
