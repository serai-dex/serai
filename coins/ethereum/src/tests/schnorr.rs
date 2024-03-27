use std::{convert::TryFrom, sync::Arc};

use rand_core::OsRng;

use ::k256::{elliptic_curve::bigint::ArrayEncoding, U256, Scalar};

use ethers_core::utils::{keccak256, Anvil, AnvilInstance};
use ethers_providers::{Middleware, Provider, Http};

use frost::{
  curve::Secp256k1,
  algorithm::IetfSchnorr,
  tests::{algorithm_machines, sign},
};

use crate::{
  crypto::*,
  schnorr::*,
  tests::{key_gen, deploy_contract},
};

async fn setup_test() -> (u32, AnvilInstance, Schnorr<Provider<Http>>) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u32();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  let contract_address =
    deploy_contract(chain_id, client.clone(), &wallet, "Schnorr").await.unwrap();
  let contract = Schnorr::new(contract_address, client.clone());
  (chain_id, anvil, contract)
}

#[tokio::test]
async fn test_deploy_contract() {
  setup_test().await;
}

#[tokio::test]
async fn test_ecrecover_hack() {
  let (chain_id, _anvil, contract) = setup_test().await;
  let chain_id = U256::from(chain_id);

  let (keys, public_key) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";
  let hashed_message = keccak256(MESSAGE);
  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig = sign(
    &mut OsRng,
    &algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, &algo, &keys),
    full_message,
  );
  let sig = Signature::new(&public_key, chain_id, MESSAGE, sig).unwrap();

  call_verify(&contract, &public_key, MESSAGE, &sig).await.unwrap();
  // Test an invalid signature fails
  let mut sig = sig;
  sig.s += Scalar::ONE;
  assert!(call_verify(&contract, &public_key, MESSAGE, &sig).await.is_err());
}
