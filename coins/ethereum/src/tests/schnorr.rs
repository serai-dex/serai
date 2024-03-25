use std::{convert::TryFrom, sync::Arc};

use rand_core::OsRng;

use group::ff::PrimeField;
use k256::Scalar;

use ethers_core::utils::{Anvil, AnvilInstance};
use ethers_providers::{Middleware, Provider, Http};

use frost::{
  curve::Secp256k1,
  algorithm::IetfSchnorr,
  tests::{algorithm_machines, sign},
};

use crate::{
  Error,
  crypto::*,
  tests::{key_gen, deploy_contract, abi::schnorr::TestSchnorr as Schnorr},
};

async fn setup_test() -> (AnvilInstance, Schnorr<Provider<Http>>) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u32();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  let contract_address =
    deploy_contract(chain_id, client.clone(), &wallet, "TestSchnorr").await.unwrap();
  let contract = Schnorr::new(contract_address, client.clone());
  (anvil, contract)
}

#[tokio::test]
async fn test_deploy_contract() {
  setup_test().await;
}

pub async fn call_verify(
  contract: &Schnorr<Provider<Http>>,
  public_key: &PublicKey,
  message: &[u8],
  signature: &Signature,
) -> Result<(), Error> {
  if contract
    .verify(
      public_key.px.to_repr().into(),
      message.to_vec().into(),
      signature.c.to_repr().into(),
      signature.s.to_repr().into(),
    )
    .call()
    .await
    .unwrap()
  {
    Ok(())
  } else {
    Err(Error::InvalidSignature)
  }
}

#[tokio::test]
async fn test_ecrecover_hack() {
  let (_anvil, contract) = setup_test().await;

  let (keys, public_key) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, &keys), MESSAGE);
  let sig = Signature::new(&public_key, MESSAGE, sig).unwrap();

  call_verify(&contract, &public_key, MESSAGE, &sig).await.unwrap();
  // Test an invalid signature fails
  let mut sig = sig;
  sig.s += Scalar::ONE;
  assert!(call_verify(&contract, &public_key, MESSAGE, &sig).await.is_err());
}
