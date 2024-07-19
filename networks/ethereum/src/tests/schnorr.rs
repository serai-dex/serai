use std::sync::Arc;

use rand_core::OsRng;

use group::ff::PrimeField;
use k256::Scalar;

use frost::{
  curve::Secp256k1,
  algorithm::IetfSchnorr,
  tests::{algorithm_machines, sign},
};

use alloy_core::primitives::Address;

use alloy_sol_types::SolCall;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use alloy_node_bindings::{Anvil, AnvilInstance};

use crate::{
  Error,
  crypto::*,
  tests::{key_gen, deploy_contract, abi::schnorr as abi},
};

async fn setup_test() -> (AnvilInstance, Arc<RootProvider<SimpleRequest>>, Address) {
  let anvil = Anvil::new().spawn();

  let provider = RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()), true),
  );
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  let address = deploy_contract(client.clone(), &wallet, "TestSchnorr").await.unwrap();
  (anvil, client, address)
}

#[tokio::test]
async fn test_deploy_contract() {
  setup_test().await;
}

pub async fn call_verify(
  provider: &RootProvider<SimpleRequest>,
  contract: Address,
  public_key: &PublicKey,
  message: &[u8],
  signature: &Signature,
) -> Result<(), Error> {
  let px: [u8; 32] = public_key.px.to_repr().into();
  let c_bytes: [u8; 32] = signature.c.to_repr().into();
  let s_bytes: [u8; 32] = signature.s.to_repr().into();
  let call = TransactionRequest::default().to(contract).input(TransactionInput::new(
    abi::verifyCall::new((px.into(), message.to_vec().into(), c_bytes.into(), s_bytes.into()))
      .abi_encode()
      .into(),
  ));
  let bytes = provider.call(&call).await.map_err(|_| Error::ConnectionError)?;
  let res =
    abi::verifyCall::abi_decode_returns(&bytes, true).map_err(|_| Error::ConnectionError)?;

  if res._0 {
    Ok(())
  } else {
    Err(Error::InvalidSignature)
  }
}

#[tokio::test]
async fn test_ecrecover_hack() {
  let (_anvil, client, contract) = setup_test().await;

  let (keys, public_key) = key_gen();

  const MESSAGE: &[u8] = b"Hello, World!";

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, &keys), MESSAGE);
  let sig = Signature::new(&public_key, MESSAGE, sig).unwrap();

  call_verify(&client, contract, &public_key, MESSAGE, &sig).await.unwrap();
  // Test an invalid signature fails
  let mut sig = sig;
  sig.s += Scalar::ONE;
  assert!(call_verify(&client, contract, &public_key, MESSAGE, &sig).await.is_err());
}
