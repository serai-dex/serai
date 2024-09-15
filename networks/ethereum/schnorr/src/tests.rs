use std::sync::Arc;

use rand_core::{RngCore, OsRng};

use group::ff::{Field, PrimeField};
use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::Address;
use alloy_sol_types::SolCall;

use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use alloy_node_bindings::{Anvil, AnvilInstance};

use crate::{PublicKey, Signature};

#[allow(warnings)]
#[allow(needless_pass_by_value)]
#[allow(clippy::all)]
#[allow(clippy::ignored_unit_patterns)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_types::sol!("contracts/tests/Schnorr.sol");
  pub(crate) use TestSchnorr::*;
}

async fn setup_test() -> (AnvilInstance, Arc<RootProvider<SimpleRequest>>, Address) {
  let anvil = Anvil::new().spawn();

  let provider = Arc::new(RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()), true),
  ));

  let mut address = [0; 20];
  OsRng.fill_bytes(&mut address);
  let address = Address::from(address);
  let _: () = provider
    .raw_request(
      "anvil_setCode".into(),
      [address.to_string(), include_str!("../artifacts/TestSchnorr.bin-runtime").to_string()],
    )
    .await
    .unwrap();

  (anvil, provider, address)
}

async fn call_verify(
  provider: &RootProvider<SimpleRequest>,
  address: Address,
  public_key: &PublicKey,
  message: &[u8],
  signature: &Signature,
) -> bool {
  let public_key: [u8; 32] = public_key.eth_repr();
  let c_bytes: [u8; 32] = signature.c().to_repr().into();
  let s_bytes: [u8; 32] = signature.s().to_repr().into();
  let call = TransactionRequest::default().to(address).input(TransactionInput::new(
    abi::verifyCall::new((
      public_key.into(),
      message.to_vec().into(),
      c_bytes.into(),
      s_bytes.into(),
    ))
    .abi_encode()
    .into(),
  ));
  let bytes = provider.call(&call).await.unwrap();
  let res = abi::verifyCall::abi_decode_returns(&bytes, true).unwrap();

  res._0
}

#[tokio::test]
async fn test_verify() {
  let (_anvil, provider, address) = setup_test().await;

  for _ in 0 .. 100 {
    let (key, public_key) = loop {
      let key = Scalar::random(&mut OsRng);
      if let Some(public_key) = PublicKey::new(ProjectivePoint::GENERATOR * key) {
        break (key, public_key);
      }
    };

    let nonce = Scalar::random(&mut OsRng);
    let mut message = vec![0; 1 + usize::try_from(OsRng.next_u32() % 256).unwrap()];
    OsRng.fill_bytes(&mut message);

    let c = Signature::challenge(ProjectivePoint::GENERATOR * nonce, &public_key, &message);
    let s = nonce + (c * key);

    let sig = Signature::new(c, s);
    assert!(sig.verify(&public_key, &message));
    assert!(call_verify(&provider, address, &public_key, &message, &sig).await);
    // Mutate the message and make sure the signature now fails to verify
    message[0] = message[0].wrapping_add(1);
    assert!(!call_verify(&provider, address, &public_key, &message, &sig).await);
  }
}
