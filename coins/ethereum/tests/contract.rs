use std::{convert::TryFrom, sync::Arc, time::Duration, fs::File};

use rand_core::OsRng;

use ::k256::{
  elliptic_curve::{bigint::ArrayEncoding, PrimeField},
  U256,
};

use ethers_core::{
  types::Signature,
  abi::Abi,
  utils::{keccak256, Anvil, AnvilInstance},
};
use ethers_contract::ContractFactory;
use ethers_providers::{Middleware, Provider, Http};
use ethers::{prelude::*, utils::Anvil};

use frost::{
  curve::Secp256k1,
  Participant,
  algorithm::IetfSchnorr,
  tests::{key_gen, algorithm_machines, sign},
};

use ethereum_serai::{
  crypto,
  contract::{Schnorr, call_verify},
  call_router_execute, call_verify, deploy_router_contract, deploy_schnorr_verifier_contract,
  router_mod,
};

// TODO: Replace with a contract deployment from an unknown account, so the environment solely has
// to fund the deployer, not create/pass a wallet
pub async fn deploy_schnorr_verifier_contract(
  chain_id: u32,
  client: Arc<Provider<Http>>,
  wallet: &k256::ecdsa::SigningKey,
) -> eyre::Result<Schnorr<Provider<Http>>> {
  let abi: Abi = serde_json::from_reader(File::open("./artifacts/Schnorr.abi").unwrap()).unwrap();

  let hex_bin_buf = std::fs::read_to_string("./artifacts/Schnorr.bin").unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let bin = hex::decode(hex_bin).unwrap();
  let factory = ContractFactory::new(abi, bin.into(), client.clone());

  let mut deployment_tx = factory.deploy(())?.tx;
  deployment_tx.set_chain_id(chain_id);
  deployment_tx.set_gas(500_000);
  let (max_fee_per_gas, max_priority_fee_per_gas) = client.estimate_eip1559_fees(None).await?;
  deployment_tx.as_eip1559_mut().unwrap().max_fee_per_gas = Some(max_fee_per_gas);
  deployment_tx.as_eip1559_mut().unwrap().max_priority_fee_per_gas = Some(max_priority_fee_per_gas);

  let sig_hash = deployment_tx.sighash();
  let (sig, rid) = wallet.sign_prehash_recoverable(sig_hash.as_ref()).unwrap();

  // EIP-155 v
  let mut v = u64::from(rid.to_byte());
  assert!((v == 0) || (v == 1));
  v += u64::from((chain_id * 2) + 35);

  let r = sig.r().to_repr();
  let r_ref: &[u8] = r.as_ref();
  let s = sig.s().to_repr();
  let s_ref: &[u8] = s.as_ref();
  let deployment_tx = deployment_tx.rlp_signed(&Signature { r: r_ref.into(), s: s_ref.into(), v });

  let pending_tx = client.send_raw_transaction(deployment_tx).await?;

  let mut receipt;
  while {
    receipt = client.get_transaction_receipt(pending_tx.tx_hash()).await?;
    receipt.is_none()
  } {
    tokio::time::sleep(Duration::from_secs(6)).await;
  }
  let receipt = receipt.unwrap();
  assert!(receipt.status == Some(1.into()));

  let contract = Schnorr::new(receipt.contract_address.unwrap(), client.clone());
  Ok(contract)
}

async fn deploy_test_contract() -> (u32, AnvilInstance, Schnorr<Provider<Http>>) {
  let anvil = Anvil::new().spawn();

  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let chain_id = provider.get_chainid().await.unwrap().as_u32();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  (chain_id, anvil, deploy_schnorr_verifier_contract(chain_id, client, &wallet).await.unwrap())
}

#[tokio::test]
async fn test_deploy_contract() {
  deploy_test_contract().await;
}

#[tokio::test]
async fn test_deploy_schnorr_contract() {
  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let _contract = deploy_schnorr_verifier_contract(client).await.unwrap();
}

#[tokio::test]
async fn test_deploy_router_contract() {
  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let _contract = deploy_router_contract(client).await.unwrap();
}

#[tokio::test]
async fn test_call_router_execute() {
  use ethereum_serai::crypto;
  use ethers::utils::keccak256;
  use frost::{
    algorithm::Schnorr,
    curve::Secp256k1,
    tests::{algorithm_machines, key_gen, sign},
  };
  use k256::elliptic_curve::bigint::ArrayEncoding;
  use k256::{Scalar, U256};
  use rand_core::OsRng;

  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let chain_id = provider.get_chainid().await.unwrap();
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&1].group_key();

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let data = Bytes::from([0]);
  let tx = router_mod::Transaction { to: to.clone(), value: value.clone(), data: data.clone() };
  let txs = vec![tx];

  const MESSAGE: &'static [u8] = b"Hello, World!";
  let hashed_message = keccak256(MESSAGE);
  let chain_id = U256::from(Scalar::from(chain_id.as_u32()));

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, crypto::EthereumHram>::new(), &keys),
    full_message,
  );
  let processed_sig =
    crypto::process_signature_for_contract(hashed_message, &sig.R, sig.s, &group_key, chain_id);

  let contract = deploy_router_contract(client.clone()).await.unwrap();
  let res = call_router_execute(&contract, txs.clone(), &processed_sig).await;
  assert!(res.is_err()); // should revert as signature is for incorrect message

  // try w actual data
  let tokens = vec![abi::Token::Array(vec![abi::Token::Tuple(vec![
    abi::Token::Address(to),
    abi::Token::Uint(value),
    abi::Token::Bytes(data.to_vec()),
  ])])];
  let encoded_calldata = abi::encode(&tokens);
  let hashed_message = keccak256(encoded_calldata);

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let sig = sign(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, crypto::EthereumHram>::new(), &keys),
    full_message,
  );
  let processed_sig =
    crypto::process_signature_for_contract(hashed_message, &sig.R, sig.s, &group_key, chain_id);

  let contract = deploy_router_contract(client).await.unwrap();
  call_router_execute(&contract, txs.clone(), &processed_sig).await.unwrap();
  call_router_execute_no_abi_encode(&contract, txs, &processed_sig).await.unwrap();
}

#[tokio::test]
async fn test_ecrecover_hack() {
  let (chain_id, _anvil, contract) = deploy_test_contract().await;
  let chain_id = U256::from(chain_id);

  let keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&Participant::new(1).unwrap()].group_key();

  const MESSAGE: &[u8] = b"Hello, World!";
  let hashed_message = keccak256(MESSAGE);

  let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

  let algo = IetfSchnorr::<Secp256k1, crypto::EthereumHram>::ietf();
  let sig = sign(
    &mut OsRng,
    &algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, &algo, &keys),
    full_message,
  );
  let mut processed_sig =
    crypto::process_signature_for_contract(hashed_message, &sig.R, sig.s, &group_key, chain_id);

  call_verify(&contract, &processed_sig).await.unwrap();

  // test invalid signature fails
  processed_sig.message[0] = 0;
  assert!(call_verify(&contract, &processed_sig).await.is_err());
}
