use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use scale::Encode;

use serai_client::{
  in_instructions::primitives::{InInstruction, RefundableInInstruction, Shorthand},
  primitives::{Amount, ExternalAddress, ExternalBalance, ExternalCoin, ExternalNetworkId},
  validator_sets::primitives::ExternalKey,
};

use dockertest::{PullPolicy, Image, StartPolicy, TestBodySpecification, DockerOperations};

use crate::*;

pub const RPC_USER: &str = "serai";
pub const RPC_PASS: &str = "seraidex";

pub const BTC_PORT: u32 = 8332;
pub const ETH_PORT: u32 = 8545;
pub const XMR_PORT: u32 = 18081;

pub fn bitcoin_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("bitcoin".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
  )
  .set_publish_all_ports(true);
  (composition, BTC_PORT)
}

pub fn ethereum_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("ethereum".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-ethereum").pull_policy(PullPolicy::Never),
  )
  .set_start_policy(StartPolicy::Strict)
  .set_publish_all_ports(true);
  (composition, ETH_PORT)
}

pub fn monero_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("monero".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
  )
  .set_start_policy(StartPolicy::Strict)
  .set_publish_all_ports(true);
  (composition, XMR_PORT)
}

pub fn network_instance(network: ExternalNetworkId) -> (TestBodySpecification, u32) {
  match network {
    ExternalNetworkId::Bitcoin => bitcoin_instance(),
    ExternalNetworkId::Ethereum => ethereum_instance(),
    ExternalNetworkId::Monero => monero_instance(),
  }
}

pub fn network_rpc(network: ExternalNetworkId, ops: &DockerOperations, handle: &str) -> String {
  let (ip, port) = ops
    .handle(handle)
    .host_port(match network {
      ExternalNetworkId::Bitcoin => BTC_PORT,
      ExternalNetworkId::Ethereum => ETH_PORT,
      ExternalNetworkId::Monero => XMR_PORT,
    })
    .unwrap();
  format!("http://{RPC_USER}:{RPC_PASS}@{ip}:{port}")
}

pub fn confirmations(network: ExternalNetworkId) -> usize {
  use processor::networks::*;
  match network {
    ExternalNetworkId::Bitcoin => Bitcoin::CONFIRMATIONS,
    ExternalNetworkId::Ethereum => Ethereum::<serai_db::MemDb>::CONFIRMATIONS,
    ExternalNetworkId::Monero => Monero::CONFIRMATIONS,
  }
}

#[derive(Clone)]
pub enum Wallet {
  Bitcoin {
    private_key: bitcoin_serai::bitcoin::PrivateKey,
    public_key: bitcoin_serai::bitcoin::PublicKey,
    input_tx: bitcoin_serai::bitcoin::Transaction,
  },
  Ethereum {
    rpc_url: String,
    key: <ciphersuite::Secp256k1 as Ciphersuite>::F,
    nonce: u64,
  },
  Monero {
    handle: String,
    spend_key: Zeroizing<curve25519_dalek::scalar::Scalar>,
    view_pair: monero_wallet::ViewPair,
    last_tx: (usize, [u8; 32]),
  },
}

// TODO: Merge these functions with the processor's tests, which offers very similar functionality
impl Wallet {
  pub async fn new(network: ExternalNetworkId, ops: &DockerOperations, handle: String) -> Wallet {
    let rpc_url = network_rpc(network, ops, &handle);

    match network {
      ExternalNetworkId::Bitcoin => {
        use bitcoin_serai::{
          bitcoin::{
            secp256k1::{SECP256K1, SecretKey},
            PrivateKey, PublicKey, ScriptBuf, Network, Address,
          },
          rpc::Rpc,
        };

        let secret_key = SecretKey::new(&mut rand_core::OsRng);
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        let main_addr = Address::p2pkh(public_key, Network::Regtest);

        let rpc = Rpc::new(rpc_url).await.expect("couldn't connect to the Bitcoin RPC");

        let new_block = rpc.get_latest_block_number().await.unwrap() + 1;
        rpc
          .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr]))
          .await
          .unwrap();

        // Mine it to maturity
        rpc
          .rpc_call::<Vec<String>>(
            "generatetoaddress",
            serde_json::json!([100, Address::p2sh(&ScriptBuf::new(), Network::Regtest).unwrap()]),
          )
          .await
          .unwrap();

        let funds = rpc
          .get_block(&rpc.get_block_hash(new_block).await.unwrap())
          .await
          .unwrap()
          .txdata
          .swap_remove(0);

        Wallet::Bitcoin { private_key, public_key, input_tx: funds }
      }

      ExternalNetworkId::Ethereum => {
        use ciphersuite::{group::ff::Field, Secp256k1};
        use ethereum_serai::alloy::{
          primitives::{U256, Address},
          simple_request_transport::SimpleRequest,
          rpc_client::ClientBuilder,
          provider::{Provider, RootProvider},
          network::Ethereum,
        };

        let key = <Secp256k1 as Ciphersuite>::F::random(&mut OsRng);
        let address =
          ethereum_serai::crypto::address(&(<Secp256k1 as Ciphersuite>::generator() * key));

        let provider = RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        );

        provider
          .raw_request::<_, ()>(
            "anvil_setBalance".into(),
            [Address(address.into()).to_string(), {
              let nine_decimals = U256::from(1_000_000_000u64);
              (U256::from(100u64) * nine_decimals * nine_decimals).to_string()
            }],
          )
          .await
          .unwrap();

        Wallet::Ethereum { rpc_url: rpc_url.clone(), key, nonce: 0 }
      }

      ExternalNetworkId::Monero => {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        use monero_simple_request_rpc::SimpleRequestRpc;
        use monero_wallet::{rpc::Rpc, address::Network, ViewPair};

        let spend_key = Scalar::random(&mut OsRng);
        let view_key = Scalar::random(&mut OsRng);

        let view_pair =
          ViewPair::new(ED25519_BASEPOINT_POINT * spend_key, Zeroizing::new(view_key)).unwrap();

        let rpc = SimpleRequestRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");

        let height = rpc.get_height().await.unwrap();
        // Mines 200 blocks so sufficient decoys exist, as only 60 is needed for maturity
        rpc.generate_blocks(&view_pair.legacy_address(Network::Mainnet), 200).await.unwrap();
        let block = rpc.get_block(rpc.get_block_hash(height).await.unwrap()).await.unwrap();

        Wallet::Monero {
          handle,
          spend_key: Zeroizing::new(spend_key),
          view_pair,
          last_tx: (height, block.miner_transaction.hash()),
        }
      }
    }
  }

  pub async fn send_to_address(
    &mut self,
    ops: &DockerOperations,
    to: &ExternalKey,
    instruction: Option<InInstruction>,
  ) -> (Vec<u8>, ExternalBalance) {
    match self {
      Wallet::Bitcoin { private_key, public_key, ref mut input_tx } => {
        use bitcoin_serai::bitcoin::{
          secp256k1::{SECP256K1, Message},
          key::{XOnlyPublicKey, TweakedPublicKey},
          consensus::Encodable,
          sighash::{EcdsaSighashType, SighashCache},
          script::{PushBytesBuf, Script, ScriptBuf, Builder},
          OutPoint, Sequence, Witness, TxIn, Amount, TxOut,
          absolute::LockTime,
          transaction::{Version, Transaction},
        };

        const AMOUNT: u64 = 100000000;
        let mut tx = Transaction {
          version: Version(2),
          lock_time: LockTime::ZERO,
          input: vec![TxIn {
            previous_output: OutPoint { txid: input_tx.compute_txid(), vout: 0 },
            script_sig: Script::new().into(),
            sequence: Sequence(u32::MAX),
            witness: Witness::default(),
          }],
          output: vec![
            TxOut {
              value: Amount::from_sat(input_tx.output[0].value.to_sat() - AMOUNT - 10000),
              script_pubkey: input_tx.output[0].script_pubkey.clone(),
            },
            TxOut {
              value: Amount::from_sat(AMOUNT),
              script_pubkey: ScriptBuf::new_p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(
                  XOnlyPublicKey::from_slice(&to[1 ..]).unwrap(),
                ),
              ),
            },
          ],
        };

        if let Some(instruction) = instruction {
          tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(
              PushBytesBuf::try_from(
                Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode(),
              )
              .unwrap(),
            ),
          });
        }

        let mut der = SECP256K1
          .sign_ecdsa_low_r(
            &Message::from_digest_slice(
              SighashCache::new(&tx)
                .legacy_signature_hash(
                  0,
                  &input_tx.output[0].script_pubkey,
                  EcdsaSighashType::All.to_u32(),
                )
                .unwrap()
                .to_raw_hash()
                .as_ref(),
            )
            .unwrap(),
            &private_key.inner,
          )
          .serialize_der()
          .to_vec();
        der.push(1);
        tx.input[0].script_sig = Builder::new()
          .push_slice(PushBytesBuf::try_from(der).unwrap())
          .push_key(public_key)
          .into_script();

        let mut buf = vec![];
        tx.consensus_encode(&mut buf).unwrap();
        *input_tx = tx;
        (buf, ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(AMOUNT) })
      }

      Wallet::Ethereum { rpc_url, key, ref mut nonce } => {
        use std::sync::Arc;
        use ethereum_serai::{
          alloy::{
            primitives::{U256, Signature, TxKind},
            sol_types::SolCall,
            simple_request_transport::SimpleRequest,
            consensus::{TxLegacy, SignableTransaction},
            rpc_client::ClientBuilder,
            provider::{Provider, RootProvider},
            network::Ethereum,
          },
          crypto::PublicKey,
          deployer::Deployer,
        };

        let eight_decimals = U256::from(100_000_000u64);
        let nine_decimals = eight_decimals * U256::from(10u64);
        let eighteen_decimals = nine_decimals * nine_decimals;
        let one_eth = eighteen_decimals;

        let provider = Arc::new(RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        ));

        let to_as_key = PublicKey::new(
          <ciphersuite::Secp256k1 as Ciphersuite>::read_G(&mut to.as_slice()).unwrap(),
        )
        .unwrap();
        let router_addr = {
          // Find the deployer
          let deployer = Deployer::new(provider.clone()).await.unwrap().unwrap();

          // Find the router, deploying if non-existent
          let router = if let Some(router) =
            deployer.find_router(provider.clone(), &to_as_key).await.unwrap()
          {
            router
          } else {
            let mut tx = deployer.deploy_router(&to_as_key);
            tx.gas_price = 1_000_000_000u64.into();
            let tx = ethereum_serai::crypto::deterministically_sign(&tx);
            let signer = tx.recover_signer().unwrap();
            let (tx, sig, _) = tx.into_parts();

            provider
              .raw_request::<_, ()>(
                "anvil_setBalance".into(),
                [signer.to_string(), (tx.gas_limit * tx.gas_price).to_string()],
              )
              .await
              .unwrap();

            let mut bytes = vec![];
            tx.encode_with_signature_fields(&Signature::from(sig), &mut bytes);
            let _ = provider.send_raw_transaction(&bytes).await.unwrap();

            provider.raw_request::<_, ()>("anvil_mine".into(), [96]).await.unwrap();

            deployer.find_router(provider.clone(), &to_as_key).await.unwrap().unwrap()
          };

          router.address()
        };

        let tx = TxLegacy {
          chain_id: None,
          nonce: *nonce,
          gas_price: 1_000_000_000u128,
          gas_limit: 200_000u128,
          to: TxKind::Call(router_addr.into()),
          // 1 ETH
          value: one_eth,
          input: ethereum_serai::router::abi::inInstructionCall::new((
            [0; 20].into(),
            one_eth,
            if let Some(instruction) = instruction {
              Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode().into()
            } else {
              vec![].into()
            },
          ))
          .abi_encode()
          .into(),
        };

        *nonce += 1;

        let sig =
          k256::ecdsa::SigningKey::from(k256::elliptic_curve::NonZeroScalar::new(*key).unwrap())
            .sign_prehash_recoverable(tx.signature_hash().as_ref())
            .unwrap();

        let mut bytes = vec![];
        tx.encode_with_signature_fields(&Signature::from(sig), &mut bytes);

        // We drop the bottom 10 decimals
        (
          bytes,
          ExternalBalance {
            coin: ExternalCoin::Ether,
            amount: Amount(u64::try_from(eight_decimals).unwrap()),
          },
        )
      }

      Wallet::Monero { handle, ref spend_key, ref view_pair, ref mut last_tx } => {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use monero_simple_request_rpc::SimpleRequestRpc;
        use monero_wallet::{
          io::decompress_point,
          ringct::RctType,
          rpc::{FeePriority, Rpc},
          address::{Network, AddressType, Address},
          Scanner, OutputWithDecoys,
          send::{Change, SignableTransaction},
        };
        use processor::{additional_key, networks::Monero};

        let rpc_url = network_rpc(ExternalNetworkId::Monero, ops, handle);
        let rpc = SimpleRequestRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");

        // Prepare inputs
        let current_height = rpc.get_height().await.unwrap();
        let mut outputs = vec![];
        for block in last_tx.0 .. current_height {
          let block = rpc.get_block_by_number(block).await.unwrap();
          if (block.miner_transaction.hash() == last_tx.1) ||
            block.transactions.contains(&last_tx.1)
          {
            outputs = Scanner::new(view_pair.clone())
              .scan(rpc.get_scannable_block(block).await.unwrap())
              .unwrap()
              .ignore_additional_timelock();
          }
        }
        assert!(!outputs.is_empty());

        let mut inputs = Vec::with_capacity(outputs.len());
        for output in outputs {
          inputs.push(
            OutputWithDecoys::fingerprintable_deterministic_new(
              &mut OsRng,
              &rpc,
              16,
              rpc.get_height().await.unwrap(),
              output,
            )
            .await
            .unwrap(),
          );
        }

        let to_spend_key = decompress_point(<[u8; 32]>::try_from(to.as_ref()).unwrap()).unwrap();
        let to_view_key = additional_key::<Monero>(0);
        let to_addr = Address::new(
          Network::Mainnet,
          AddressType::Featured { subaddress: false, payment_id: None, guaranteed: true },
          to_spend_key,
          ED25519_BASEPOINT_POINT * to_view_key.0,
        );

        // Create and sign the TX
        const AMOUNT: u64 = 1_000_000_000_000;
        let mut data = vec![];
        if let Some(instruction) = instruction {
          data.push(Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode());
        }
        let mut outgoing_view_key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(outgoing_view_key.as_mut());
        let tx = SignableTransaction::new(
          RctType::ClsagBulletproofPlus,
          outgoing_view_key,
          inputs,
          vec![(to_addr, AMOUNT)],
          Change::new(view_pair.clone(), None),
          data,
          rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
        )
        .unwrap()
        .sign(&mut OsRng, spend_key)
        .unwrap();

        // Update the last TX to track the change output
        last_tx.0 = current_height;
        last_tx.1 = tx.hash();

        (tx.serialize(), ExternalBalance { coin: ExternalCoin::Monero, amount: Amount(AMOUNT) })
      }
    }
  }

  pub fn address(&self) -> ExternalAddress {
    use serai_client::networks;

    match self {
      Wallet::Bitcoin { public_key, .. } => {
        use bitcoin_serai::bitcoin::ScriptBuf;
        ExternalAddress::new(
          networks::bitcoin::Address::new(ScriptBuf::new_p2pkh(&public_key.pubkey_hash()))
            .unwrap()
            .into(),
        )
        .unwrap()
      }
      Wallet::Ethereum { key, .. } => ExternalAddress::new(
        ethereum_serai::crypto::address(&(ciphersuite::Secp256k1::generator() * key)).into(),
      )
      .unwrap(),
      Wallet::Monero { view_pair, .. } => {
        use monero_wallet::address::Network;
        ExternalAddress::new(
          networks::monero::Address::new(view_pair.legacy_address(Network::Mainnet))
            .unwrap()
            .into(),
        )
        .unwrap()
      }
    }
  }
}
