use std::collections::HashSet;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use serai_primitives::NetworkId;
use serai_validator_sets_primitives::ExternalKey;

use dockertest::{PullPolicy, Image, StartPolicy, Composition, DockerOperations};

use crate::*;

pub const RPC_USER: &str = "serai";
pub const RPC_PASS: &str = "seraidex";

pub const BTC_PORT: u32 = 8332;
pub const XMR_PORT: u32 = 18081;

pub fn bitcoin_instance() -> (Composition, u32) {
  serai_docker_tests::build("bitcoin".to_string());

  let mut composition = Composition::with_image(
    Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
  )
  .with_cmd(vec![
    "bitcoind".to_string(),
    "-txindex".to_string(),
    "-regtest".to_string(),
    format!("-rpcuser={RPC_USER}"),
    format!("-rpcpassword={RPC_PASS}"),
    "-rpcbind=0.0.0.0".to_string(),
    "-rpcallowip=0.0.0.0/0".to_string(),
    "-rpcport=8332".to_string(),
  ]);
  composition.publish_all_ports();
  (composition, BTC_PORT)
}

pub fn monero_instance() -> (Composition, u32) {
  serai_docker_tests::build("monero".to_string());

  let mut composition = Composition::with_image(
    Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
  )
  .with_cmd(vec![
    "monerod".to_string(),
    "--regtest".to_string(),
    "--offline".to_string(),
    "--fixed-difficulty=1".to_string(),
    "--rpc-bind-ip=0.0.0.0".to_string(),
    format!("--rpc-login={RPC_USER}:{RPC_PASS}"),
    "--rpc-access-control-origins=*".to_string(),
    "--confirm-external-bind".to_string(),
    "--non-interactive".to_string(),
  ])
  .with_start_policy(StartPolicy::Strict);
  composition.publish_all_ports();
  (composition, XMR_PORT)
}

pub fn network_instance(network: NetworkId) -> (Composition, u32) {
  match network {
    NetworkId::Bitcoin => bitcoin_instance(),
    NetworkId::Ethereum => todo!(),
    NetworkId::Monero => monero_instance(),
    NetworkId::Serai => {
      panic!("Serai is not a valid network to spawn an instance of for a processor")
    }
  }
}

pub fn network_rpc(network: NetworkId, ops: &DockerOperations, handle: &str) -> String {
  let (ip, port) = ops
    .handle(handle)
    .host_port(match network {
      NetworkId::Bitcoin => BTC_PORT,
      NetworkId::Ethereum => todo!(),
      NetworkId::Monero => XMR_PORT,
      NetworkId::Serai => panic!("getting port for external network yet it was Serai"),
    })
    .unwrap();
  format!("http://{RPC_USER}:{RPC_PASS}@{ip}:{port}")
}

pub fn confirmations(network: NetworkId) -> usize {
  use processor::coins::*;
  match network {
    NetworkId::Bitcoin => Bitcoin::CONFIRMATIONS,
    NetworkId::Ethereum => todo!(),
    NetworkId::Monero => Monero::CONFIRMATIONS,
    NetworkId::Serai => panic!("getting confirmations required for Serai"),
  }
}

#[derive(Clone)]
pub enum Wallet {
  Bitcoin {
    private_key: bitcoin_serai::bitcoin::PrivateKey,
    public_key: bitcoin_serai::bitcoin::PublicKey,
    input_tx: bitcoin_serai::bitcoin::Transaction,
  },
  Monero {
    handle: String,
    spend_key: Zeroizing<curve25519_dalek::scalar::Scalar>,
    view_pair: monero_serai::wallet::ViewPair,
    inputs: Vec<monero_serai::wallet::ReceivedOutput>,
  },
}

// TODO: Merge these functions with the processor's tests, which offers very similar functionality
impl Wallet {
  pub async fn new(network: NetworkId, ops: &DockerOperations, handle: String) -> Wallet {
    let rpc_url = network_rpc(network, ops, &handle);

    match network {
      NetworkId::Bitcoin => {
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
        let main_addr = Address::p2pkh(&public_key, Network::Regtest);

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

      NetworkId::Ethereum => todo!(),

      NetworkId::Monero => {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        use monero_serai::{
          wallet::{
            ViewPair, Scanner,
            address::{Network, AddressSpec},
          },
          rpc::HttpRpc,
        };

        let mut bytes = [0; 64];
        OsRng.fill_bytes(&mut bytes);
        let spend_key = Scalar::from_bytes_mod_order_wide(&bytes);
        OsRng.fill_bytes(&mut bytes);
        let view_key = Scalar::from_bytes_mod_order_wide(&bytes);

        let view_pair =
          ViewPair::new(ED25519_BASEPOINT_POINT * spend_key, Zeroizing::new(view_key));

        let rpc = HttpRpc::new(rpc_url).expect("couldn't connect to the Monero RPC");

        let height = rpc.get_height().await.unwrap();
        // Mines 200 blocks so sufficient decoys exist, as only 60 is needed for maturity
        let _: EmptyResponse = rpc
          .json_rpc_call(
            "generateblocks",
            Some(serde_json::json!({
              "wallet_address": view_pair.address(
                Network::Mainnet,
                AddressSpec::Standard
              ).to_string(),
              "amount_of_blocks": 200,
            })),
          )
          .await
          .unwrap();
        let block = rpc.get_block(rpc.get_block_hash(height).await.unwrap()).await.unwrap();

        let output = Scanner::from_view(view_pair.clone(), Some(HashSet::new()))
          .scan(&rpc, &block)
          .await
          .unwrap()
          .remove(0)
          .ignore_timelock()
          .remove(0);

        Wallet::Monero {
          handle,
          spend_key: Zeroizing::new(spend_key),
          view_pair,
          inputs: vec![output.output.clone()],
        }
      }
      NetworkId::Serai => panic!("creating a wallet for for Serai"),
    }
  }

  pub async fn send_to_address(&mut self, ops: &DockerOperations, to: &ExternalKey) -> Vec<u8> {
    match self {
      Wallet::Bitcoin { private_key, public_key, ref mut input_tx } => {
        use bitcoin_serai::bitcoin::{
          secp256k1::{SECP256K1, Message},
          key::{XOnlyPublicKey, TweakedPublicKey},
          consensus::Encodable,
          sighash::{EcdsaSighashType, SighashCache},
          script::{PushBytesBuf, Script, Builder},
          address::Payload,
          OutPoint, Sequence, Witness, TxIn, TxOut,
          absolute::LockTime,
          Transaction,
        };

        let mut tx = Transaction {
          version: 2,
          lock_time: LockTime::ZERO,
          input: vec![TxIn {
            previous_output: OutPoint { txid: input_tx.txid(), vout: 0 },
            script_sig: Script::empty().into(),
            sequence: Sequence(u32::MAX),
            witness: Witness::default(),
          }],
          output: vec![TxOut {
            value: input_tx.output[0].value - 10000,
            script_pubkey: Payload::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
              XOnlyPublicKey::from_slice(&to[1 ..]).unwrap(),
            ))
            .script_pubkey(),
          }],
        };

        let mut der = SECP256K1
          .sign_ecdsa_low_r(
            &Message::from(
              SighashCache::new(&tx)
                .legacy_signature_hash(
                  0,
                  &input_tx.output[0].script_pubkey,
                  EcdsaSighashType::All.to_u32(),
                )
                .unwrap()
                .to_raw_hash(),
            ),
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
        buf
      }

      Wallet::Monero { handle, ref spend_key, ref view_pair, ref mut inputs } => {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};
        use monero_serai::{
          Protocol,
          wallet::{
            address::{Network, AddressType, AddressMeta, Address},
            SpendableOutput, Decoys, Change, FeePriority, Scanner, SignableTransaction,
          },
          rpc::HttpRpc,
        };
        use processor::{additional_key, coins::Monero};

        let rpc_url = network_rpc(NetworkId::Monero, ops, handle);
        let rpc = HttpRpc::new(rpc_url).expect("couldn't connect to the Monero RPC");

        // Prepare inputs
        let outputs = inputs.drain(..).collect::<Vec<_>>();
        let mut these_inputs = vec![];
        for output in outputs {
          these_inputs.push(
            SpendableOutput::from(&rpc, output)
              .await
              .expect("prior transaction was never published"),
          );
        }
        let mut decoys = Decoys::select(
          &mut OsRng,
          &rpc,
          Protocol::v16.ring_len(),
          rpc.get_height().await.unwrap() - 1,
          &these_inputs,
        )
        .await
        .unwrap();

        let to_spend_key =
          CompressedEdwardsY(<[u8; 32]>::try_from(to.as_ref()).unwrap()).decompress().unwrap();
        let to_view_key = additional_key::<Monero>(0);
        let to_addr = Address::new(
          AddressMeta::new(
            Network::Mainnet,
            AddressType::Featured { subaddress: false, payment_id: None, guaranteed: true },
          ),
          to_spend_key,
          ED25519_BASEPOINT_POINT * to_view_key.0,
        );

        // Create and sign the TX
        let tx = SignableTransaction::new(
          Protocol::v16,
          None,
          these_inputs.drain(..).zip(decoys.drain(..)).collect(),
          vec![(to_addr, 1_000_000_000_000)],
          Some(Change::new(view_pair, false)),
          vec![],
          rpc.get_fee(Protocol::v16, FeePriority::Low).await.unwrap(),
        )
        .unwrap()
        .sign(&mut OsRng, spend_key)
        .await
        .unwrap();

        // Push the change output
        inputs.push(
          Scanner::from_view(view_pair.clone(), Some(HashSet::new()))
            .scan_transaction(&tx)
            .ignore_timelock()
            .remove(0),
        );

        tx.serialize()
      }
    }
  }
}
