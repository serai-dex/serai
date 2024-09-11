#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

use ciphersuite::Ciphersuite;

use serai_db::{DbTxn, Db};
use ::primitives::EncodableG;
use ::key_gen::KeyGenParams as KeyGenParamsTrait;

mod primitives;
pub(crate) use crate::primitives::*;

// Internal utilities for scanning transactions
mod scan;

// App-logic trait satisfactions
mod key_gen;
use crate::key_gen::KeyGenParams;
mod rpc;
use rpc::Rpc;
mod scheduler;
use scheduler::Scheduler;

// Our custom code for Bitcoin
mod db;
mod txindex;

pub(crate) fn hash_bytes(hash: bitcoin_serai::bitcoin::hashes::sha256d::Hash) -> [u8; 32] {
  use bitcoin_serai::bitcoin::hashes::Hash;

  let mut res = hash.to_byte_array();
  res.reverse();
  res
}

/// Fetch the next message from the Coordinator.
///
/// This message is guaranteed to have never been handled before, where handling is defined as
/// this `txn` being committed.
async fn next_message(_txn: &mut impl DbTxn) -> messages::CoordinatorMessage {
  todo!("TODO")
}

async fn send_message(_msg: messages::ProcessorMessage) {
  todo!("TODO")
}

async fn coordinator_loop<D: Db>(
  mut db: D,
  mut key_gen: ::key_gen::KeyGen<KeyGenParams>,
  mut signers: signers::Signers<D, Rpc<D>, Scheduler<D>, Rpc<D>>,
  mut scanner: Option<scanner::Scanner<Rpc<D>>>,
) {
  loop {
    let mut txn = db.txn();
    let msg = next_message(&mut txn).await;
    let mut txn = Some(txn);
    match msg {
      messages::CoordinatorMessage::KeyGen(msg) => {
        let txn = txn.as_mut().unwrap();
        let mut new_key = None;
        // This is a computationally expensive call yet it happens infrequently
        for msg in key_gen.handle(txn, msg) {
          if let messages::key_gen::ProcessorMessage::GeneratedKeyPair { session, .. } = &msg {
            new_key = Some(*session)
          }
          send_message(messages::ProcessorMessage::KeyGen(msg)).await;
        }

        // If we were yielded a key, register it in the signers
        if let Some(session) = new_key {
          let (substrate_keys, network_keys) =
            ::key_gen::KeyGen::<KeyGenParams>::key_shares(txn, session)
              .expect("generated key pair yet couldn't get key shares");
          signers.register_keys(txn, session, substrate_keys, network_keys);
        }
      }

      // These are cheap calls which are fine to be here in this loop
      messages::CoordinatorMessage::Sign(msg) => {
        let txn = txn.as_mut().unwrap();
        signers.queue_message(txn, &msg)
      }
      messages::CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
          session,
          block_number,
          block,
        },
      ) => {
        let txn = txn.take().unwrap();
        signers.cosign_block(txn, session, block_number, block)
      }
      messages::CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::SignSlashReport { session, report },
      ) => {
        let txn = txn.take().unwrap();
        signers.sign_slash_report(txn, session, &report)
      }

      messages::CoordinatorMessage::Substrate(msg) => match msg {
        messages::substrate::CoordinatorMessage::SetKeys { serai_time, session, key_pair } => {
          let txn = txn.as_mut().unwrap();
          let key = EncodableG(
            KeyGenParams::decode_key(key_pair.1.as_ref()).expect("invalid key set on serai"),
          );

          // Queue the key to be activated upon the next Batch
          db::KeyToActivate::<
            <<KeyGenParams as ::key_gen::KeyGenParams>::ExternalNetworkCurve as Ciphersuite>::G,
          >::send(txn, &key);

          // Set the external key, as needed by the signers
          db::ExternalKeyForSessionForSigners::<
            <<KeyGenParams as ::key_gen::KeyGenParams>::ExternalNetworkCurve as Ciphersuite>::G,
          >::set(txn, session, &key);

          // This isn't cheap yet only happens for the very first set of keys
          if scanner.is_none() {
            todo!("TODO")
          }
        }
        messages::substrate::CoordinatorMessage::SlashesReported { session } => {
          let txn = txn.as_mut().unwrap();

          // Since this session had its slashes reported, it has finished all its signature
          // protocols and has been fully retired. We retire it from the signers accordingly
          let key = db::ExternalKeyForSessionForSigners::<
            <<KeyGenParams as ::key_gen::KeyGenParams>::ExternalNetworkCurve as Ciphersuite>::G,
          >::take(txn, session)
          .unwrap()
          .0;

          // This is a cheap call
          signers.retire_session(txn, session, &key)
        }
        messages::substrate::CoordinatorMessage::BlockWithBatchAcknowledgement {
          block: _,
          batch_id,
          in_instruction_succeededs,
          burns,
        } => {
          let mut txn = txn.take().unwrap();
          let scanner = scanner.as_mut().unwrap();
          let key_to_activate = db::KeyToActivate::<
            <<KeyGenParams as ::key_gen::KeyGenParams>::ExternalNetworkCurve as Ciphersuite>::G,
          >::try_recv(&mut txn)
          .map(|key| key.0);
          // This is a cheap call as it internally just queues this to be done later
          scanner.acknowledge_batch(
            txn,
            batch_id,
            in_instruction_succeededs,
            burns,
            key_to_activate,
          )
        }
        messages::substrate::CoordinatorMessage::BlockWithoutBatchAcknowledgement {
          block: _,
          burns,
        } => {
          let txn = txn.take().unwrap();
          let scanner = scanner.as_mut().unwrap();
          // This is a cheap call as it internally just queues this to be done later
          scanner.queue_burns(txn, burns)
        }
      },
    };
    // If the txn wasn't already consumed and committed, commit it
    if let Some(txn) = txn {
      txn.commit();
    }
  }
}

#[tokio::main]
async fn main() {}

/*
use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as HashTrait,
    key::{Parity, XOnlyPublicKey},
    consensus::{Encodable, Decodable},
    script::Instruction,
    Transaction, Block, ScriptBuf,
    opcodes::all::{OP_SHA256, OP_EQUALVERIFY},
  },
  wallet::{
    tweak_keys, p2tr_script_buf, ReceivedOutput, Scanner, TransactionError,
    SignableTransaction as BSignableTransaction, TransactionMachine,
  },
  rpc::{RpcError, Rpc},
};

#[cfg(test)]
use bitcoin_serai::bitcoin::{
  secp256k1::{SECP256K1, SecretKey, Message},
  PrivateKey, PublicKey,
  sighash::{EcdsaSighashType, SighashCache},
  script::PushBytesBuf,
  absolute::LockTime,
  Amount as BAmount, Sequence, Script, Witness, OutPoint,
  transaction::Version,
  blockdata::transaction::{TxIn, TxOut},
};

use serai_client::{
  primitives::{MAX_DATA_LEN, Coin, NetworkId, Amount, Balance},
  networks::bitcoin::Address,
};
*/

/*
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Fee(u64);

#[async_trait]
impl TransactionTrait<Bitcoin> for Transaction {
  #[cfg(test)]
  async fn fee(&self, network: &Bitcoin) -> u64 {
    let mut value = 0;
    for input in &self.input {
      let output = input.previous_output;
      let mut hash = *output.txid.as_raw_hash().as_byte_array();
      hash.reverse();
      value += network.rpc.get_transaction(&hash).await.unwrap().output
        [usize::try_from(output.vout).unwrap()]
      .value
      .to_sat();
    }
    for output in &self.output {
      value -= output.value.to_sat();
    }
    value
  }
}

#[async_trait]
impl BlockTrait<Bitcoin> for Block {
  async fn time(&self, rpc: &Bitcoin) -> u64 {
    // Use the network median time defined in BIP-0113 since the in-block time isn't guaranteed to
    // be monotonic
    let mut timestamps = vec![u64::from(self.header.time)];
    let mut parent = self.parent();
    // BIP-0113 uses a median of the prior 11 blocks
    while timestamps.len() < 11 {
      let mut parent_block;
      while {
        parent_block = rpc.rpc.get_block(&parent).await;
        parent_block.is_err()
      } {
        log::error!("couldn't get parent block when trying to get block time: {parent_block:?}");
        sleep(Duration::from_secs(5)).await;
      }
      let parent_block = parent_block.unwrap();
      timestamps.push(u64::from(parent_block.header.time));
      parent = parent_block.parent();

      if parent == [0; 32] {
        break;
      }
    }
    timestamps.sort();
    timestamps[timestamps.len() / 2]
  }
}

impl Bitcoin {
  pub(crate) async fn new(url: String) -> Bitcoin {
    let mut res = Rpc::new(url.clone()).await;
    while let Err(e) = res {
      log::error!("couldn't connect to Bitcoin node: {e:?}");
      sleep(Duration::from_secs(5)).await;
      res = Rpc::new(url.clone()).await;
    }
    Bitcoin { rpc: res.unwrap() }
  }

  #[cfg(test)]
  pub(crate) async fn fresh_chain(&self) {
    if self.rpc.get_latest_block_number().await.unwrap() > 0 {
      self
        .rpc
        .rpc_call(
          "invalidateblock",
          serde_json::json!([hex::encode(self.rpc.get_block_hash(1).await.unwrap())]),
        )
        .await
        .unwrap()
    }
  }

  // This function panics on a node which doesn't follow the Bitcoin protocol, which is deemed fine
  async fn median_fee(&self, block: &Block) -> Result<Fee, NetworkError> {
    let mut fees = vec![];
    if block.txdata.len() > 1 {
      for tx in &block.txdata[1 ..] {
        let mut in_value = 0;
        for input in &tx.input {
          let mut input_tx = input.previous_output.txid.to_raw_hash().to_byte_array();
          input_tx.reverse();
          in_value += self
            .rpc
            .get_transaction(&input_tx)
            .await
            .map_err(|_| NetworkError::ConnectionError)?
            .output[usize::try_from(input.previous_output.vout).unwrap()]
          .value
          .to_sat();
        }
        let out = tx.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
        fees.push((in_value - out) / u64::try_from(tx.vsize()).unwrap());
      }
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // The DUST constant documentation notes a relay rule practically enforcing a
    // 1000 sat/kilo-vbyte minimum fee.
    Ok(Fee(fee.max(1)))
  }

  #[cfg(test)]
  pub(crate) fn sign_btc_input_for_p2pkh(
    tx: &Transaction,
    input_index: usize,
    private_key: &PrivateKey,
  ) -> ScriptBuf {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    let public_key = PublicKey::from_private_key(SECP256K1, private_key);
    let main_addr = BAddress::p2pkh(public_key, BNetwork::Regtest);

    let mut der = SECP256K1
      .sign_ecdsa_low_r(
        &Message::from_digest_slice(
          SighashCache::new(tx)
            .legacy_signature_hash(
              input_index,
              &main_addr.script_pubkey(),
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

    ScriptBuf::builder()
      .push_slice(PushBytesBuf::try_from(der).unwrap())
      .push_key(&public_key)
      .into_script()
  }
}

#[async_trait]
impl Network for Bitcoin {
  // 2 inputs should be 2 * 230 = 460 weight units
  // The output should be ~36 bytes, or 144 weight units
  // The overhead should be ~20 bytes at most, or 80 weight units
  // 684 weight units, 171 vbytes, round up to 200
  // 200 vbytes at 1 sat/weight (our current minimum fee, 4 sat/vbyte) = 800 sat fee for the
  // aggregation TX
  const COST_TO_AGGREGATE: u64 = 800;

  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block_number(id).await.unwrap()
  }

  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    _: &EmptyClaim,
  ) -> bool {
    self.rpc.get_transaction(&eventuality.0).await.is_ok()
  }

  #[cfg(test)]
  async fn get_transaction_by_eventuality(&self, _: usize, id: &Eventuality) -> Transaction {
    self.rpc.get_transaction(&id.0).await.unwrap()
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    self
      .rpc
      .rpc_call::<Vec<String>>(
        "generatetoaddress",
        serde_json::json!([1, BAddress::p2sh(Script::new(), BNetwork::Regtest).unwrap()]),
      )
      .await
      .unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    use bitcoin_serai::bitcoin::{Network as BNetwork, Address as BAddress};

    let secret_key = SecretKey::new(&mut rand_core::OsRng);
    let private_key = PrivateKey::new(secret_key, BNetwork::Regtest);
    let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
    let main_addr = BAddress::p2pkh(public_key, BNetwork::Regtest);

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    self
      .rpc
      .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([100, main_addr]))
      .await
      .unwrap();

    let tx = self.get_block(new_block).await.unwrap().txdata.swap_remove(0);
    let mut tx = Transaction {
      version: Version(2),
      lock_time: LockTime::ZERO,
      input: vec![TxIn {
        previous_output: OutPoint { txid: tx.compute_txid(), vout: 0 },
        script_sig: Script::new().into(),
        sequence: Sequence(u32::MAX),
        witness: Witness::default(),
      }],
      output: vec![TxOut {
        value: tx.output[0].value - BAmount::from_sat(10000),
        script_pubkey: address.clone().into(),
      }],
    };
    tx.input[0].script_sig = Self::sign_btc_input_for_p2pkh(&tx, 0, &private_key);

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.send_raw_transaction(&tx).await.unwrap();
    for _ in 0 .. Self::CONFIRMATIONS {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}
*/
