use dockertest::{
  PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image,
  TestBodySpecification, DockerOperations, DockerTest,
};

#[cfg(feature = "bitcoin")]
mod bitcoin {
  use std::sync::Arc;

  use rand_core::OsRng;

  use frost::Participant;

  use bitcoin_serai::bitcoin::{
    secp256k1::{SECP256K1, SecretKey, Message},
    PrivateKey, PublicKey,
    hashes::{HashEngine, Hash, sha256::Hash as Sha256},
    sighash::{SighashCache, EcdsaSighashType},
    absolute::LockTime,
    Amount as BAmount, Sequence, Script, Witness, OutPoint,
    address::Address as BAddress,
    transaction::{Version, Transaction, TxIn, TxOut},
    Network as BNetwork, ScriptBuf,
    opcodes::all::{OP_SHA256, OP_EQUALVERIFY},
  };

  use scale::Encode;
  use sp_application_crypto::Pair;
  use serai_client::{in_instructions::primitives::Shorthand, primitives::insecure_pair_from_name};

  use tokio::{
    time::{timeout, Duration},
    sync::Mutex,
  };

  use serai_db::MemDb;

  use super::*;
  use crate::{
    networks::{Network, UtxoNetwork, Bitcoin, Output, OutputType, Block},
    tests::scanner::new_scanner,
    multisigs::scanner::ScannerEvent,
  };

  #[test]
  fn test_dust_constant() {
    struct IsTrue<const V: bool>;
    trait True {}
    impl True for IsTrue<true> {}
    fn check<T: True>() {
      core::hint::black_box(());
    }
    check::<IsTrue<{ Bitcoin::DUST >= bitcoin_serai::wallet::DUST }>>();
  }

  #[test]
  fn test_receive_data_from_input() {
    let docker = spawn_bitcoin();
    docker.run(|ops| async move {
      let btc = bitcoin(&ops).await;

      // generate a multisig address to receive the coins
      let mut keys = frost::tests::key_gen::<_, <Bitcoin as Network>::Curve>(&mut OsRng)
        .remove(&Participant::new(1).unwrap())
        .unwrap();
      <Bitcoin as Network>::tweak_keys(&mut keys);
      let group_key = keys.group_key();
      let serai_btc_address = <Bitcoin as UtxoNetwork>::external_address(&network, group_key);

      // btc key pair to send from
      let private_key = PrivateKey::new(SecretKey::new(&mut rand_core::OsRng), BNetwork::Regtest);
      let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
      let main_addr = BAddress::p2pkh(&public_key, BNetwork::Regtest);

      // get unlocked coins
      let new_block = btc.get_latest_block_number().await.unwrap() + 1;
      btc
        .rpc
        .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([100, main_addr]))
        .await
        .unwrap();

      // create a scanner
      let db = MemDb::new();
      let mut scanner = new_scanner(&btc, &db, group_key, &Arc::new(Mutex::new(true))).await;

      // make a transfer instruction & hash it for script.
      let serai_address = insecure_pair_from_name("alice").public();
      let message = Shorthand::transfer(None, serai_address.into()).encode();
      let mut data = Sha256::engine();
      data.input(&message);

      // make the output script => msg_script(OP_SHA256 PUSH MSG_HASH OP_EQUALVERIFY) + any_script
      let mut script = ScriptBuf::builder()
        .push_opcode(OP_SHA256)
        .push_slice(Sha256::from_engine(data).as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .into_script();
      // append a regular spend script
      for i in main_addr.script_pubkey().instructions() {
        script.push_instruction(i.unwrap());
      }

      // Create the first transaction
      let tx = btc.get_block(new_block).await.unwrap().txdata.swap_remove(0);
      let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint { txid: tx.txid(), vout: 0 },
          script_sig: Script::new().into(),
          sequence: Sequence(u32::MAX),
          witness: Witness::default(),
        }],
        output: vec![TxOut {
          value: tx.output[0].value - BAmount::from_sat(10000),
          script_pubkey: ScriptBuf::new_p2wsh(&script.wscript_hash()),
        }],
      };
      tx.input[0].script_sig = Bitcoin::sign_btc_input_for_p2pkh(&tx, 0, &private_key);
      let initial_output_value = tx.output[0].value;

      // send it
      btc.rpc.send_raw_transaction(&tx).await.unwrap();

      // Chain a transaction spending it with the InInstruction embedded in the input
      let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint { txid: tx.txid(), vout: 0 },
          script_sig: Script::new().into(),
          sequence: Sequence(u32::MAX),
          witness: Witness::new(),
        }],
        output: vec![TxOut {
          value: tx.output[0].value - BAmount::from_sat(10000),
          script_pubkey: serai_btc_address.as_ref().script_pubkey(),
        }],
      };

      // add the witness script
      // This is the standard script with an extra argument of the InInstruction
      let mut sig = SECP256K1
        .sign_ecdsa_low_r(
          &Message::from(
            SighashCache::new(&tx)
              .p2wsh_signature_hash(0, &script, initial_output_value, EcdsaSighashType::All)
              .unwrap()
              .to_raw_hash(),
          ),
          &private_key.inner,
        )
        .serialize_der()
        .to_vec();
      sig.push(1);
      tx.input[0].witness.push(sig);
      tx.input[0].witness.push(public_key.inner.serialize());
      tx.input[0].witness.push(message.clone());
      tx.input[0].witness.push(script);

      // Send it immediately, as Bitcoin allows mempool chaining
      btc.rpc.send_raw_transaction(&tx).await.unwrap();

      // Mine enough confirmations
      let block_number = btc.get_latest_block_number().await.unwrap() + 1;
      for _ in 0 .. <Bitcoin as Network>::CONFIRMATIONS {
        btc.mine_block().await;
      }
      let tx_block = btc.get_block(block_number).await.unwrap();

      // verify that scanner picked up the output
      let outputs =
        match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
          ScannerEvent::Block { is_retirement_block, block, outputs } => {
            scanner.multisig_completed.send(false).unwrap();
            assert!(!is_retirement_block);
            assert_eq!(block, tx_block.id());
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].kind(), OutputType::External);
            outputs
          }
          _ => panic!("unexpectedly got eventuality completion"),
        };

      // verify that the amount and message are correct
      assert_eq!(outputs[0].balance().amount.0, tx.output[0].value.to_sat());
      assert_eq!(outputs[0].data(), message);
    });
  }

  fn spawn_bitcoin() -> DockerTest {
    serai_docker_tests::build("bitcoin".to_string());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::OnError,
      source: LogSource::Both,
    }))
    .set_publish_all_ports(true);

    let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
    test.provide_container(composition);
    test
  }

  async fn bitcoin(ops: &DockerOperations) -> Bitcoin {
    let handle = ops.handle("serai-dev-bitcoin").host_port(8332).unwrap();
    let bitcoin = Bitcoin::new(format!("http://serai:seraidex@{}:{}", handle.0, handle.1)).await;
    bitcoin.fresh_chain().await;
    bitcoin
  }

  test_network!(
    Bitcoin,
    spawn_bitcoin,
    bitcoin,
    bitcoin_key_gen,
    bitcoin_scanner,
    bitcoin_signer,
    bitcoin_wallet,
    bitcoin_addresses,
    bitcoin_no_deadlock_in_multisig_completed,
  );
}

#[cfg(feature = "monero")]
mod monero {
  use super::*;
  use crate::networks::{Network, Monero};

  fn spawn_monero() -> DockerTest {
    serai_docker_tests::build("monero".to_string());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::OnError,
      source: LogSource::Both,
    }))
    .set_publish_all_ports(true);

    let mut test = DockerTest::new();
    test.provide_container(composition);
    test
  }

  async fn monero(ops: &DockerOperations) -> Monero {
    let handle = ops.handle("serai-dev-monero").host_port(18081).unwrap();
    let monero = Monero::new(format!("http://serai:seraidex@{}:{}", handle.0, handle.1)).await;
    while monero.get_latest_block_number().await.unwrap() < 150 {
      monero.mine_block().await;
    }
    monero
  }

  test_network!(
    Monero,
    spawn_monero,
    monero,
    monero_key_gen,
    monero_scanner,
    monero_signer,
    monero_wallet,
    monero_addresses,
    monero_no_deadlock_in_multisig_completed,
  );
}
