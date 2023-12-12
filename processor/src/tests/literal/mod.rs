use dockertest::{
  PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image,
  TestBodySpecification, DockerOperations, DockerTest,
};

#[cfg(feature = "bitcoin")]
mod bitcoin {
  use super::*;
  use crate::{networks::{Network, Bitcoin, Output, OutputType, Block}, tests::scanner::new_scanner, multisigs::scanner::ScannerEvent};
  use sp_application_crypto::Pair;

  use bitcoin_serai::bitcoin::{
    secp256k1::{SECP256K1, SecretKey, Message},
    PrivateKey, PublicKey,
    hashes::{HashEngine, Hash, sha256::Hash as Sha256},
    sighash::{EcdsaSighashType, SighashCache},
    script::{PushBytesBuf, Builder},
    absolute::LockTime,
    Amount as BAmount, Sequence, Script, Witness, OutPoint,
    address::Address as BAddress,
    transaction::{Version, Transaction, TxIn, TxOut},
    Network as BNetwork, ScriptBuf,
    opcodes::all::{OP_SHA256, OP_EQUAL},
  };

  use frost::Participant;
  use rand_core::OsRng;
  use scale::{Encode, Decode};
  use serai_client::{
    in_instructions::primitives::{Shorthand, RefundableInInstruction, InInstruction}, primitives::insecure_pair_from_name,
  };
  use serai_db::MemDb;
  use tokio::time::{timeout, Duration};

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

      // generate a musig address to receive the funds
      let mut keys =
        frost::tests::key_gen::<_, <Bitcoin as Network>::Curve>(&mut OsRng).remove(&Participant::new(1).unwrap()).unwrap();
      <Bitcoin as Network>::tweak_keys(&mut keys);
      let group_key = keys.group_key();
      let address = <Bitcoin as Network>::external_address(group_key);

      // btc key pair to spend from.
      let secret_key = SecretKey::new(&mut rand_core::OsRng);
      let private_key = PrivateKey::new(secret_key, BNetwork::Regtest);
      let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
      let main_addr = BAddress::p2pkh(&public_key, BNetwork::Regtest);

      // make some funds to spent
      let new_block = btc.get_latest_block_number().await.unwrap() + 1;
      btc
        .rpc
        .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr]))
        .await
        .unwrap();

      for _ in 0 .. 100 {
        btc.mine_block().await;
      }

      // create a scanner
      let db = MemDb::new();
      let mut scanner = new_scanner(&btc, &db, group_key).await;

      // make a transfer instruction & hash it.
      let serai_address = insecure_pair_from_name("dadadadada").public();
      let message =
        Shorthand::transfer(None, serai_address.into()).encode();
      let mut data = Sha256::engine();
      data.input(&message);

      // make the output script SHA256 PUSH MSG_HASH OP_EQ
      let script = ScriptBuf::builder()
        .push_opcode(OP_SHA256)
        .push_slice(Sha256::from_engine(data).as_byte_array())
        .push_opcode(OP_EQUAL);

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
        output: vec![
          TxOut {
            value: tx.output[0].value -
              BAmount::from_sat(bitcoin_serai::wallet::DUST) -
              BAmount::from_sat(10000),
            script_pubkey: main_addr.script_pubkey(),
          },
          TxOut {
            value: BAmount::from_sat(bitcoin_serai::wallet::DUST),
            script_pubkey: ScriptBuf::new_p2wsh(&script.as_script().wscript_hash()),
          },
        ],
      };
      // sign the input
      let mut der = SECP256K1
        .sign_ecdsa_low_r(
          &Message::from(
            SighashCache::new(&tx)
              .legacy_signature_hash(0, &main_addr.script_pubkey(), EcdsaSighashType::All.to_u32())
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
        .push_key(&public_key)
        .into_script();

      // send it
      btc.rpc.send_raw_transaction(&tx).await.unwrap();

      // witness script
      let mut witness = Witness::new();
      witness.push(message);
      witness.push(script.as_script());

      // make another tx that spends both outputs
      let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![
          TxIn {
            previous_output: OutPoint { txid: tx.txid(), vout: 0 },
            script_sig: Script::new().into(),
            sequence: Sequence(u32::MAX),
            witness: Witness::default(),
          },
          TxIn {
            previous_output: OutPoint { txid: tx.txid(), vout: 1 },
            script_sig: Script::new().into(),
            sequence: Sequence(u32::MAX),
            witness: witness,
          },
        ],
        output: vec![TxOut {
          value: tx.output[0].value + tx.output[1].value - BAmount::from_sat(10000),
          script_pubkey: address.0.script_pubkey(),
        }],
      };

      // sign the first input
      let mut der = SECP256K1
        .sign_ecdsa_low_r(
          &Message::from(
            SighashCache::new(&tx)
              .legacy_signature_hash(0, &main_addr.script_pubkey(), EcdsaSighashType::All.to_u32())
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
        .push_key(&public_key)
        .into_script();

      // send it
      let block_number = btc.get_latest_block_number().await.unwrap() + 1;
      btc.rpc.send_raw_transaction(&tx).await.unwrap();
      for _ in 0 .. <Bitcoin as Network>::CONFIRMATIONS {
        btc.mine_block().await;
      }
      let tx_block = btc.get_block(block_number).await.unwrap();

      // verify that scanner picked the output up with the right message
      let outputs = match timeout(Duration::from_secs(30), scanner.events.recv()).await.unwrap().unwrap() {
        ScannerEvent::Block { is_retirement_block, block, outputs } => {
          scanner.multisig_completed.send(false).unwrap();
          assert!(!is_retirement_block);
          assert_eq!(block, tx_block.id());
          assert_eq!(outputs.len(), 1);
          assert_eq!(outputs[0].kind(), OutputType::External);
          outputs
        }
        ScannerEvent::Completed(_, _, _, _) => {
          panic!("unexpectedly got eventuality completion");
        }
      };

      let mut data = outputs[0].data();
      assert!(!data.is_empty());
      let Ok(shorthand) = Shorthand::decode(&mut data) else { panic!("can't decode data") };
      let Ok(instruction) = RefundableInInstruction::try_from(shorthand) else { panic!("can't decode ins") };
      match instruction.instruction {
        InInstruction::Transfer(address) => assert_eq!(address, serai_address.into()),
        _ => panic!("wrong ins")
      }
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
