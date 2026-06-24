use std::collections::HashMap;

use rand_core::{RngCore as _, OsRng};

use k256::{
  elliptic_curve::group::{ff::Field as _, Group as _},
  Scalar, ProjectivePoint,
};
use frost::{
  curve::Secp256k1,
  Participant, ThresholdKeys,
  tests::{THRESHOLD, key_gen, sign_without_caching},
};

use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as _,
    blockdata::opcodes::all::OP_RETURN,
    script::{PushBytesBuf, Instruction, Instructions, Script},
    OutPoint, Amount, TxOut, Transaction, Network, Address,
  },
  wallet::{ReceivedOutput, Scanner, TransactionError, SignableTransaction, address},
  rpc::Rpc,
};

mod runner;
use runner::rpc;

const FEE: u64 = 20;

async fn send_and_get_output(rpc: &Rpc, scanner: &Scanner, key: ProjectivePoint) -> ReceivedOutput {
  let block_number = rpc.get_latest_block_number().await.unwrap() + 1;

  rpc
    .call::<Vec<String>>(
      "generatetoaddress",
      &format!(
        r#"[1, "{}"]"#,
        Address::from_script(&address(key).unwrap(), Network::Regtest).unwrap()
      ),
    )
    .await
    .unwrap();

  // Mine until maturity
  rpc
    .call::<Vec<String>>(
      "generatetoaddress",
      &format!(r#"[100, "{}"]"#, Address::p2sh(Script::new(), Network::Regtest).unwrap()),
    )
    .await
    .unwrap();

  let block = rpc.get_block(&rpc.get_block_hash(block_number).await.unwrap()).await.unwrap();

  let mut outputs = scanner.scan_block(&block);
  assert_eq!(outputs, scanner.scan_transaction(&block.txdata[0]));

  assert_eq!(outputs.len(), 1);
  assert_eq!(outputs[0].outpoint(), &OutPoint::new(block.txdata[0].compute_txid(), 0));
  assert_eq!(outputs[0].value(), block.txdata[0].output[0].value.to_sat());

  assert_eq!(
    ReceivedOutput::read::<&[u8]>(&mut outputs[0].serialize().as_ref()).unwrap(),
    outputs[0]
  );

  outputs.swap_remove(0)
}

fn keys() -> (HashMap<Participant, ThresholdKeys<Secp256k1>>, ProjectivePoint) {
  let keys = key_gen(&mut OsRng);
  let key = keys.values().next().unwrap().group_key();
  (keys, key)
}

fn sign(
  keys: &HashMap<Participant, ThresholdKeys<Secp256k1>>,
  tx: &SignableTransaction,
) -> Transaction {
  let mut machines = HashMap::new();
  for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
    machines.insert(i, tx.clone().multisig(&keys[&i].clone()).unwrap());
  }
  sign_without_caching(&mut OsRng, machines, &[])
}

async_sequential! {
  async fn test_scanner() {
    let key = ProjectivePoint::random(&mut OsRng);
    {
      let mut scanner = Scanner::new(key).unwrap();
      for _ in 0 .. 128 {
        let offset = Scalar::random(&mut OsRng);
        let () = scanner.register_offset(offset).unwrap();
        // Registering this again should return None
        assert!(scanner.register_offset(offset).is_none());
      }
    }

    let rpc = rpc().await;
    let mut scanner = Scanner::new(key).unwrap();

    assert_eq!(send_and_get_output(&rpc, &scanner, key).await.offset(), Scalar::ZERO);

    // Register an offset and test receiving to it
    let offset = Scalar::random(&mut OsRng);
    let () = scanner.register_offset(offset).unwrap();
    assert_eq!(
      send_and_get_output(&rpc, &scanner, key + (ProjectivePoint::GENERATOR * offset))
        .await
        .offset(),
      offset
    );
  }

  async fn test_transaction_errors() {
    let (_, key) = keys();

    let rpc = rpc().await;
    let scanner = Scanner::new(key).unwrap();

    let output = send_and_get_output(&rpc, &scanner, key).await;
    assert_eq!(output.offset(), Scalar::ZERO);

    let inputs = vec![output];
    let addr = || address(key).unwrap();
    let payments = vec![(addr(), 1000)];

    SignableTransaction::new(&inputs, &payments, None, None, FEE).unwrap();

    assert_eq!(
      SignableTransaction::new(&[], &payments, None, None, FEE),
      Err(TransactionError::NoInputs)
    );

    // No change
    SignableTransaction::new(&inputs, &[(addr(), 1000)], None, None, FEE).unwrap();
    // Consolidation TX
    SignableTransaction::new(&inputs, &[], Some(addr()), None, FEE).unwrap();
    // Data
    SignableTransaction::new(&inputs, &[], None, Some(vec![]), FEE).unwrap();
    // No outputs
    assert_eq!(
      SignableTransaction::new(&inputs, &[], None, None, FEE),
      Err(TransactionError::NoOutputs),
    );

    assert_eq!(
      SignableTransaction::new(&inputs, &[(addr(), 1)], None, None, FEE),
      Err(TransactionError::DustPayment),
    );

    SignableTransaction::new(&inputs, &payments, None, Some(vec![0; 80]), FEE).unwrap();
    assert_eq!(
      SignableTransaction::new(&inputs, &payments, None, Some(vec![0; 81]), FEE),
      Err(TransactionError::TooMuchData),
    );

    assert_eq!(
      SignableTransaction::new(&inputs, &[], Some(addr()), None, 0),
      Err(TransactionError::TooLowFee),
    );

    assert!(matches!(
      SignableTransaction::new(&inputs, &[(addr(), inputs[0].value() * 2)], None, None, FEE),
      Err(TransactionError::NotEnoughFunds { .. }),
    ));

    assert_eq!(
      SignableTransaction::new(&inputs, &vec![(addr(), 1000); 10000], None, None, FEE),
      Err(TransactionError::TooLargeTransaction),
    );
  }

  async fn test_send() {
    let (keys, key) = keys();

    let rpc = rpc().await;
    let mut scanner = Scanner::new(key).unwrap();

    // Get inputs, one not offset and one offset
    let output = send_and_get_output(&rpc, &scanner, key).await;
    assert_eq!(output.offset(), Scalar::ZERO);

    let offset = Scalar::random(&mut OsRng);
    let () = scanner.register_offset(offset).unwrap();
    let offset_key = key + (ProjectivePoint::GENERATOR * offset);
    let offset_output = send_and_get_output(&rpc, &scanner, offset_key).await;
    assert_eq!(offset_output.offset(), offset);

    // Declare payments, change, fee
    let payments = [
      (address(key).unwrap(), 1005),
      (address(offset_key).unwrap(), 1007)
    ];

    let change_offset = Scalar::random(&mut OsRng);
    let () = scanner.register_offset(change_offset).unwrap();
    let change_key = key + (ProjectivePoint::GENERATOR * change_offset);
    let change_addr = address(change_key).unwrap();

    // Create and sign the TX
    let tx = SignableTransaction::new(
      &[output.clone(), offset_output.clone()],
      &payments,
      Some(change_addr.clone()),
      None,
      FEE
    ).unwrap();
    let needed_fee = tx.needed_fee();
    let expected_id = tx.txid();
    let tx = sign(&keys, &tx);

    assert_eq!(tx.output.len(), 3);

    // Ensure we can scan it
    let outputs = scanner.scan_transaction(&tx);
    for (o, output) in outputs.iter().enumerate() {
      assert_eq!(output.outpoint(), &OutPoint::new(tx.compute_txid(), u32::try_from(o).unwrap()));
      assert_eq!(&ReceivedOutput::read::<&[u8]>(&mut output.serialize().as_ref()).unwrap(), output);
    }

    assert_eq!(outputs[0].offset(), Scalar::ZERO);
    assert_eq!(outputs[1].offset(), offset);
    assert_eq!(outputs[2].offset(), change_offset);

    // Make sure the payments were properly created
    for ((output, scanned), payment) in tx.output.iter().zip(outputs.iter()).zip(payments.iter()) {
      assert_eq!(
        output,
        &TxOut { script_pubkey: payment.0.clone(), value: Amount::from_sat(payment.1) },
      );
      assert_eq!(scanned.value(), payment.1 );
    }

    // Make sure the change is correct
    assert_eq!(needed_fee, u64::try_from(tx.vsize()).unwrap() * FEE);
    let input_value = output.value() + offset_output.value();
    let output_value = tx.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
    assert_eq!(input_value - output_value, needed_fee);

    let change_amount =
      input_value - payments.iter().map(|payment| payment.1).sum::<u64>() - needed_fee;
    assert_eq!(
      tx.output[2],
      TxOut { script_pubkey: change_addr, value: Amount::from_sat(change_amount) },
    );

    // This also tests `send_raw_transaction`, which the RPC test can't effectively test
    rpc.send_raw_transaction(&tx).await.unwrap();
    let mut hash = *tx.compute_txid().as_raw_hash().as_byte_array();
    hash.reverse();
    assert_eq!(expected_id, hash);
  }

  async fn test_data() {
    let (keys, key) = keys();

    let rpc = rpc().await;
    let scanner = Scanner::new(key).unwrap();

    let output = send_and_get_output(&rpc, &scanner, key).await;
    assert_eq!(output.offset(), Scalar::ZERO);

    let data_len = 60 + usize::try_from(OsRng.next_u64() % 21).unwrap();
    let mut data = vec![0; data_len];
    OsRng.fill_bytes(&mut data);

    let tx = sign(
      &keys,
      &SignableTransaction::new(
        &[output],
        &[],
        Some(address(key).unwrap()),
        Some(data.clone()),
        FEE
      ).unwrap()
    );

    assert!(tx.output[0].script_pubkey.is_op_return());
    let check = |mut instructions: Instructions| {
      assert_eq!(instructions.next().unwrap().unwrap(), Instruction::Op(OP_RETURN));
      assert_eq!(
        instructions.next().unwrap().unwrap(),
        Instruction::PushBytes(&PushBytesBuf::try_from(data.clone()).unwrap()),
      );
      assert!(instructions.next().is_none());
    };
    check(tx.output[0].script_pubkey.instructions());
    check(tx.output[0].script_pubkey.instructions_minimal());
  }
}
