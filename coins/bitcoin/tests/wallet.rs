use std::collections::HashMap;

use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};

use k256::{
  elliptic_curve::{
    group::{ff::Field, Group},
    sec1::{Tag, ToEncodedPoint},
  },
  Scalar, ProjectivePoint,
};
use frost::{
  Participant,
  tests::{THRESHOLD, key_gen, sign_without_caching},
};

use bitcoin_serai::{
  bitcoin::{hashes::Hash as HashTrait, OutPoint, Script, TxOut, Network, Address},
  wallet::{tweak_keys, address, ReceivedOutput, Scanner, SignableTransaction},
  rpc::Rpc,
};

mod runner;
use runner::rpc;

fn is_even(key: ProjectivePoint) -> bool {
  key.to_encoded_point(true).tag() == Tag::CompressedEvenY
}

async fn send(rpc: &Rpc, address: Address) -> usize {
  let res = rpc.get_latest_block_number().await.unwrap() + 1;

  rpc.rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, address])).await.unwrap();

  // Mine until maturity
  rpc
    .rpc_call::<Vec<String>>(
      "generatetoaddress",
      serde_json::json!([100, Address::p2sh(&Script::new(), Network::Regtest).unwrap()]),
    )
    .await
    .unwrap();

  res
}

async fn send_and_get_output(rpc: &Rpc, scanner: &Scanner, key: ProjectivePoint) -> ReceivedOutput {
  let block_number = send(rpc, address(Network::Regtest, key).unwrap()).await;
  let block = rpc.get_block(&rpc.get_block_hash(block_number).await.unwrap()).await.unwrap();

  let mut outputs = scanner.scan_block(&block);
  assert_eq!(outputs, scanner.scan_transaction(&block.txdata[0]));

  assert_eq!(outputs.len(), 1);
  assert_eq!(outputs[0].outpoint(), &OutPoint::new(block.txdata[0].txid(), 0));
  assert_eq!(outputs[0].value(), block.txdata[0].output[0].value);

  assert_eq!(
    ReceivedOutput::read::<&[u8]>(&mut outputs[0].serialize().as_ref()).unwrap(),
    outputs[0]
  );

  outputs.swap_remove(0)
}

#[test]
fn test_tweak_keys() {
  let mut even = false;
  let mut odd = false;

  // Generate keys until we get an even set and an odd set
  while !(even && odd) {
    let mut keys = key_gen(&mut OsRng).drain().next().unwrap().1;
    if is_even(keys.group_key()) {
      // Tweaking should do nothing
      assert_eq!(tweak_keys(&keys).group_key(), keys.group_key());

      even = true;
    } else {
      let tweaked = tweak_keys(&keys).group_key();
      assert_ne!(tweaked, keys.group_key());
      // Tweaking should produce an even key
      assert!(is_even(tweaked));

      // Verify it uses the smallest possible offset
      while keys.group_key().to_encoded_point(true).tag() == Tag::CompressedOddY {
        keys = keys.offset(Scalar::ONE);
      }
      assert_eq!(tweaked, keys.group_key());

      odd = true;
    }
  }
}

async_sequential! {
  async fn test_scanner() {
    // Test Scanners are creatable for even keys.
    for _ in 0 .. 128 {
      let key = ProjectivePoint::random(&mut OsRng);
      assert_eq!(Scanner::new(key).is_some(), is_even(key));
    }

    let mut key = ProjectivePoint::random(&mut OsRng);
    while !is_even(key) {
      key += ProjectivePoint::GENERATOR;
    }

    {
      let mut scanner = Scanner::new(key).unwrap();
      for _ in 0 .. 128 {
        let mut offset = Scalar::random(&mut OsRng);
        let registered = scanner.register_offset(offset).unwrap();
        // Registering this again should return None
        assert!(scanner.register_offset(offset).is_none());

        // We can only register offsets resulting in even keys
        // Make this even
        while !is_even(key + (ProjectivePoint::GENERATOR * offset)) {
          offset += Scalar::ONE;
        }
        // Ensure it matches the registered offset
        assert_eq!(registered, offset);
        // Assert registering this again fails
        assert!(scanner.register_offset(offset).is_none());
      }
    }

    let rpc = rpc().await;
    let mut scanner = Scanner::new(key).unwrap();

    assert_eq!(send_and_get_output(&rpc, &scanner, key).await.offset(), Scalar::ZERO);

    // Register an offset and test receiving to it
    let offset = scanner.register_offset(Scalar::random(&mut OsRng)).unwrap();
    assert_eq!(
      send_and_get_output(&rpc, &scanner, key + (ProjectivePoint::GENERATOR * offset))
        .await
        .offset(),
      offset
    );
  }

  async fn test_send() {
    let mut keys = key_gen(&mut OsRng);
    for (_, keys) in keys.iter_mut() {
      *keys = tweak_keys(keys);
    }
    let key = keys.values().next().unwrap().group_key();

    let rpc = rpc().await;
    let mut scanner = Scanner::new(key).unwrap();

    // Get inputs, one not offset and one offset
    let output = send_and_get_output(&rpc, &scanner, key).await;
    assert_eq!(output.offset(), Scalar::ZERO);

    let offset = scanner.register_offset(Scalar::random(&mut OsRng)).unwrap();
    let offset_key = key + (ProjectivePoint::GENERATOR * offset);
    let offset_output = send_and_get_output(&rpc, &scanner, offset_key).await;
    assert_eq!(offset_output.offset(), offset);

    // Declare payments, change, fee
    let payments = [
      (address(Network::Regtest, key).unwrap(), 1005),
      (address(Network::Regtest, offset_key).unwrap(), 1007)
    ];

    let change_offset = scanner.register_offset(Scalar::random(&mut OsRng)).unwrap();
    let change_key = key + (ProjectivePoint::GENERATOR * change_offset);
    let change_addr = address(Network::Regtest, change_key).unwrap();

    const FEE: u64 = 20;

    // Create and sign the TX
    let tx = SignableTransaction::new(
      vec![output.clone(), offset_output.clone()],
      &payments,
      Some(change_addr.clone()),
      None, // TODO: Test with data
      FEE
    ).unwrap();
    let needed_fee = tx.needed_fee();

    let mut machines = HashMap::new();
    for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
      machines.insert(
        i,
        tx
          .clone()
          .multisig(keys[&i].clone(), RecommendedTranscript::new(b"bitcoin-serai Test Transaction"))
          .unwrap()
      );
    }
    let tx = sign_without_caching(&mut OsRng, machines, &[]);

    assert_eq!(tx.output.len(), 3);

    // Ensure we can scan it
    let outputs = scanner.scan_transaction(&tx);
    for (o, output) in outputs.iter().enumerate() {
      assert_eq!(output.outpoint(), &OutPoint::new(tx.txid(), u32::try_from(o).unwrap()));
      assert_eq!(&ReceivedOutput::read::<&[u8]>(&mut output.serialize().as_ref()).unwrap(), output);
    }

    assert_eq!(outputs[0].offset(), Scalar::ZERO);
    assert_eq!(outputs[1].offset(), offset);
    assert_eq!(outputs[2].offset(), change_offset);

    // Make sure the payments were properly created
    for ((output, scanned), payment) in tx.output.iter().zip(outputs.iter()).zip(payments.iter()) {
      assert_eq!(output, &TxOut { script_pubkey: payment.0.script_pubkey(), value: payment.1 });
      assert_eq!(scanned.value(), payment.1 );
    }

    // Make sure the change is correct
    assert_eq!(needed_fee, u64::try_from(tx.weight()).unwrap() * FEE);
    let input_value = output.value() + offset_output.value();
    let output_value = tx.output.iter().map(|output| output.value).sum::<u64>();
    assert_eq!(input_value - output_value, needed_fee);

    let change_amount =
      input_value - payments.iter().map(|payment| payment.1).sum::<u64>() - needed_fee;
    assert_eq!(
      tx.output[2],
      TxOut { script_pubkey: change_addr.script_pubkey(), value: change_amount },
    );

    // This also tests send_raw_transaction and get_transaction, which the RPC test can't
    // effectively test
    rpc.send_raw_transaction(&tx).await.unwrap();
    let mut hash = tx.txid().as_hash().into_inner();
    hash.reverse();
    assert_eq!(tx, rpc.get_transaction(&hash).await.unwrap());
  }
}

// TODO: Test SignableTransaction error cases
// TODO: Test x, x_only, make_even?
