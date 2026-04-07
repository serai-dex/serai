use core::marker::PhantomData;

use schnorr::SchnorrSignature;

use serai_db::{Db, DbTxn, MemDb};
use serai_primitives::test_helpers::{random_block_hash, random_block_number, random_vec_of_len};
use serai_cosign_types::CosignIntent;
use tributary_sdk::{
  Block, BlockHeader, Transaction as TributaryTransaction, Evidence, tendermint::tx::TendermintTx,
};

use crate::{
  CosignIntents, DkgConfirmationMessages, ProcessorMessages, RecognizedTopics, ScanBlock,
  SubstrateBlockPlans, db::CosignIntents as DbCosignIntents,
};

use super::*;

fn new_scan_block<'a, TDT: DbTxn>(
  txn: &'a mut TDT,
  set_info: &'a NewSetInformation,
  validators: &'a [SeraiAddress],
  total_weight: u16,
  validator_weights: &'a HashMap<SeraiAddress, u16>,
) -> ScanBlock<'a, MemDb, TDT, MockP2p> {
  ScanBlock {
    _td: PhantomData,
    _p2p: PhantomData,
    tributary_txn: txn,
    set: set_info,
    validators,
    total_weight,
    validator_weights,
  }
}

/// Create a Signed with the given signer key and a random signature.
fn new_signed(signer: RistrettoPoint) -> Signed {
  Signed {
    signer,
    signature: SchnorrSignature {
      R: Ristretto::generator() * <Ristretto as WrappedGroup>::F::random(&mut OsRng),
      s: <Ristretto as WrappedGroup>::F::random(&mut OsRng),
    },
  }
}

#[test]
fn potentially_start_cosign() {
  let (_, validator_data, validators, weights, total_weight) =
    setup_test_validators_and_weights_with_keys();
  let set_info = new_test_set_info(&validator_data);
  let set = set_info.set;

  // Already actively cosigning: should not replace the actively cosigning block
  {
    let mut db = MemDb::new();
    let initial_block_hash = random_block_hash(&mut OsRng);

    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, initial_block_hash, OsRng.next_u64());
      let new_block_hash = random_block_hash(&mut OsRng);
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, new_block_hash);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    // Did not replace initial_block_hash for new_block_hash
    assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(initial_block_hash));
  }

  // No TributaryDb::latest_substrate_block_to_cosign block: no-op
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }
    assert!(TributaryDb::actively_cosigning(&mut txn, set).is_none());
  }

  // Already cosigned: no-op
  {
    let mut db = MemDb::new();
    let initial_block_hash = random_block_hash(&mut OsRng);

    {
      let mut txn = db.txn();
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, initial_block_hash);
      TributaryDb::mark_cosigned(&mut txn, set, initial_block_hash);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    assert!(TributaryDb::actively_cosigning(&mut txn, set).is_none());
  }

  // Ready to cosign: starts cosigning and sends processor message
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

    let intent = CosignIntent {
      global_session,
      block_number: random_block_number(&mut OsRng),
      block_hash,
      notable: false,
    };

    {
      let mut txn = db.txn();
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, block_hash);
      CosignIntents::provide(&mut txn, set, &intent);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    assert_cosigning_invariants(&mut txn, set, block_hash, intent.block_number);
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  // Panics when stored intent's block_hash differs from latest_substrate_block_to_cosign
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

    {
      let mut txn = db.txn();
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, block_hash);

      let new_block_hash = random_block_hash(&mut OsRng);
      DbCosignIntents::set(
        &mut txn,
        set,
        // Store the intent under block_hash (the key `CosignIntents::take` will look up)
        block_hash,
        &CosignIntent {
          global_session,
          block_number: random_block_number(&mut OsRng),
          // but the intent's block_hash field is a new_block_hash
          block_hash: new_block_hash,
          notable: false,
        },
      );
      txn.commit();
    }

    let result = std::panic::catch_unwind(move || {
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    });
    let err = result.expect_err("should panic on differing intent block hash");
    let msg = err.downcast_ref::<String>().expect("panic payload should be a String");
    assert!(
      msg.contains("provided CosignIntent wasn't saved by its block hash"),
      "unexpected panic message: {msg}"
    );
  }
}

#[test]
fn accumulate_dkg_confirmation() {
  let (_, validator_data, validators, weights, total_weight) =
    setup_test_validators_and_weights_with_keys();
  let (v1, v2, v3) = (validators[0], validators[1], validators[2]);
  let set_info = new_test_set_info(&validator_data);
  let set = set_info.set;
  let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };

  // Panics if the topic isn't DkgConfirmation
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.accumulate_dkg_confirmation(
        random_block_number(&mut OsRng),
        Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
        &random_vec_of_len(&mut OsRng, 4),
        validators[0],
      );
    }));

    assert!(result.is_err(), "should panic when called with a non-DkgConfirmation topic");
  }

  // Threshold crossed: third accumulation returns SignId + correctly mapped data
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = random_block_number(&mut OsRng);

    {
      let data1 = random_vec_of_len(&mut OsRng, 4);
      let data2 = random_vec_of_len(&mut OsRng, 4);
      let data3 = random_vec_of_len(&mut OsRng, 4);

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data1, v1).is_none());
      assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data2, v2).is_none());
      let result = scan_block.accumulate_dkg_confirmation(block_number, topic, &data3, v3);

      let (sign_id, data_set) = result.expect("third accumulation should cross threshold");

      assert_eq!(
        sign_id,
        topic.dkg_confirmation_sign_id(set).unwrap(),
        "SignId must match what dkg_confirmation_sign_id produces"
      );

      // Participants are 1-indexed by list position, not by weight-based indices
      assert_eq!(data_set.len(), 3);
      assert_eq!(data_set[&Participant::new(1).unwrap()], data1);
      assert_eq!(data_set[&Participant::new(2).unwrap()], data2);
      assert_eq!(data_set[&Participant::new(3).unwrap()], data3);
    }

    // Past threshold: further accumulations from a new validator are no-ops
    {
      // Add a 4th validator so we have a fresh signer after threshold is crossed.
      // total_weight=4, required_participation = 3, so v0+v1+v2 cross threshold.
      let v4 = random_serai_address(&mut OsRng);
      let mut validator_data_4 = validator_data.clone();
      validator_data_4.push((v4, 1));
      let validators_4: Vec<SeraiAddress> = validator_data_4.iter().map(|(a, _)| *a).collect();
      let mut weights_4 = weights.clone();
      weights_4.insert(v4, 1);
      let set_info_4 = new_test_set_info(&validator_data_4);

      let data4 = random_vec_of_len(&mut OsRng, 4);

      {
        let mut scan_block = new_scan_block(&mut txn, &set_info_4, &validators_4, 4, &weights_4);
        assert!(
          scan_block.accumulate_dkg_confirmation(block_number, topic, &data4, v4).is_none(),
          "accumulation after threshold should be a NOP"
        );
      }
    }
  }
}

mod handle_application_tx {
  use super::*;

  #[test]
  fn dont_handle_signed_kind_from_fatally_slashed() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    let mut db = MemDb::new();

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, default_signer, "test reason");
      txn.commit();
    }

    for tx in all_signed_transactions_and_attempts(Signed::default()) {
      let mut txn = db.txn();

      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_application_tx(random_block_number(&mut OsRng), tx.clone());
      }

      assert!(
        ProcessorMessages::try_recv(&mut txn, set).is_none(),
        "fatally slashed signer should be ignored for {tx:?}"
      );
    }
  }

  #[test]
  fn remove_participant() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    // The signer is fatally slashed if the participant voted to be removed is nonexistent
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      let nonexistent = random_serai_address(&mut OsRng);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::RemoveParticipant { participant: nonexistent, signed: Signed::default() },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, default_signer));
    }

    // Valid RemoveParticipant accumulates weight and eventually crosses threshold
    {
      let (keys_addrs, validator_data, validators, weights, _) = setup_n_validators_with_keys(3);
      let set_info = new_test_set_info(&validator_data);
      let (key0, addr0) = keys_addrs[0];
      let (key1, _) = keys_addrs[1];
      let (key2, _) = keys_addrs[2];

      let target = addr0;
      let block_number = random_block_number(&mut OsRng);

      let mut db = MemDb::new();
      let mut txn = db.txn();

      // First vote: topic is recognized, target not yet slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key0) },
        );
      }
      assert!(
        RecognizedTopics::recognized(
          &mut txn,
          set,
          Topic::RemoveParticipant { participant: target }
        ),
        "RemoveParticipant topic should be recognized after handling the tx"
      );
      assert!(
        !TributaryDb::is_fatally_slashed(&mut txn, set, target),
        "target should not be fatally slashed after one vote"
      );

      // Threshold crossed, target gets fatally slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key1) },
        );
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key2) },
        );
      }
      assert!(
        TributaryDb::is_fatally_slashed(&mut txn, set, target),
        "target should be fatally slashed after threshold is crossed"
      );
    }
  }

  #[test]
  fn dkg_participation() {
    let mut db = MemDb::new();

    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (signer_key, _) = keys_addrs[0];

    let mut txn = db.txn();

    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::DkgParticipation {
          participation: vec![1, 2, 3],
          signed: new_signed(signer_key),
        },
      );
    }

    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn dkg_confirmation_preprocess() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, key1, key2) = (keys_addrs[0].0, keys_addrs[1].0, keys_addrs[2].0);

    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = random_block_number(&mut OsRng);

    // Below threshold: no DkgConfirmationMessages sent
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        block_number,
        Transaction::DkgConfirmationPreprocess {
          attempt: 0,
          preprocess: random_bytes_64(&mut OsRng),
          signed: new_signed(key0),
        },
      );
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_none());

    // Threshold crossed: sends DkgConfirmationMessages (Preprocesses)
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key1, key2] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess: random_bytes_64(&mut OsRng),
            signed: new_signed(key),
          },
        );
      }
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn dkg_confirmation_share() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, addr0) = keys_addrs[0];
    let (key1, key2) = (keys_addrs[1].0, keys_addrs[2].0);

    // Share without preceding preprocess participation -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::DkgConfirmationShare {
          attempt: 0,
          share: random_bytes_32(&mut OsRng),
          signed: new_signed(key0),
        },
      );

      assert!(
        TributaryDb::is_fatally_slashed(&mut txn, set, addr0),
        "share without preceding preprocess should fatally slash"
      );
    }

    // Full preprocess->share flow
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = random_block_number(&mut OsRng);

    // All 3 validators submit preprocesses (threshold crossed -> DkgConfirmationMessages sent)
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key0, key1, key2] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess: random_bytes_64(&mut OsRng),
            signed: new_signed(key),
          },
        );
      }
    }
    assert!(
      DkgConfirmationMessages::try_recv(&mut txn, set).is_some(),
      "preprocesses crossing threshold should produce DkgConfirmationMessages"
    );

    // Below threshold: no DkgConfirmationMessages sent
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        block_number,
        Transaction::DkgConfirmationShare {
          attempt: 0,
          share: random_bytes_32(&mut OsRng),
          signed: new_signed(key0),
        },
      );
    }
    assert!(
      DkgConfirmationMessages::try_recv(&mut txn, set).is_none(),
      "single share should not produce DkgConfirmationMessages"
    );

    // Threshold crossed: sends DkgConfirmationMessages (Shares)
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key1, key2] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationShare {
            attempt: 0,
            share: random_bytes_32(&mut OsRng),
            signed: new_signed(key),
          },
        );
      }
    }
    assert!(
      DkgConfirmationMessages::try_recv(&mut txn, set).is_some(),
      "shares crossing threshold should produce DkgConfirmationMessages"
    );
  }

  #[test]
  fn cosign() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);

    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

    let intent = CosignIntent {
      global_session,
      block_number: random_block_number(&mut OsRng),
      block_hash,
      notable: false,
    };

    // Sets LatestSubstrateBlockToCosign and starts cosigning
    {
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        CosignIntents::provide(&mut txn, set, &intent);
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::Cosign { substrate_block_hash: block_hash },
      );

      assert_eq!(TributaryDb::latest_substrate_block_to_cosign(&mut txn, set), Some(block_hash));
      assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(block_hash));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }

    // When already cosigning, updates LatestSubstrateBlockToCosign but doesn't replace active
    {
      let mut db = MemDb::new();
      let first_hash = random_block_hash(&mut OsRng);
      let second_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, first_hash, OsRng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::Cosign { substrate_block_hash: second_hash },
      );

      assert_eq!(TributaryDb::latest_substrate_block_to_cosign(&mut txn, set), Some(second_hash));
      assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(first_hash));
    }
  }

  #[test]
  fn cosigned() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);

    // Marks block as cosigned
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let block_hash = random_block_hash(&mut OsRng);

      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_application_tx(
          random_block_number(&mut OsRng),
          Transaction::Cosigned { substrate_block_hash: block_hash },
        );
      }

      assert!(TributaryDb::cosigned(&mut txn, set, block_hash));
    }

    // Finishes active cosign when matching block
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, block_hash, OsRng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(block_hash));

      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_application_tx(
          random_block_number(&mut OsRng),
          Transaction::Cosigned { substrate_block_hash: block_hash },
        );
      }
      assert!(TributaryDb::actively_cosigning(&mut txn, set).is_none());
    }

    // Does not finish active cosign when block doesn't match
    {
      let mut db = MemDb::new();
      let active_hash = random_block_hash(&mut OsRng);
      let other_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, active_hash, OsRng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_application_tx(
          random_block_number(&mut OsRng),
          Transaction::Cosigned { substrate_block_hash: other_hash },
        );
      }
      assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(active_hash));
      assert!(TributaryDb::cosigned(&mut txn, set, other_hash));
    }
  }

  #[test]
  fn substrate_block() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let plans = vec![random_bytes_32(&mut OsRng), random_bytes_32(&mut OsRng)];

    {
      let mut txn = db.txn();
      SubstrateBlockPlans::set(&mut txn, set, block_hash, &plans);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::SubstrateBlock { hash: block_hash },
      );
    }

    for plan in &plans {
      let topic = expected_initially_recognized_sign_topic(VariantSignId::Transaction(*plan));
      assert!(RecognizedTopics::recognized(&mut txn, set, topic));
    }
  }

  #[test]
  fn batch() {
    let set = default_test_validator_set();
    let (_, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let batch_hash = random_bytes_32(&mut OsRng);

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::Batch { hash: batch_hash },
      );
    }

    let topic = expected_initially_recognized_sign_topic(VariantSignId::Batch(batch_hash));
    assert!(RecognizedTopics::recognized(&mut txn, set, topic));
  }

  mod slash_report {
    use super::*;

    #[test]
    fn odd_slash_points() {
      let set = default_test_validator_set();
      let (keys_addrs, validator_data, validators, weights, total_weight) =
        setup_test_validators_and_weights_with_keys();
      let set_info = new_test_set_info(&validator_data);
      let (key0, addr0) = keys_addrs[0];

      // Wrong length: 3 validators but mismatched slash points -> fatal slash
      for wrong_points in [
        vec![],
        // 1 or 2
        vec![0; 1 + (OsRng.next_u32() as usize % 2)],
        // 4..100
        vec![0; 4 + (OsRng.next_u32() as usize % 97)],
      ] {
        let mut db = MemDb::new();
        let mut txn = db.txn();

        {
          let mut scan_block =
            new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
          scan_block.handle_application_tx(
            random_block_number(&mut OsRng),
            Transaction::SlashReport {
              slash_points: wrong_points.clone(),
              signed: new_signed(key0),
            },
          );
        }
        assert!(
          TributaryDb::is_fatally_slashed(&mut txn, set, addr0),
          "expected fatal slash for slash_points length {}, but wasn't slashed",
          wrong_points.len()
        );
      }

      let (keys_addrs, validator_data, validators, weights, total_weight) =
        setup_n_validators_with_keys(4);
      let set_info = new_test_set_info(&validator_data);

      let mut db = MemDb::new();
      let mut txn = db.txn();

      // Valid length: accumulates weight
      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_application_tx(
          random_block_number(&mut OsRng),
          Transaction::SlashReport {
            slash_points: vec![0, 0, 0, 100],
            signed: new_signed(keys_addrs[0].0),
          },
        );
      }
      assert!(RecognizedTopics::recognized(&mut txn, set, Topic::SlashReport));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_none());

      // Threshold crossed: computes median slash report and sends SignSlashReport message
      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 4, &weights);
        for key in [keys_addrs[1].0, keys_addrs[2].0] {
          scan_block.handle_application_tx(
            random_block_number(&mut OsRng),
            // Each reporter says: first 3 validators have 0 points, 4th has 100
            Transaction::SlashReport { slash_points: vec![0, 0, 0, 100], signed: new_signed(key) },
          );
        }
      }
      let sign_topic = expected_initially_recognized_sign_topic(VariantSignId::SlashReport);
      assert!(RecognizedTopics::recognized(&mut txn, set, sign_topic,));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }

    /// Exercises the even-length median branch (`(this_validator.len() / 2) - 1`) in
    /// the SlashReport handler by using 5 validators where `required_participation = 4` (even).
    #[test]
    fn even_slash_points() {
      let set = default_test_validator_set();

      // 5 validators of weight 1 -> required_participation = 5*2/3+1 = 4
      let (keys_addrs, validator_data, validators, weights, _) = setup_n_validators_with_keys(5);
      let set_info = new_test_set_info(&validator_data);

      let mut db = MemDb::new();
      let mut txn = db.txn();

      // 4 reporters submit different opinions about validator 4 (index 4).
      // Reports (for all 5 validator positions):
      //   reporter 0: [0, 0, 0, 0, 10]
      //   reporter 1: [0, 0, 0, 0, 20]
      //   reporter 2: [0, 0, 0, 0, 30]
      //   reporter 3: [0, 0, 0, 0, 40]
      //
      // Sorted values for validator 4: [10, 20, 30, 40] (len=4, even)
      // Even median index: (4 / 2) - 1 = 1 -> median = 20
      //
      // f = (5-1)/3 = 1, amortization baseline = sorted_medians[5-1-1] = sorted_medians[3] = 0
      // amortized: [0, 0, 0, 0, 20]. Non-zero entries: [20] for validator 4.
      let slash_reports = vec![
        vec![0u32, 0, 0, 0, 10],
        vec![0, 0, 0, 0, 20],
        vec![0, 0, 0, 0, 30],
        vec![0, 0, 0, 0, 40],
      ];

      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 5, &weights);
        for (i, report) in slash_reports.iter().enumerate() {
          let (key, _) = keys_addrs[i];
          scan_block.handle_application_tx(
            random_block_number(&mut OsRng),
            Transaction::SlashReport { slash_points: report.clone(), signed: new_signed(key) },
          );
        }
      }

      // Threshold was crossed with 4 reporters (even) -> even median branch exercised.
      // Verify the signing topic was recognized and a message was sent.
      let sign_topic = expected_initially_recognized_sign_topic(VariantSignId::SlashReport);
      assert!(
        RecognizedTopics::recognized(&mut txn, set, sign_topic),
        "SlashReport sign topic should be recognized"
      );

      let msg = ProcessorMessages::try_recv(&mut txn, set);
      assert!(msg.is_some(), "expected SignSlashReport processor message");
    }

    mod fuzz_slash_report {
      use super::*;

      /// Independently compute the expected slash report that `handle_application_tx` should
      /// produce when `DataSet::Participating` is reached, mirroring the production logic.
      ///
      /// Returns `None` if `f == 0` (the slash report would be empty and nothing is sent).
      fn expected_slash_report(num_validators: usize, reports: &[Vec<u32>]) -> Option<Vec<u32>> {
        let f = (num_validators - 1) / 3;
        if f == 0 {
          return None;
        }

        // Compute the median for each validator position across all reporters
        let mut medians = Vec::with_capacity(num_validators);
        for i in 0 .. num_validators {
          let mut values: Vec<u32> = reports.iter().map(|r| r[i]).collect();
          values.sort_unstable();
          let median_index =
            if (values.len() % 2) == 1 { values.len() / 2 } else { (values.len() / 2) - 1 };
          medians.push(values[median_index]);
        }

        // Find worst validator in the supermajority and amortize
        let mut sorted = medians.clone();
        sorted.sort_unstable();
        let amortization = sorted[num_validators - f - 1];

        let amortized: Vec<u32> = medians.iter().map(|p| p.saturating_sub(amortization)).collect();

        // Filter to non-zero entries only
        let result: Vec<u32> = amortized.into_iter().filter(|&p| p > 0).collect();
        Some(result)
      }

      /// Generate a random slash point value drawn from a weighted distribution:
      /// ~30% zero, ~20% small (1..100), ~20% medium (100..10_000), ~30% fatal (u32::MAX).
      /// The high fatal weight ensures the median across reporters frequently lands on u32::MAX,
      /// exercising the Slash::Fatal branch after amortization.
      fn random_slash_point(rng: &mut impl Rng) -> u32 {
        match rng.gen_range(0u8 .. 10) {
          0 ..= 2 => 0,
          3 ..= 4 => rng.gen_range(1 .. 100),
          5 ..= 6 => rng.gen_range(100 .. 10_000),
          _ => u32::MAX,
        }
      }

      /// Generate `count` slash report vectors, each of length `num_validators`.
      fn random_slash_reports(
        rng: &mut impl Rng,
        num_validators: usize,
        count: usize,
      ) -> Vec<Vec<u32>> {
        (0 .. count)
          .map(|_| (0 .. num_validators).map(|_| random_slash_point(rng)).collect())
          .collect()
      }

      /// Fuzz the SlashReport -> Participating path with randomized slash point vectors.
      ///
      /// Uses 4 validators (f=1) so the threshold-crossing path is reachable.
      /// All 4 submit identical reports so the median equals the input.
      #[test]
      fn fuzz_slash_report_participating_4_validators() {
        for _ in 0 .. 200 {
          let set = default_test_validator_set();

          let (keys_addrs, validator_data, validators, weights, total_weight) =
            setup_n_validators_with_keys(4);
          let set_info = new_test_set_info(&validator_data);

          let slash_points: Vec<u32> = (0 .. 4).map(|_| random_slash_point(&mut OsRng)).collect();

          let mut db = MemDb::new();
          let mut txn = db.txn();

          // All 4 validators submit the same slash_points
          // required_participation = 4*2/3+1 = 3, so 3 cross the threshold.
          // The 4th submission is a NOP (past threshold).
          let reports: Vec<Vec<u32>> = vec![slash_points.clone(); 3];
          let expected = expected_slash_report(4, &reports);

          {
            let mut scan_block =
              new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
            for (key, _) in &keys_addrs {
              scan_block.handle_application_tx(
                1,
                Transaction::SlashReport {
                  slash_points: slash_points.clone(),
                  signed: new_signed(*key),
                },
              );
            }
          }

          match expected {
            Some(result) if !result.is_empty() => {
              assert!(
                ProcessorMessages::try_recv(&mut txn, set).is_some(),
                "expected ProcessorMessage for non-empty slash report {result:?}",
              );
            }
            _ => {
              // Empty or f==0 -> slash report is empty, nothing to sign.
              // The handler always sends a message when Participating is reached
              // (assert passes with len=0 <= f=1).
              assert!(
                ProcessorMessages::try_recv(&mut txn, set).is_some(),
                "expected ProcessorMessage even for empty slash report",
              );
            }
          }

          let sign_topic = expected_initially_recognized_sign_topic(VariantSignId::SlashReport);
          assert!(
            RecognizedTopics::recognized(&mut txn, set, sign_topic),
            "SlashReport sign topic should be recognized",
          );
        }
      }

      /// Fuzz with varying reporter opinions (not all identical).
      /// Uses 7 validators (f=2) for a richer median calculation.
      #[test]
      fn fuzz_slash_report_diverse_opinions_7_validators() {
        for _ in 0 .. 200 {
          let set = default_test_validator_set();

          // 7 validators, f = (7-1)/3 = 2
          let (keys_addrs, validator_data, validators, weights, _) =
            setup_n_validators_with_keys(7);
          let set_info = new_test_set_info(&validator_data);

          // required_participation = 7*2/3+1 = 5
          // We have 5 reports from 5 different validators to cross the threshold
          let reports = random_slash_reports(&mut OsRng, 7, 5);
          let expected = expected_slash_report(7, &reports[.. 5]);

          let mut db = MemDb::new();
          let mut txn = db.txn();

          {
            let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 7, &weights);
            for (i, report) in reports.iter().enumerate() {
              let (key, _) = keys_addrs[i];
              scan_block.handle_application_tx(
                1,
                Transaction::SlashReport { slash_points: report.clone(), signed: new_signed(key) },
              );
            }
          }

          match expected {
            Some(result) => {
              assert!(result.len() <= 2, "slash report len {} should be <= f=2", result.len());
            }
            None => {
              unreachable!();
            }
          }

          assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
          let sign_topic = expected_initially_recognized_sign_topic(VariantSignId::SlashReport);
          assert!(RecognizedTopics::recognized(&mut txn, set, sign_topic));
        }
      }

      /// Fuzz the wrong-length path: slash_points.len() != validators.len() -> fatal slash
      #[test]
      fn fuzz_slash_report_wrong_length() {
        for _ in 0 .. 200 {
          let num_validators = OsRng.gen_range(4usize .. 10);
          let mut wrong_len = OsRng.gen_range(1usize .. 20);
          if wrong_len == num_validators {
            // Shift to guarantee mismatch
            wrong_len = if wrong_len == 1 { 2 } else { wrong_len - 1 };
          }

          let set = default_test_validator_set();

          let (keys_addrs, validator_data, validators, weights, total_weight) =
            setup_n_validators_with_keys(num_validators);
          let set_info = new_test_set_info(&validator_data);

          let mut db = MemDb::new();
          let mut txn = db.txn();

          let (signer_key, signer_addr) = keys_addrs[0];

          {
            let mut scan_block =
              new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
            scan_block.handle_application_tx(
              1,
              Transaction::SlashReport {
                slash_points: vec![0; wrong_len],
                signed: new_signed(signer_key),
              },
            );
          }

          assert!(
            TributaryDb::is_fatally_slashed(&mut txn, set, signer_addr),
            "signer should be fatally slashed for wrong-length slash report",
          );
          assert!(
            ProcessorMessages::try_recv(&mut txn, set).is_none(),
            "no message should be sent for wrong-length slash report",
          );
        }
      }
    }
  }

  #[test]
  fn sign() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, addr0) = keys_addrs[0];
    let (key1, key2) = (keys_addrs[1].0, keys_addrs[2].0);

    let sign_id = VariantSignId::Transaction(random_bytes_32(&mut OsRng));
    let topic = expected_initially_recognized_sign_topic(sign_id);

    // Wrong data length: signer has weight 1 but submits 2 entries -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::Sign {
          id: sign_id,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
          data: vec![vec![1], vec![2]],
          signed: new_signed(key0),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }

    // Valid data: threshold crossing sends ProcessorMessage
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        for key in [key0, key1, key2] {
          scan_block.handle_application_tx(
            random_block_number(&mut OsRng),
            Transaction::Sign {
              id: sign_id,
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
              data: vec![vec![1, 2, 3]],
              signed: new_signed(key),
            },
          );
        }
      }

      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  /// Exercises the Sign Share -> Participating path (line 559: `Shares { id, shares: data_set }`).
  /// Requires first accumulating preprocesses to threshold (which recognizes the Share topic
  /// and stores preceding data), then accumulating shares to threshold.
  #[test]
  fn sign_share_sends_shares_message() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, key1, key2) = (keys_addrs[0].0, keys_addrs[1].0, keys_addrs[2].0);

    let sign_id = VariantSignId::Transaction(random_bytes_32(&mut OsRng));
    let preprocess_topic = expected_initially_recognized_sign_topic(sign_id);
    let share_topic = Topic::Sign { id: sign_id, attempt: 0, round: SigningProtocolRound::Share };

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // Recognize the Preprocess topic
    TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);

    // Step 1: All validators submit preprocesses, crossing threshold.
    // This auto-recognizes the Share topic (succeeding_topic) and stores preprocess data.
    {
      let block_number = random_block_number(&mut OsRng);
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key0, key1, key2] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Preprocess,
            data: vec![vec![1, 2, 3]],
            signed: new_signed(key),
          },
        );
      }
    }

    // Drain the Preprocesses message from step 1
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());

    // Share topic should now be recognized
    assert!(RecognizedTopics::recognized(&mut txn, set, share_topic));

    // Step 2: All validators submit shares, crossing threshold -> sends Shares message.
    {
      let block_number = random_block_number(&mut OsRng);
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key0, key1, key2] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Share,
            data: vec![vec![4, 5, 6]],
            signed: new_signed(key),
          },
        );
      }
    }

    // The Shares message should have been sent
    let msg = ProcessorMessages::try_recv(&mut txn, set);
    assert!(msg.is_some(), "expected Shares processor message");

    // No validators should be slashed
    for v in &validators {
      assert!(!TributaryDb::is_fatally_slashed(&mut txn, set, *v));
    }
  }
}

mod handle_block {
  use super::*;

  #[test]
  fn handles_all_transaction_types() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_n_validators_with_keys(3);
    let set_info = new_test_set_info(&validator_data);
    let addr0 = validator_data[0].0;
    let signed = new_signed(keys_addrs[0].0);

    // Empty block only calls start of block
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let block = Block {
        header: BlockHeader {
          parent: random_bytes_32(&mut OsRng),
          transactions: random_bytes_32(&mut OsRng),
        },
        transactions: vec![],
      };

      {
        let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_block(random_block_number(&mut OsRng), block);
      }
      assert_no_pending_messages(&mut txn, set);
    }

    // Each application transaction type passes through handle_block.
    // Signed transactions use a real validator key so participant_indexes lookups succeed.
    // Cosign and SubstrateBlock need external state populated before they can run.
    for tx in all_signed_transactions_and_attempts(signed) {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      let block_txs = vec![TributaryTransaction::Application(tx)];
      let block = Block {
        header: BlockHeader {
          parent: random_bytes_32(&mut OsRng),
          transactions: random_bytes_32(&mut OsRng),
        },
        transactions: block_txs.clone(),
      };

      {
        let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_block(random_block_number(&mut OsRng), block);
      }
      assert_block_side_effects(&mut txn, set, &block_txs);
    }

    // Provided transactions that need preconditions
    for tx in all_provided_transactions() {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      // Set up required external state
      match &tx {
        Transaction::Cosign { substrate_block_hash } => {
          CosignIntents::provide(
            &mut txn,
            set,
            &CosignIntent {
              global_session: random_bytes_32(&mut OsRng),
              block_number: random_block_number(&mut OsRng),
              block_hash: *substrate_block_hash,
              notable: false,
            },
          );
        }
        Transaction::SubstrateBlock { hash } => {
          let plans = vec![random_bytes_32(&mut OsRng)];
          SubstrateBlockPlans::set(&mut txn, set, *hash, &plans);
        }
        _ => {}
      }

      let block_txs = vec![TributaryTransaction::Application(tx)];
      let block = Block {
        header: BlockHeader {
          parent: random_bytes_32(&mut OsRng),
          transactions: random_bytes_32(&mut OsRng),
        },
        transactions: block_txs.clone(),
      };

      {
        let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_block(random_block_number(&mut OsRng), block);
      }
      assert_block_side_effects(&mut txn, set, &block_txs);
    }

    // Each Tendermint SlashEvidence type fatally slashes the sender
    {
      let all_evidence = [
        Evidence::InvalidPrecommit(make_signed_message_bytes(addr0.0)),
        Evidence::InvalidValidRound(make_signed_message_bytes(addr0.0)),
        Evidence::ConflictingMessages(
          make_signed_message_bytes(addr0.0),
          make_signed_message_bytes(addr0.0),
        ),
      ];

      for evidence in all_evidence {
        let mut db = MemDb::new();
        let mut txn = db.txn();

        let block = Block {
          header: BlockHeader {
            parent: random_bytes_32(&mut OsRng),
            transactions: random_bytes_32(&mut OsRng),
          },
          transactions: vec![TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
            evidence,
          ))],
        };

        {
          let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
          scan_block.handle_block(1, block);
        }
        assert!(
          TributaryDb::is_fatally_slashed(&txn, set, addr0),
          "SlashEvidence should fatally slash the sender",
        );

        assert_no_pending_messages(&mut txn, set);
        txn.commit();
      }
    }

    // Fuzz mixed blocks with random quantities, types, and ordering
    for _ in 0 .. 100 {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      let num_txs = OsRng.gen_range(1usize ..= 8);
      let mut transactions = Vec::with_capacity(num_txs);
      let mut has_evidence = false;
      let mut batch_hashes = vec![];

      for _ in 0 .. num_txs {
        if OsRng.gen_bool(0.5) {
          // Random Tendermint evidence type
          let evidence = match OsRng.gen_range(0u8 .. 3) {
            0 => Evidence::InvalidPrecommit(make_signed_message_bytes(addr0.0)),
            1 => Evidence::InvalidValidRound(make_signed_message_bytes(addr0.0)),
            _ => Evidence::ConflictingMessages(
              make_signed_message_bytes(addr0.0),
              make_signed_message_bytes(addr0.0),
            ),
          };
          transactions
            .push(TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(evidence)));
          has_evidence = true;
        } else {
          // Random application transaction, use Batch so we can assert recognition
          let hash = random_bytes_32(&mut OsRng);
          batch_hashes.push(hash);
          transactions.push(TributaryTransaction::Application(Transaction::Batch { hash }));
        }
      }

      let block = Block {
        header: BlockHeader {
          parent: random_bytes_32(&mut OsRng),
          transactions: random_bytes_32(&mut OsRng),
        },
        transactions: transactions.clone(),
      };

      {
        let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.handle_block(random_block_number(&mut OsRng), block);
      }

      if has_evidence {
        assert!(
          TributaryDb::is_fatally_slashed(&txn, set, addr0),
          "SlashEvidence should fatally slash the sender in mixed blocks",
        );
      }
      for hash in &batch_hashes {
        let topic = expected_initially_recognized_sign_topic(VariantSignId::Batch(*hash));
        assert!(
          RecognizedTopics::recognized(&txn, set, topic),
          "Batch should be recognized regardless of other txs in the block",
        );
      }
      assert_block_side_effects(&mut txn, set, &transactions);
    }
  }
}
