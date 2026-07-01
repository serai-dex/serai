use core::marker::PhantomData;

use std::collections::HashMap;

use dkg::Participant;

use serai_mock_rpc::new_test_rng;
use serai_primitives::{
  test_helpers::{random_block_hash, random_vec_u8},
};

use serai_db::{Db as _, DbTxn, MemDb};
use serai_tributary_types::test_helpers::u16_to_participant;
use tributary_sdk::{
  tendermint::tx::TendermintTx, Evidence, Transaction as TributaryTransaction, BlockHeader, Block,
};

use serai_cosign_types::CosignIntent;
use crate::{db::SubstrateCosignIntents as DbCosignIntents, *};
use super::*;

fn new_scan_block<'a, TDT: DbTxn>(
  txn: &'a mut TDT,
  tributary_validator_set_info: &'a TributaryValidatorSetInfo,
) -> ScanBlock<'a, MemDb, TDT, NopP2p> {
  ScanBlock {
    _td: PhantomData,
    _p2p: PhantomData,
    tributary_txn: txn,
    tributary_validator_set_info,
  }
}

#[test]
fn potentially_start_cosign() {
  let mut rng = new_test_rng();
  let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
  let set = tributary_validator_set_info.set;

  // Already actively cosigning: should not replace the actively cosigning block
  {
    let mut db = MemDb::new();
    let initial_block_hash = random_block_hash(&mut rng);

    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, initial_block_hash, rng.next_u64());
      let new_block_hash = random_block_hash(&mut rng);
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, new_block_hash);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.potentially_start_cosign();
    }

    // Did not replace initial_block_hash for new_block_hash
    assert_eq!(TributaryDb::get_actively_cosigning_hash(&mut txn, set), Some(initial_block_hash));
  }

  // No TributaryDb::latest_substrate_block_to_cosign block: nop
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.potentially_start_cosign();
    }
    assert!(TributaryDb::get_actively_cosigning_hash(&mut txn, set).is_none());
  }

  // Already cosigned: nop
  {
    let mut db = MemDb::new();
    let initial_block_hash = random_block_hash(&mut rng);

    {
      let mut txn = db.txn();
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, initial_block_hash);
      TributaryDb::mark_cosigned(&mut txn, set, initial_block_hash);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.potentially_start_cosign();
    }

    assert!(TributaryDb::get_actively_cosigning_hash(&mut txn, set).is_none());
  }

  // Ready to cosign: starts cosigning and sends processor message
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut rng);
    let global_session = random_bytes(&mut rng);

    let intent = CosignIntent {
      global_cosigning_session: global_session,
      block_number: rng.next_u64(),
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
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.potentially_start_cosign();
    }

    assert_start_cosigning_invariants(&mut txn, set, block_hash, intent.block_number);
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  // Panics when stored intent's block_hash differs from latest_substrate_block_to_cosign
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut rng);
    let global_session = random_bytes(&mut rng);

    {
      let mut txn = db.txn();
      TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, block_hash);

      let new_block_hash = random_block_hash(&mut rng);
      DbCosignIntents::set(
        &mut txn,
        set,
        // Store the intent under block_hash (the key `CosignIntents::take` will look up)
        block_hash,
        &CosignIntent {
          global_cosigning_session: global_session,
          block_number: rng.next_u64(),
          // but the intent's block_hash field is a new_block_hash
          block_hash: new_block_hash,
          notable: false,
        },
      );
      txn.commit();
    }

    let result = std::panic::catch_unwind(move || {
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
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
  let mut rng = new_test_rng();
  let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
  let set = tributary_validator_set_info.set;

  let k1_participant = u16_to_participant(1);
  let k2_participant = u16_to_participant(2);
  let k3_participant = u16_to_participant(3);
  let k4_participant = u16_to_participant(4);

  let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };

  // Panics if the topic isn't DkgConfirmation
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.accumulate_dkg_confirmation(
        rng.next_u64(),
        Topic::RemoveParticipant { participant: Participant::new(u16::MAX).unwrap() },
        &random_vec_u8(&mut rng, 4 ..= 4),
        k1_participant,
      );
    }));

    assert!(result.is_err(), "should panic when called with a non-DkgConfirmation topic");
  }

  // Threshold crossed: third accumulation returns SignId + correctly mapped data
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = rng.next_u64();

    {
      let data1 = random_vec_u8(&mut rng, 4 ..= 4);
      let data2 = random_vec_u8(&mut rng, 4 ..= 4);
      let data3 = random_vec_u8(&mut rng, 4 ..= 4);

      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);

      assert!(scan_block
        .accumulate_dkg_confirmation(block_number, topic, &data1, k1_participant)
        .is_none());
      assert!(scan_block
        .accumulate_dkg_confirmation(block_number, topic, &data2, k2_participant)
        .is_none());
      let result =
        scan_block.accumulate_dkg_confirmation(block_number, topic, &data3, k3_participant);

      let (sign_id, data_set) = result.expect("third accumulation should cross threshold");

      assert_eq!(
        sign_id,
        topic.dkg_confirmation_sign_id(set).unwrap(),
        "SignId must match what dkg_confirmation_sign_id produces"
      );

      // The `data_set` from `accumulate_dkg_confirmation` is `HashMap<Participant, Vec<u8>>`
      // The keys are the DkgParticipants (1-indexed by position in the validator list).
      assert_eq!(data_set.len(), 3);
      assert!(data_set.contains_key(&Participant::new(1).unwrap()));
      assert!(data_set.contains_key(&Participant::new(2).unwrap()));
      assert!(data_set.contains_key(&Participant::new(3).unwrap()));

      // Past threshold: further accumulations should be nops (weight >= threshold check)
      {
        // Use a participant that hasn't accumulated yet to avoid the duplicate assertion
        let data4 = random_vec_u8(&mut rng, 4 ..= 4);
        assert!(
          scan_block
            .accumulate_dkg_confirmation(block_number, topic, &data4, k4_participant)
            .is_none(),
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
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;
    // Get the participant index of the first validator
    let default_participant = Participant::new(1).unwrap();

    let mut db = MemDb::new();

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, default_participant, "test reason");
      assert!(TributaryDb::is_fatally_slashed(&txn, set, default_participant,));
      txn.commit();
    }

    for tx in all_signed_transactions_and_attempts(&mut rng, Signed::default(), None) {
      let mut txn = db.txn();

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(rng.next_u64(), tx.clone());
      }

      assert!(
        ProcessorMessages::try_recv(&mut txn, set).is_none(),
        "fatally slashed signer should be ignored for {tx:?}"
      );
    }
  }

  #[test]
  fn remove_participant() {
    let mut rng = new_test_rng();
    // The signer is fatally slashed if the participant voted to be removed is nonexistent
    {
      let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
      let set = tributary_validator_set_info.set;
      let first_participant = u16_to_participant(1);

      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);

      let nonexistent = Participant::new(u16::MAX).unwrap();

      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::RemoveParticipant {
          participant: nonexistent,
          signed: random_signed_for_validator(
            &mut rng,
            &tributary_validator_set_info,
            first_participant,
          ),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&txn, set, first_participant));
    }

    // Valid RemoveParticipant accumulates weight and eventually crosses threshold
    {
      let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
      let set = tributary_validator_set_info.set;
      let first_participant = u16_to_participant(1);
      let second_participant = u16_to_participant(2);
      let third_participant = u16_to_participant(3);

      let block_number = rng.next_u64();

      let mut db = MemDb::new();
      let mut txn = db.txn();

      // First vote: topic is recognized, target not yet slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant {
            participant: first_participant,
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              first_participant,
            ),
          },
        );
      }
      assert!(
        RecognizedTopics::is_topic_recognized(
          &txn,
          set,
          Topic::RemoveParticipant { participant: first_participant }
        ),
        "RemoveParticipant topic should be recognized after handling the tx"
      );
      assert!(
        !TributaryDb::is_fatally_slashed(&txn, set, first_participant),
        "target should not be fatally slashed after one vote"
      );

      // Threshold crossed, target gets fatally slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant {
            participant: first_participant,
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              second_participant,
            ),
          },
        );
        assert!(
          !TributaryDb::is_fatally_slashed(scan_block.tributary_txn, set, first_participant),
          "target should not be fatally slashed after two votes"
        );
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant {
            participant: first_participant,
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              third_participant,
            ),
          },
        );
      }
      assert!(
        TributaryDb::is_fatally_slashed(&txn, set, first_participant),
        "target should be fatally slashed after threshold is crossed"
      );
    }
  }

  #[test]
  fn dkg_participation() {
    let mut db = MemDb::new();
    let mut rng = new_test_rng();

    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;
    let first_participant = u16_to_participant(1);

    let mut txn = db.txn();

    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::DkgParticipation {
          participation: vec![1, 2, 3, 4],
          signed: random_signed_for_validator(
            &mut rng,
            &tributary_validator_set_info,
            first_participant,
          ),
        },
      );
    }

    // TODO: Check the received message is the expected one
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn dkg_confirmation_preprocess() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;

    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = rng.next_u64();

    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      for (i_participant, _) in
        tributary_validator_set_info.tributary_validator_set.consensus_participants()
      {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess: random_bytes(&mut rng),
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              i_participant,
            ),
          },
        );
        // With 4 validators weight 1 each, required_participation = 2.
        // Participant 1 is below threshold; participant 2 crosses it.
        if u16::from(i_participant) == 1 {
          assert!(DkgConfirmationMessages::try_recv(scan_block.tributary_txn, set).is_none());
        }
      }
    }
    // Threshold crossed: sends DkgConfirmationMessages (Preprocesses)
    // TODO: Check the received message is the expected one
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn dkg_confirmation_share() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;
    let first_participant = u16_to_participant(1);
    let second_participant = u16_to_participant(2);
    let third_participant = u16_to_participant(3);

    // Share without preceding preprocess participation -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);

      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::DkgConfirmationShare {
          attempt: 0,
          share: random_bytes(&mut rng),
          signed: random_signed_for_validator(
            &mut rng,
            &tributary_validator_set_info,
            first_participant,
          ),
        },
      );

      assert!(
        TributaryDb::is_fatally_slashed(&txn, set, first_participant),
        "share without preceding preprocess should fatally slash"
      );
    }

    // Full preprocess->share flow
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = rng.next_u64();

    // All 3 validators submit preprocesses (threshold crossed -> DkgConfirmationMessages sent)
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      for (i, participant) in
        [first_participant, second_participant, third_participant].into_iter().enumerate()
      {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess: random_bytes(&mut rng),
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              participant,
            ),
          },
        );
        if i != 2 {
          assert!(DkgConfirmationMessages::try_recv(scan_block.tributary_txn, set).is_none());
        }
      }
    }
    // TODO: Check the exact message received
    assert!(
      DkgConfirmationMessages::try_recv(&mut txn, set).is_some(),
      "preprocesses crossing threshold should produce DkgConfirmationMessages"
    );

    // Threshold crossed: sends DkgConfirmationMessages (Shares)
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      for (i, participant) in
        [first_participant, second_participant, third_participant].into_iter().enumerate()
      {
        scan_block.handle_application_tx(
          block_number,
          Transaction::DkgConfirmationShare {
            attempt: 0,
            share: random_bytes(&mut rng),
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              participant,
            ),
          },
        );
        if i != 2 {
          assert!(
            DkgConfirmationMessages::try_recv(scan_block.tributary_txn, set).is_none(),
            "less than threshold should not produce DkgConfirmationMessages"
          );
        }
      }
    }
    // TODO: Check the exact message received
    assert!(
      DkgConfirmationMessages::try_recv(&mut txn, set).is_some(),
      "shares crossing threshold should produce DkgConfirmationMessages"
    );
  }

  #[test]
  fn cosign() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;

    let block_hash = random_block_hash(&mut rng);
    let global_session = random_bytes(&mut rng);

    let intent = CosignIntent {
      global_cosigning_session: global_session,
      block_number: rng.next_u64(),
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
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);

      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::Cosign { substrate_block_hash: block_hash },
      );

      assert_eq!(TributaryDb::latest_substrate_block_to_cosign(&txn, set), Some(block_hash));
      assert_eq!(TributaryDb::get_actively_cosigning_hash(&mut txn, set), Some(block_hash));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }

    // When already cosigning, updates LatestSubstrateBlockToCosign but doesn't replace active
    {
      let mut db = MemDb::new();
      let first_hash = random_block_hash(&mut rng);
      let second_hash = random_block_hash(&mut rng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, first_hash, rng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);

      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::Cosign { substrate_block_hash: second_hash },
      );

      assert_eq!(TributaryDb::latest_substrate_block_to_cosign(&txn, set), Some(second_hash));
      assert_eq!(TributaryDb::get_actively_cosigning_hash(&mut txn, set), Some(first_hash));
    }
  }

  #[test]
  fn cosigned() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;

    // Marks block as cosigned
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let block_hash = random_block_hash(&mut rng);

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          rng.next_u64(),
          Transaction::Cosigned { substrate_block_hash: block_hash },
        );
      }

      assert!(TributaryDb::is_cosigned(&mut txn, set, block_hash));
    }

    // Finishes active cosign when matching block
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut rng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, block_hash, rng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      assert_eq!(TributaryDb::get_actively_cosigning_hash(&mut txn, set), Some(block_hash));

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          rng.next_u64(),
          Transaction::Cosigned { substrate_block_hash: block_hash },
        );
      }
      assert!(TributaryDb::get_actively_cosigning_hash(&mut txn, set).is_none());
    }

    // Does not finish active cosign when block doesn't match
    /*
      TODO: The story for this test is unclear.

      The intent is that if we are to cosign block #500, then block #501, we don't interrupt
      cosigning block #500 to begin on block #501. Instead, we finish #500, by which point we may
      be asked to cosign block #501, or maybe even #502. The intent is by finishing #500, we
      inherently begin the latest block to cosign.

      This test asserts that if we're cosigning X, but then finish Y (which should be an
      unreachable invariant, as we shouldn't start cosinging while already cosigning), that we
      continue on X. Presumably, this is a byproduct of how if we finish #500 but have #501
      pending, we're intended to immediately rollover to #501, presented here as explicit
      functionality to test for. This has to be straightened out.
    */
    {
      let mut db = MemDb::new();
      let active_hash = random_block_hash(&mut rng);
      let other_hash = random_block_hash(&mut rng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, active_hash, rng.next_u64());
        txn.commit();
      }

      let mut txn = db.txn();
      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          rng.next_u64(),
          Transaction::Cosigned { substrate_block_hash: other_hash },
        );
      }
      assert_eq!(TributaryDb::get_actively_cosigning_hash(&mut txn, set), Some(active_hash));
      assert!(TributaryDb::is_cosigned(&mut txn, set, other_hash));
    }
  }

  #[test]
  fn substrate_block() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;

    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut rng);
    let plans = vec![random_bytes(&mut rng), random_bytes(&mut rng)];

    {
      let mut txn = db.txn();
      SubstrateBlockPlans::set(&mut txn, set, block_hash, &plans);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block
        .handle_application_tx(rng.next_u64(), Transaction::SubstrateBlock { hash: block_hash });
    }

    for plan in &plans {
      let topic = initial_sign_topic(VariantSignId::Transaction(*plan));
      assert!(RecognizedTopics::is_topic_recognized(&txn, set, topic));
    }
  }

  #[test]
  fn batch() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 5);
    let set = tributary_validator_set_info.set;

    let mut db = MemDb::new();
    let batch_hash = random_bytes(&mut rng);

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_application_tx(rng.next_u64(), Transaction::Batch { hash: batch_hash });
    }

    let topic = initial_sign_topic(VariantSignId::Batch(batch_hash));
    assert!(RecognizedTopics::is_topic_recognized(&txn, set, topic));
  }

  mod slash_report {
    use super::*;

    #[test]
    fn wrong_length() {
      let mut rng = new_test_rng();
      let num_validators = rng.gen_range(4u16 .. 10);
      let mut wrong_len = rng.gen_range(1u16 .. 20);
      if wrong_len == num_validators {
        wrong_len = if wrong_len == 1 { 2 } else { wrong_len - 1 };
      }

      let tributary_validator_set_info = setup_n_validators(&mut rng, num_validators);
      let set = tributary_validator_set_info.set;
      let first_participant = u16_to_participant(1);

      let mut db = MemDb::new();
      let mut txn = db.txn();

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_application_tx(
          rng.next_u64(),
          Transaction::SlashReport {
            slash_points: vec![0; usize::from(wrong_len)],
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              first_participant,
            ),
          },
        );
      }

      assert!(
        TributaryDb::is_fatally_slashed(&txn, set, first_participant),
        "signer should be fatally slashed for wrong-length slash report",
      );
      assert!(
        ProcessorMessages::try_recv(&mut txn, set).is_none(),
        "no message should be sent for wrong-length slash report",
      );
    }

    #[test]
    fn fatal_slash_as_reported_median() {
      let mut rng = new_test_rng();
      let num_validators = rng.gen_range(4u16 .. 10);
      let num_reports = usize::from(required_participation(num_validators));

      let tributary_validator_set_info = setup_n_validators(&mut rng, num_validators);
      let set = tributary_validator_set_info.set;

      let mut report = vec![0u32; usize::from(num_validators)];
      report[0] = u32::MAX;
      let reports: Vec<Vec<u32>> = vec![report; num_reports];

      let mut db = MemDb::new();
      let mut txn = db.txn();

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        for (i, report) in reports.iter().enumerate() {
          let participant = u16_to_participant(u16::try_from(i + 1).unwrap());
          scan_block.handle_application_tx(
            rng.next_u64(),
            Transaction::SlashReport {
              slash_points: report.clone(),
              signed: random_signed_for_validator(
                &mut rng,
                &tributary_validator_set_info,
                participant,
              ),
            },
          );
        }
      }

      // A ProcessorMessage should be produced containing a Fatal slash
      // TODO: Check the exact message received
      let msg = ProcessorMessages::try_recv(&mut txn, set);
      assert!(msg.is_some(), "expected ProcessorMessage for fatal slash report");
    }

    mod fuzz_slash_report {
      use super::*;

      /// Independently compute the expected slash report that `handle_application_tx` should
      /// produce when `DataSet::Participating` is reached, mirroring the production logic.
      ///
      /// Returns `None` if `f == 0` (the slash report would be empty and nothing is sent).
      fn expected_slash_report(num_validators: u16, reports: &[Vec<u32>]) -> Vec<u32> {
        let f = (num_validators - 1) / 3;

        // Compute the median for each validator position across all reporters
        let mut medians = Vec::with_capacity(usize::from(num_validators));
        for i in 0 .. usize::from(num_validators) {
          let mut values: Vec<u32> = reports.iter().map(|r| r[i]).collect();
          values.sort_unstable();
          let median_index =
            if (values.len() % 2) == 1 { values.len() / 2 } else { (values.len() / 2) - 1 };
          medians.push(values[median_index]);
        }

        // Find worst validator in the supermajority and amortize
        let mut sorted = medians.clone();
        sorted.sort_unstable();
        let amortization = sorted[usize::from(num_validators - f - 1)];

        medians.iter().map(|p| p.saturating_sub(amortization)).collect::<Vec<u32>>()
      }

      /// Generate `count` slash report vectors, each of length `num_validators`.
      fn random_slash_reports(
        rng: &mut impl Rng,
        num_validators: u16,
        count: u16,
      ) -> Vec<Vec<u32>> {
        (0 .. count).map(|_| (0 .. num_validators).map(|_| rng.next_u32()).collect()).collect()
      }

      #[test]
      fn fuzz_slash_report_even_validators() {
        let mut rng = new_test_rng();
        for _ in 0 .. 200 {
          // random even: 4, 6, 8, or 10
          let n = rng.gen_range(2u16 ..= 5) * 2;
          let num_reports = required_participation(n);

          let tributary_validator_set_info = setup_n_validators(&mut rng, n);
          let set = tributary_validator_set_info.set;

          let reports = random_slash_reports(&mut rng, n, num_reports);
          let expected = expected_slash_report(n, &reports);

          let mut db = MemDb::new();
          let mut txn = db.txn();

          {
            let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
            for (i, report) in reports.iter().enumerate() {
              let participant = u16_to_participant(u16::try_from(i + 1).unwrap());
              scan_block.handle_application_tx(
                rng.next_u64(),
                Transaction::SlashReport {
                  slash_points: report.clone(),
                  signed: random_signed_for_validator(
                    &mut rng,
                    &tributary_validator_set_info,
                    participant,
                  ),
                },
              );
            }
          }

          assert_eq!(
            ProcessorMessages::try_recv(&mut txn, set),
            Some(messages::CoordinatorMessage::from(
              messages::coordinator::CoordinatorMessage::SignSlashReport {
                session: set.session,
                slash_report: expected
                  .into_iter()
                  .filter(|points| *points != 0 || *points == u32::MAX)
                  .map(|points| if points == u32::MAX {
                    Slash::Fatal
                  } else {
                    Slash::Points(points)
                  })
                  .collect::<Vec<_>>()
                  .try_into()
                  .unwrap(),
              }
            ))
          );

          let sign_topic = initial_sign_topic(VariantSignId::SlashReport);
          assert!(
            RecognizedTopics::is_topic_recognized(&txn, set, sign_topic),
            "SlashReport sign topic should be recognized",
          );
        }
      }

      #[test]
      fn fuzz_slash_report_odd_validators() {
        let mut rng = new_test_rng();
        for _ in 0 .. 200 {
          // random odd: 5, 7, 9, or 11
          let n = rng.gen_range(2u16 ..= 5) * 2 + 1;
          let num_reports = required_participation(n);

          let tributary_validator_set_info = setup_n_validators(&mut rng, n);
          let set = tributary_validator_set_info.set;

          let reports = random_slash_reports(&mut rng, n, num_reports);
          let expected = expected_slash_report(n, &reports);

          let mut db = MemDb::new();
          let mut txn = db.txn();

          {
            let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
            for (i, report) in reports.iter().enumerate() {
              let participant = u16_to_participant(u16::try_from(i + 1).unwrap());
              scan_block.handle_application_tx(
                rng.next_u64(),
                Transaction::SlashReport {
                  slash_points: report.clone(),
                  signed: random_signed_for_validator(
                    &mut rng,
                    &tributary_validator_set_info,
                    participant,
                  ),
                },
              );
            }
          }

          assert_eq!(
            ProcessorMessages::try_recv(&mut txn, set),
            Some(messages::CoordinatorMessage::from(
              messages::coordinator::CoordinatorMessage::SignSlashReport {
                session: set.session,
                slash_report: expected
                  .into_iter()
                  .filter(|points| *points != 0 || *points == u32::MAX)
                  .map(|points| if points == u32::MAX {
                    Slash::Fatal
                  } else {
                    Slash::Points(points)
                  })
                  .collect::<Vec<_>>()
                  .try_into()
                  .unwrap(),
              }
            ))
          );
          let sign_topic = initial_sign_topic(VariantSignId::SlashReport);
          assert!(RecognizedTopics::is_topic_recognized(&txn, set, sign_topic));
        }
      }
    }
  }

  #[test]
  fn sign() {
    let mut rng = new_test_rng();

    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;
    let first_participant = u16_to_participant(1);

    let sign_id = VariantSignId::Transaction(random_bytes(&mut rng));
    let topic = initial_sign_topic(sign_id);

    // Wrong data length: signer has weight 1 but submits 2 entries -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_application_tx(
        rng.next_u64(),
        Transaction::Sign {
          id: sign_id,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
          data: HashMap::from([
            (Participant::new(1).unwrap(), vec![1]),
            (Participant::new(2).unwrap(), vec![2]),
          ]),
          signed: random_signed_for_validator(
            &mut rng,
            &tributary_validator_set_info,
            first_participant,
          ),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&txn, set, first_participant));
    }

    // Valid data: threshold crossing sends ProcessorMessage
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      {
        let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        for (i_participant, _) in
          tributary_validator_set_info.tributary_validator_set.consensus_participants()
        {
          scan_block.handle_application_tx(
            rng.next_u64(),
            Transaction::Sign {
              id: sign_id,
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
              data: HashMap::from([(Participant::new(1).unwrap(), vec![1, 2, 3])]),
              signed: random_signed_for_validator(
                &mut rng,
                &tributary_validator_set_info,
                i_participant,
              ),
            },
          );
        }
      }

      // TODO: Check the exact message received
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  /// Exercises the Sign Share -> Participating path.
  /// Requires first accumulating preprocesses to threshold (which recognizes the Share topic
  /// and stores preceding data), then accumulating shares to threshold.
  #[test]
  fn sign_share_sends_shares_message() {
    let mut rng = new_test_rng();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;
    let first_participant = u16_to_participant(1);
    let second_participant = u16_to_participant(2);
    let third_participant = u16_to_participant(3);

    let sign_id = VariantSignId::Transaction(random_bytes(&mut rng));
    let preprocess_topic = initial_sign_topic(sign_id);
    let share_topic = Topic::Sign { id: sign_id, attempt: 0, round: SigningProtocolRound::Share };

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // Recognize the Preprocess topic
    TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);

    // Step 1: All validators submit preprocesses, crossing threshold.
    // This auto-recognizes the Share topic (succeeding_topic) and stores preprocess data.
    {
      let block_number = rng.next_u64();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      for participant in [first_participant, second_participant, third_participant] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Preprocess,
            data: HashMap::from([(Participant::new(1).unwrap(), vec![1, 2, 3])]),
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              participant,
            ),
          },
        );
      }
    }

    // Drain the Preprocesses message from step 1
    // TODO: Check the exact message received
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());

    // Share topic should now be recognized
    assert!(RecognizedTopics::is_topic_recognized(&txn, set, share_topic));

    // Step 2: All validators submit shares, crossing threshold -> sends Shares message.
    {
      let block_number = rng.next_u64();
      let mut scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      for participant in [first_participant, second_participant, third_participant] {
        scan_block.handle_application_tx(
          block_number,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Share,
            data: HashMap::from([(Participant::new(1).unwrap(), vec![4, 5, 6])]),
            signed: random_signed_for_validator(
              &mut rng,
              &tributary_validator_set_info,
              participant,
            ),
          },
        );
      }
    }

    // The Shares message should have been sent
    let msg = ProcessorMessages::try_recv(&mut txn, set);
    // TODO: Check the exact message received
    assert!(msg.is_some(), "expected Shares processor message");

    // No validators should be slashed
    for participant in [first_participant, second_participant, third_participant] {
      assert!(!TributaryDb::is_fatally_slashed(&txn, set, participant));
    }
  }
}

#[test]
fn handle_block() {
  let mut rng = new_test_rng();
  let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
  let set = tributary_validator_set_info.set;
  let first_participant = u16_to_participant(1);
  let signed =
    random_signed_for_validator(&mut rng, &tributary_validator_set_info, first_participant);

  // Empty block only calls start of block
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block = Block {
      header: BlockHeader { parent: random_bytes(&mut rng), transactions: random_bytes(&mut rng) },
      transactions: vec![],
    };

    {
      let scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_block(rng.next_u64(), block);
    }
    assert_no_pending_messages(&mut txn, set);
  }

  // Each application transaction type passes through handle_block.
  // Signed transactions use a real validator key so participant_indexes lookups succeed.
  // Cosign and SubstrateBlock need external state populated before they can run.
  let n_validators =
    tributary_validator_set_info.tributary_validator_set.consensus_tributary_validators.len();
  for tx in all_signed_transactions_and_attempts(&mut rng, signed, Some(n_validators)) {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let block_txs = vec![TributaryTransaction::Application(tx)];
    let block = Block {
      header: BlockHeader { parent: random_bytes(&mut rng), transactions: random_bytes(&mut rng) },
      transactions: block_txs.clone(),
    };

    {
      let scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_block(rng.next_u64(), block);
    }
    assert_block_side_effects(&mut txn, set, &block_txs);
  }

  // Provided transactions that need preconditions
  for tx in all_provided_transactions(&mut rng) {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    // Set up required external state
    match &tx {
      Transaction::Cosign { substrate_block_hash } => {
        CosignIntents::provide(
          &mut txn,
          set,
          &CosignIntent {
            global_cosigning_session: random_bytes(&mut rng),
            block_number: rng.next_u64(),
            block_hash: *substrate_block_hash,
            notable: false,
          },
        );
      }
      Transaction::SubstrateBlock { hash } => {
        let plans = vec![random_bytes(&mut rng)];
        SubstrateBlockPlans::set(&mut txn, set, *hash, &plans);
      }
      // `Cosigned`, `Batch` are provided but do not require pre-existing state
      Transaction::Cosigned { .. } | Transaction::Batch { .. } => {}
      // These aren't provided transactions
      Transaction::RemoveParticipant { .. } |
      Transaction::DkgParticipation { .. } |
      Transaction::DkgConfirmationPreprocess { .. } |
      Transaction::DkgConfirmationShare { .. } |
      Transaction::Sign { .. } |
      Transaction::SlashReport { .. } => unreachable!(),
    }

    let block_txs = vec![TributaryTransaction::Application(tx)];
    let block = Block {
      header: BlockHeader { parent: random_bytes(&mut rng), transactions: random_bytes(&mut rng) },
      transactions: block_txs.clone(),
    };

    {
      let scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_block(rng.next_u64(), block);
    }
    assert_block_side_effects(&mut txn, set, &block_txs);
  }

  // Each Tendermint SlashEvidence type fatally slashes the sender
  {
    // Get the serai_networks_auxiliary_key of the first validator for evidence
    let first_validator =
      tributary_validator_set_info.tributary_validator_set.consensus_tributary_validators[0]
        .serai_networks_auxiliary_key;

    let all_evidence = [
      Evidence::InvalidPrecommit(make_signed_message_bytes(first_validator)),
      Evidence::InvalidValidRound(make_signed_message_bytes(first_validator)),
      Evidence::ConflictingMessages(
        make_signed_message_bytes(first_validator),
        make_signed_message_bytes(first_validator),
      ),
    ];

    for evidence in all_evidence {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      let block = Block {
        header: BlockHeader {
          parent: random_bytes(&mut rng),
          transactions: random_bytes(&mut rng),
        },
        transactions: vec![TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(evidence))],
      };

      {
        let scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
        scan_block.handle_block(1, block);
      }
      assert!(
        TributaryDb::is_fatally_slashed(&txn, set, first_participant),
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

    let num_txs = rng.gen_range(1usize ..= 8);
    let mut transactions = Vec::with_capacity(num_txs);
    let mut has_evidence = false;
    let mut batch_hashes = vec![];

    for _ in 0 .. num_txs {
      if rng.gen_bool(0.5) {
        // Random Tendermint evidence type
        let first_validator =
          tributary_validator_set_info.tributary_validator_set.consensus_tributary_validators[0]
            .serai_networks_auxiliary_key;
        let evidence = match rng.gen_range(0u8 .. 3) {
          0 => Evidence::InvalidPrecommit(make_signed_message_bytes(first_validator)),
          1 => Evidence::InvalidValidRound(make_signed_message_bytes(first_validator)),
          _ => Evidence::ConflictingMessages(
            make_signed_message_bytes(first_validator),
            make_signed_message_bytes(first_validator),
          ),
        };
        transactions.push(TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(evidence)));
        has_evidence = true;
      } else {
        // Random application transaction, use Batch so we can assert recognition
        let hash = random_bytes(&mut rng);
        batch_hashes.push(hash);
        transactions.push(TributaryTransaction::Application(Transaction::Batch { hash }));
      }
    }

    let block = Block {
      header: BlockHeader { parent: random_bytes(&mut rng), transactions: random_bytes(&mut rng) },
      transactions: transactions.clone(),
    };

    {
      let scan_block = new_scan_block(&mut txn, &tributary_validator_set_info);
      scan_block.handle_block(rng.next_u64(), block);
    }

    if has_evidence {
      assert!(
        TributaryDb::is_fatally_slashed(&txn, set, first_participant),
        "SlashEvidence should fatally slash the sender in mixed blocks",
      );
    }
    for hash in &batch_hashes {
      let topic = initial_sign_topic(VariantSignId::Batch(*hash));
      assert!(
        RecognizedTopics::is_topic_recognized(&txn, set, topic),
        "Batch should be recognized regardless of other txs in the block",
      );
    }
    assert_block_side_effects(&mut txn, set, &transactions);
  }
}
