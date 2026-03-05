use rand::{RngCore, rngs::OsRng};

use serai_primitives::{address::SeraiAddress, validator_sets::ExternalValidatorSet};

use messages::sign::VariantSignId;

use serai_db::{Db, DbTxn, MemDb};
use serai_substrate_tests::random_serai_address;

use crate::{
  db::*,
  tests::{default_test_validator_set, random_transaction_id, random_block_number},
  transaction::SigningProtocolRound,
};

fn random_data_u32() -> [u8; 32] {
  let mut data = [0u8; 32];
  OsRng.fill_bytes(&mut data);
  data
}
fn random_data_u64() -> [u8; 64] {
  let mut data = [0u8; 64];
  OsRng.fill_bytes(&mut data);
  data
}

fn all_topics() -> Vec<Topic> {
  vec![
    Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share },
    Topic::SlashReport,
    Topic::Sign {
      id: random_transaction_id(),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign { id: random_transaction_id(), attempt: 0, round: SigningProtocolRound::Share },
  ]
}

fn all_topics_with_u32_max_attempts() -> Vec<Topic> {
  vec![
    Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
    Topic::DkgConfirmation { attempt: std::u32::MAX, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: std::u32::MAX, round: SigningProtocolRound::Share },
    Topic::SlashReport,
    Topic::Sign {
      id: random_transaction_id(),
      attempt: std::u32::MAX,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: std::u32::MAX,
      round: SigningProtocolRound::Share,
    },
  ]
}

type NoEachFn = fn(usize, &DataSet<[u8; 32]>);

/// Cross threshold by accumulating from all validators, returning the final result.
fn accumulate_to_threshold<F1>(
  txn: &mut impl DbTxn,
  set: ExternalValidatorSet,
  validators: &[SeraiAddress],
  total_weight: u16,
  block_number: u64,
  topic: Topic,
  on_each: Option<F1>,
) -> DataSet<[u8; 32]>
where
  F1: FnMut(usize, &DataSet<[u8; 32]>),
{
  let mut on_each = on_each;
  let mut result = DataSet::None;
  for (i, v) in validators.iter().enumerate() {
    result = TributaryDb::accumulate::<[u8; 32]>(
      txn,
      set,
      validators,
      total_weight,
      block_number,
      topic,
      *v,
      1,
      &[i as u8; 32],
    );
    if let Some(ref mut f) = on_each {
      f(i, &result);
    }
  }

  result
}

mod topic {
  use messages::sign::SignId;
  use super::*;

  #[test]
  fn next_attempt_topic() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.next_attempt_topic(), None),
        Topic::DkgConfirmation { attempt, .. } => assert_eq!(
          topic.next_attempt_topic(),
          Some(Topic::DkgConfirmation {
            attempt: attempt + 1,
            round: SigningProtocolRound::Preprocess,
          })
        ),
        Topic::SlashReport => assert_eq!(topic.next_attempt_topic(), None),
        Topic::Sign { id, attempt, .. } => assert_eq!(
          topic.next_attempt_topic(),
          Some(Topic::Sign { id, attempt: attempt + 1, round: SigningProtocolRound::Preprocess })
        ),
      }
    }

    for topic in all_topics_with_u32_max_attempts() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.next_attempt_topic(), None),
        Topic::DkgConfirmation { .. } => assert_eq!(
          topic.next_attempt_topic(),
          Some(Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess })
        ),
        Topic::SlashReport => assert_eq!(topic.next_attempt_topic(), None),
        Topic::Sign { id, .. } => assert_eq!(
          topic.next_attempt_topic(),
          Some(Topic::Sign { id, attempt: 0, round: SigningProtocolRound::Preprocess })
        ),
      }
    }
  }

  #[test]
  fn reattempt_topic() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.reattempt_topic(), None),
        Topic::DkgConfirmation { attempt, round } => match round {
          SigningProtocolRound::Preprocess => {
            let next_attempt = attempt + 1;
            assert_eq!(
              topic.reattempt_topic(),
              Some((
                next_attempt,
                Topic::DkgConfirmation {
                  attempt: next_attempt,
                  round: SigningProtocolRound::Preprocess,
                },
              ))
            );
          }
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::SlashReport => assert_eq!(topic.reattempt_topic(), None),
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => {
            let next_attempt = attempt + 1;
            assert_eq!(
              topic.reattempt_topic(),
              Some((
                next_attempt,
                Topic::Sign { id, attempt: next_attempt, round: SigningProtocolRound::Preprocess },
              ))
            );
          }
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
      }
    }

    for topic in all_topics_with_u32_max_attempts() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.reattempt_topic(), None),
        Topic::DkgConfirmation { round, .. } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            Some((
              0,
              Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
            ))
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::SlashReport => assert_eq!(topic.reattempt_topic(), None),
        Topic::Sign { id, round, .. } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            Some((0, Topic::Sign { id, attempt: 0, round: SigningProtocolRound::Preprocess }))
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
      }
    }
  }

  #[test]
  fn sign_id() {
    let set = default_test_validator_set();
    for topic in all_topics() {
      match topic {
        Topic::Sign { id, attempt, round: _ } => {
          assert_eq!(topic.sign_id(set), Some(SignId { session: set.session, id, attempt }))
        }
        _ => assert_eq!(topic.sign_id(set), None),
      }
    }
  }

  #[test]
  fn dkg_confirmation_sign_id() {
    let set = default_test_validator_set();
    for topic in all_topics() {
      match topic {
        Topic::DkgConfirmation { attempt, round: _ } => assert_eq!(
          topic.dkg_confirmation_sign_id(set),
          Some({
            let id = {
              let mut id = [0; 32];
              let encoded_set = borsh::to_vec(&set).unwrap();
              id[.. encoded_set.len()].copy_from_slice(&encoded_set);
              VariantSignId::Batch(id)
            };
            SignId { session: set.session, id, attempt }
          })
        ),
        _ => assert_eq!(topic.dkg_confirmation_sign_id(set), None),
      }
    }
  }

  #[test]
  fn succeeding_topic() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.succeeding_topic(), None),
        Topic::DkgConfirmation { attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.succeeding_topic(),
            Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share })
          ),

          SigningProtocolRound::Share => assert_eq!(topic.succeeding_topic(), None),
        },
        Topic::SlashReport => assert_eq!(topic.succeeding_topic(), None),
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.succeeding_topic(),
            Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Share })
          ),
          SigningProtocolRound::Share => assert_eq!(topic.succeeding_topic(), None),
        },
      }
    }
  }

  #[test]
  fn requires_recognition() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.requires_recognition(), false),
        Topic::DkgConfirmation { attempt, .. } => {
          assert_eq!(topic.requires_recognition(), attempt != 0)
        }
        Topic::SlashReport => assert_eq!(topic.requires_recognition(), false),
        Topic::Sign { .. } => assert_eq!(topic.requires_recognition(), true),
      }
    }
  }

  #[test]
  fn participating() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => {
          assert_eq!(topic.participating(), Participating::Everyone)
        }
        Topic::DkgConfirmation { .. } => {
          assert_eq!(topic.participating(), Participating::Participated)
        }
        Topic::SlashReport => assert_eq!(topic.participating(), Participating::Everyone),
        Topic::Sign { .. } => assert_eq!(topic.participating(), Participating::Participated),
      }
    }
  }
}

mod tributary_db {
  use serai_substrate_tests::random_block_hash;
  use super::*;

  #[test]
  fn start_cosigning() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let block_hash1 = random_block_hash(&mut OsRng);
    let block_number1 = random_block_number();

    let topic = Topic::Sign {
      id: VariantSignId::Cosign(block_number1),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    };

    // Recognizes topic
    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number1);
      assert!(TributaryDb::try_recv_topic_requiring_recognition(&mut txn, set).is_some());
      assert!(TributaryDb::recognized(&txn, set, topic));
      txn.commit();
    }

    // Same set cannot recognize again until finished
    {
      let mut txn = db.txn();
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash1));

      let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let block_hash2 = random_block_hash(&mut OsRng);
        let block_number2 = random_block_number();
        TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      }));

      assert!(retry.is_err());

      // Previous topic still recognized
      assert!(TributaryDb::recognized(&txn, set, topic));

      txn.commit();
    }

    // Finish cosigning
    {
      let mut txn = db.txn();
      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), None);

      // Previous topic remains recognized
      assert!(TributaryDb::recognized(
        &txn,
        set,
        Topic::Sign {
          id: VariantSignId::Cosign(block_number1),
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        }
      ));

      txn.commit();
    }

    // Start cosigning new block
    {
      let mut txn = db.txn();
      let block_hash2 = random_block_hash(&mut OsRng);
      let block_number2 = random_block_number();

      TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash2));

      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), None);

      // The new topic is now recognized
      assert!(TributaryDb::recognized(
        &txn,
        set,
        Topic::Sign {
          id: VariantSignId::Cosign(block_number2),
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        }
      ));
      // Previous topic also remains recognized
      assert!(TributaryDb::recognized(
        &txn,
        set,
        Topic::Sign {
          id: VariantSignId::Cosign(block_number1),
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        }
      ));

      txn.commit();
    }
  }

  #[test]
  fn start_of_block() {
    let _ = env_logger::try_init();
    let set = default_test_validator_set();

    let reattemptable_topics: Vec<Topic> = all_topics()
      .into_iter()
      .filter_map(|t| t.reattempt_topic().map(|(_, reattempt_topic)| reattempt_topic))
      .collect();

    serai_log::log::info!(
      "start_of_block fuzz: reattemptable_topics={reattemptable_topics:?}, \
     all_topics count={}",
      all_topics().len()
    );

    for iteration in 0 .. 100 {
      for topic in all_topics() {
        // Fresh DB per topic so recognized state doesn't leak between iterations
        let mut db = MemDb::new();
        let block_number = random_block_number();
        let mut txn = db.txn();

        // Randomly select which reattempt topics are queued for this block
        let reattempts: Vec<Topic> =
          reattemptable_topics.iter().copied().filter(|_| OsRng.next_u64() % 2 == 0).collect();

        serai_log::log::info!(
          "iteration={iteration}, topic={topic:?}, block_number={block_number}, \
         reattempts={reattempts:?}"
        );

        if !reattempts.is_empty() {
          Reattempt::set(&mut txn, set, block_number, &reattempts);
          serai_log::log::info!("set {} reattempt(s) for block {block_number}", reattempts.len());
        }

        TributaryDb::start_of_block(&mut txn, set, block_number);

        // Verify each queued reattempt topic was recognized and its message sent
        for reattempt in &reattempts {
          assert!(TributaryDb::recognized(&txn, set, *reattempt));
          if reattempt.sign_id(set).is_some() {
            assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
            serai_log::log::info!("verified ProcessorMessage for {reattempt:?}");
          } else if reattempt.dkg_confirmation_sign_id(set).is_some() {
            assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
            serai_log::log::info!("verified DkgConfirmationMessage for {reattempt:?}");
          }
        }

        // When no reattempts were set, verify the current topic's reattempt was not recognized
        if reattempts.is_empty() {
          if let Some((_, reattempt_topic)) = topic.reattempt_topic() {
            assert_eq!(TributaryDb::recognized(&txn, set, reattempt_topic), false);
            serai_log::log::info!("verified {reattempt_topic:?} not recognized (no reattempts)");
          }
        }

        // No extra messages should remain in either queue
        assert!(ProcessorMessages::try_recv(&mut txn, set).is_none());
        assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_none());

        txn.commit();
      }
    }

    serai_log::log::info!("start_of_block fuzz: completed 100 iterations");
  }

  #[test]
  fn fatal_slash() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let validator = random_serai_address(&mut OsRng);

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, validator, "test reason");
      txn.commit();
    }

    assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
    assert_eq!(SlashPoints::get(&db, set, validator), Some(std::u32::MAX));
  }

  mod accumulate {
    use super::*;

    mod accumulate_preceding_topic {
      use super::*;

      /// Set up a DkgConfirmation Share topic (which has a Preprocess preceding topic)
      /// with 3 validators of weight 1 each so `required_participation = 3`.
      fn setup() -> (ExternalValidatorSet, Vec<SeraiAddress>, u16, u16, Topic, Topic, SeraiAddress)
      {
        let set = default_test_validator_set();
        let validators: Vec<SeraiAddress> =
          (0 .. 3).map(|_| random_serai_address(&mut OsRng)).collect();
        let total_weight = 3;

        let share_topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share };
        let preprocess_topic =
          Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };
        assert_eq!(share_topic.preceding_topic(), Some(preprocess_topic));

        let validator = validators[0];
        let validator_weight = 1;
        (set, validators, validator_weight, total_weight, share_topic, preprocess_topic, validator)
      }

      #[test]
      fn no_preceding_data_slashes_validator() {
        let (
          set,
          validators,
          validator_weight,
          total_weight,
          share_topic,
          _preprocess_topic,
          validator,
        ) = setup();
        let mut db = MemDb::new();
        let mut txn = db.txn();

        // Recognize the share topic so the recognition check doesn't slash
        TributaryDb::recognize_topic(&mut txn, set, share_topic);

        // Do NOT store any preceding Preprocess data
        // Validator should be slashed with reason:
        // "participated in topic without participating in prior"
        let result = TributaryDb::accumulate::<[u8; 32]>(
          &mut txn,
          set,
          &validators,
          total_weight,
          random_block_number(),
          share_topic,
          validator,
          validator_weight,
          &random_data_u32(),
        );
        txn.commit();

        assert!(matches!(result, DataSet::None));
        assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
      }

      #[test]
      fn different_type_stored_in_preceding_topic_passes_existence_check() {
        let (
          set,
          validators,
          validator_weight,
          total_weight,
          share_topic,
          preprocess_topic,
          validator,
        ) = setup();
        let mut db = MemDb::new();
        let mut txn = db.txn();

        // Recognize the share topic so the recognition check doesn't slash
        TributaryDb::recognize_topic(&mut txn, set, share_topic);

        // Store preceding preprocess data ([u8; 64])
        Accumulated::<[u8; 64]>::set(
          &mut txn,
          set,
          preprocess_topic,
          validator,
          &random_data_u64(),
        );

        // Accumulate a share ([u8; 32])
        // The preceding check should find the key despite the type mismatch and NOT slash.
        let result = TributaryDb::accumulate::<[u8; 32]>(
          &mut txn,
          set,
          &validators,
          total_weight,
          random_block_number(),
          share_topic,
          validator,
          validator_weight,
          &random_data_u32(),
        );
        txn.commit();

        // Below threshold (1 of 3) so result is None but data is stored
        assert!(matches!(result, DataSet::None));

        assert_eq!(TributaryDb::is_fatally_slashed(&db, set, validator), false);
        assert!(Accumulated::<[u8; 32]>::get(&db, set, share_topic, validator).is_some());
      }

      #[test]
      fn same_type_stored_in_preceding_topic_passes_existence_check() {
        let (
          set,
          validators,
          validator_weight,
          total_weight,
          _share_topic,
          _preprocess_topic,
          validator,
        ) = setup();

        // Sign Share has a Sign Preprocess preceding topic, both use Vec<Vec<u8>> as D
        let txid = random_transaction_id();
        let share_topic = Topic::Sign { id: txid, attempt: 0, round: SigningProtocolRound::Share };
        let preprocess_topic =
          Topic::Sign { id: txid, attempt: 0, round: SigningProtocolRound::Preprocess };
        assert_eq!(share_topic.preceding_topic(), Some(preprocess_topic));

        let mut db = MemDb::new();
        let mut txn = db.txn();

        // Recognize both topics
        TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);
        TributaryDb::recognize_topic(&mut txn, set, share_topic);

        // Store preceding data with the same type as share will use
        let preprocess_data: Vec<Vec<u8>> = vec![vec![1, 2, 3]];
        Accumulated::set(&mut txn, set, preprocess_topic, validator, &preprocess_data);

        let share_data: Vec<Vec<u8>> = vec![vec![4, 5, 6]];
        let result = TributaryDb::accumulate::<Vec<Vec<u8>>>(
          &mut txn,
          set,
          &validators,
          total_weight,
          random_block_number(),
          share_topic,
          validator,
          validator_weight,
          &share_data,
        );
        txn.commit();

        assert!(matches!(result, DataSet::None));
        assert_eq!(
          Accumulated::<Vec<Vec<u8>>>::get(&db, set, share_topic, validator),
          Some(share_data)
        );
        assert!(!TributaryDb::is_fatally_slashed(&db, set, validator));
      }
    }

    mod accumulate_next_attempt_topic {
      use super::*;

      /// Set up a DkgConfirmation Preprocess topic with `attempt = std::u32::MAX` and
      /// with 3 validators of weight 1 each so `required_participation = 3`.
      fn setup() -> (ExternalValidatorSet, Vec<SeraiAddress>, u16, u16, Topic) {
        let set = default_test_validator_set();
        let validators: Vec<SeraiAddress> =
          (0 .. 3).map(|_| random_serai_address(&mut OsRng)).collect();
        let total_weight = 3;
        let validator_weight = 1;

        // what topic is being tested does not alter the functions being tested
        // we are only testing attempt amounts here
        let topic = Topic::DkgConfirmation {
          attempt: std::u32::MAX,
          round: SigningProtocolRound::Preprocess,
        };

        (set, validators, validator_weight, total_weight, topic)
      }

      #[test]
      fn accumulates_normally_despite_overflow() {
        let (set, validators, _validator_weight, total_weight, topic) = setup();
        let mut db = MemDb::new();
        let block_number = random_block_number();

        {
          let mut txn = db.txn();

          // DkgConfirmation with attempt = std::u32::MAX requires recognition
          TributaryDb::recognize_topic(&mut txn, set, topic);

          // Accumulate from all 3 validators to cross threshold
          let result = accumulate_to_threshold(
            &mut txn,
            set,
            &validators,
            total_weight,
            block_number,
            topic,
            Some(|i: usize, result: &DataSet<[u8; 32]>| {
              if i < 2 {
                assert!(matches!(result, DataSet::None));
              } else {
                // Third validator crosses the threshold
                match result {
                  DataSet::Participating(data_set) => assert_eq!(data_set.len(), 3),
                  DataSet::None => panic!("expected Participating after crossing threshold"),
                }
              }
            }),
          );
          assert!(matches!(result, DataSet::Participating(_)));

          // reattempt_topic() wraps attempt std::u32::MAX to 0, so blocks_till_reattempt = 0.
          // A reattempt is queued at block_number itself.
          assert!(Reattempt::get(&txn, set, block_number).is_some());
          // But not at any subsequent block
          for offset in 1 ..= 3 {
            assert!(Reattempt::get(&txn, set, block_number.wrapping_add(offset)).is_none());
          }

          txn.commit();
        }

        for (i, v) in validators.iter().enumerate() {
          assert!(!TributaryDb::is_fatally_slashed(&db, set, *v));
          assert_eq!(Accumulated::<[u8; 32]>::get(&db, set, topic, *v), Some([i as u8; 32]));
        }

        assert_eq!(AccumulatedWeight::get(&db, set, topic), Some(3));
      }

      /// When attempt 0 has already accumulated data, accumulating for attempt std::u32::MAX should be
      /// NOP'd because `next_attempt_topic(std::u32::MAX)` wraps to attempt 0, which already exists.
      #[test]
      fn attempt_max_nopd_when_attempt_zero_exists() {
        let (set, validators, validator_weight, total_weight, topic_max) = setup();
        let topic_0 = topic_max.next_attempt_topic().unwrap();

        assert_eq!(
          topic_0,
          Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
        );

        let mut db = MemDb::new();

        // First: accumulate for attempt 0 (below threshold, just one validator)
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_0);
          let result = TributaryDb::accumulate::<[u8; 32]>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(),
            topic_0,
            validators[0],
            validator_weight,
            &random_data_u32(),
          );
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        // Attempt 0 has accumulated weight
        assert_eq!(AccumulatedWeight::get(&db, set, topic_0), Some(validator_weight));

        // Now try to accumulate for attempt std::u32::MAX
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_max);
          let result = TributaryDb::accumulate::<[u8; 32]>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(),
            topic_max,
            validators[1],
            validator_weight,
            &random_data_u32(),
          );
          // NOP'd: next_attempt_topic(std::u32::MAX) = attempt 0, which already has weight
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        // Attempt std::u32::MAX should have no accumulated data (it was NOP'd)
        assert!(Accumulated::<[u8; 32]>::get(&db, set, topic_max, validators[1]).is_none());
        // Weight for std::u32::MAX stays at initial recognized value (0)
        assert_eq!(AccumulatedWeight::get(&db, set, topic_max), Some(0));
      }

      #[test]
      fn attempt_max_proceeds() {
        let (set, validators, validator_weight, total_weight, topic_max) = setup();
        let topic_0 = topic_max.next_attempt_topic().unwrap();

        let mut db = MemDb::new();

        // First: accumulate for attempt std::u32::MAX (below threshold)
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_max);
          let result = TributaryDb::accumulate::<[u8; 32]>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(),
            topic_max,
            validators[0],
            validator_weight,
            &random_data_u32(),
          );
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        assert_eq!(AccumulatedWeight::get(&db, set, topic_max), Some(validator_weight));

        let data = random_data_u32();

        // Now accumulate for attempt 0
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_0);
          let result = TributaryDb::accumulate::<[u8; 32]>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(),
            topic_0,
            validators[1],
            validator_weight,
            &data,
          );
          // Proceeds: next_attempt_topic(0) = attempt 1, which has no weight
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        // Attempt 0 accumulated successfully
        assert_eq!(Accumulated::<[u8; 32]>::get(&db, set, topic_0, validators[1]), Some(data));
        assert_eq!(AccumulatedWeight::get(&db, set, topic_0), Some(validator_weight));
      }
    }

    mod fuzz {
      use proptest::prelude::*;
      use super::*;

      /// Verify all DB invariants after a single `TributaryDb::accumulate` call.
      ///
      /// Independently computes the expected DB state by tracing the code paths in `accumulate`
      /// based on the inputs and pre-state, then asserts the actual DB matches.
      #[expect(clippy::too_many_arguments)]
      fn verify_accumulate_invariants(
        db: &MemDb,
        set: ExternalValidatorSet,
        total_weight: u16,
        block_number: u64,
        topic: Topic,
        validator: SeraiAddress,
        validator_weight: u16,
        data: &Vec<u8>,
        pre_weight: Option<u16>,
        pre_slashed: bool,
        has_preceding_accumulated: bool,
        has_next_topic_weight: bool,
        validator_in_list: bool,
        result: &DataSet<Vec<u8>>,
      ) {
        let required = required_participation(total_weight);
        let post_slashed = TributaryDb::is_fatally_slashed(db, set, validator);
        let post_weight = AccumulatedWeight::get(db, set, topic);

        // Branch 1: Slash for participating in unrecognized topic requiring recognition.
        if topic.requires_recognition() && pre_weight.is_none() {
          assert!(post_slashed, "should be fatally slashed for unrecognized topic");
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, None, "weight should remain None after recognition slash");
          assert!(
            Accumulated::<Vec<u8>>::get(db, set, topic, validator).is_none(),
            "no data should be stored after recognition slash"
          );
          return;
        }

        let weight_before = pre_weight.unwrap_or(0);

        // Branch 2: Slash for participating without completing the preceding topic.
        if topic.preceding_topic().is_some() && !has_preceding_accumulated {
          assert!(post_slashed, "should be fatally slashed for missing preceding participation");
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, pre_weight, "weight unchanged after preceding slash");
          return;
        }

        // Branch 3: required_participation overflows.
        let Some(required) = required else {
          assert!(matches!(result, DataSet::None));
          assert_eq!(
            post_weight, pre_weight,
            "weight unchanged when required_participation overflows"
          );
          if !pre_slashed {
            assert!(!post_slashed, "should not be slashed on overflow NOP");
          }
          return;
        };

        // Branch 4: Already accumulated past the threshold - NOP.
        if weight_before >= required {
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, pre_weight, "weight unchanged when past threshold");
          if !pre_slashed {
            assert!(!post_slashed, "should not be slashed on threshold NOP");
          }
          return;
        }

        // Branch 5: Old attempt - the next attempt's topic already has weight.
        // Note: pre_weight may be None (topic not yet recognized) which is preserved.
        let next_attempt_superseded = has_next_topic_weight && topic.next_attempt_topic().is_some();
        if next_attempt_superseded {
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, pre_weight, "weight unchanged for superseded attempt");
          if !pre_slashed {
            assert!(!post_slashed, "should not be slashed on superseded NOP");
          }
          return;
        }

        // Accumulation happened (Branches 6 & 7)
        let new_weight = weight_before + validator_weight;
        assert_eq!(post_weight, Some(new_weight), "weight should reflect accumulation");

        if !pre_slashed {
          assert!(!post_slashed, "should not be slashed after valid accumulation");
        }

        if new_weight >= required {
          // Branch 7: Threshold crossed.

          // 7a: Reattempt should be queued if topic is reattemptable.
          if let Some((reattempt_attempt, reattempt_topic)) = topic.reattempt_topic() {
            #[cfg(not(feature = "longer-reattempts"))]
            const BASE_REATTEMPT_DELAY: u32 =
              (5u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);
            #[cfg(feature = "longer-reattempts")]
            const BASE_REATTEMPT_DELAY: u32 =
              (10u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

            let blocks_till = u64::from(reattempt_attempt * BASE_REATTEMPT_DELAY);
            let recognize_at = block_number + blocks_till;

            let queued = Reattempt::get(db, set, recognize_at);
            assert!(queued.is_some(), "reattempt should be queued at block {recognize_at}");
            assert!(
              queued.unwrap().contains(&reattempt_topic),
              "reattempt queue should contain {reattempt_topic:?}"
            );
          }

          // 7b: Succeeding topic should be recognized (weight set to 0).
          if let Some(succeeding) = topic.succeeding_topic() {
            assert_eq!(
              AccumulatedWeight::get(db, set, succeeding),
              Some(0),
              "succeeding topic should be recognized with weight=0"
            );
          }

          // 7c: Accumulated data cleanup depends on whether a reattempt exists.
          // The cleanup loop only iterates the `validators` slice, so data for a validator
          // not in the list is never deleted regardless of reattempt status.
          let has_reattempt = topic.reattempt_topic().is_some();
          if has_reattempt || !validator_in_list {
            assert_eq!(
              Accumulated::<Vec<u8>>::get(db, set, topic, validator),
              Some(data.clone()),
              "data should be preserved (reattempt={has_reattempt}, in_list={validator_in_list})"
            );
          } else {
            assert!(
              Accumulated::<Vec<u8>>::get(db, set, topic, validator).is_none(),
              "data should be cleaned up when no reattempt and validator in list"
            );
          }

          // 7d: Result depends on whether the validator was in the collection list.
          // The collection loop only gathers data from the `validators` slice.
          // `participated` = data_set.contains_key(&validator), which is false when
          // the validator is not in the slice.
          if validator_in_list {
            match result {
              DataSet::Participating(data_set) => {
                assert!(
                  data_set.contains_key(&validator),
                  "validator should be in result data set"
                );
                assert_eq!(
                  data_set.get(&validator).unwrap(),
                  data,
                  "result data should match input"
                );
              }
              DataSet::None => {
                panic!("result should be Participating when threshold crossed by listed validator");
              }
            }
          } else {
            match topic.participating() {
              Participating::Participated => {
                // Validator accumulated but isn't in the list, so participated=false
                assert!(matches!(result, DataSet::None), "Participated + not in list => None");
              }
              Participating::Everyone => {
                // Everyone always returns Participating, but the validator's data won't
                // be in the set (it was only collected from the validators slice)
                match result {
                  DataSet::Participating(data_set) => {
                    assert!(
                      !data_set.contains_key(&validator),
                      "validator not in list should not appear in data set"
                    );
                  }
                  DataSet::None => {
                    panic!("Everyone topics always return Participating");
                  }
                }
              }
            }
          }
        } else {
          // Branch 6: Below threshold - data stored, result is None.
          assert!(matches!(result, DataSet::None), "result should be None when below threshold");
          assert_eq!(
            Accumulated::<Vec<u8>>::get(db, set, topic, validator),
            Some(data.clone()),
            "accumulated data should be stored"
          );
        }
      }

      proptest! {
          #![proptest_config(ProptestConfig::with_cases(1000))]

          #[test]
          fn fuzz_accumulate(
              has_initial_weight in any::<bool>(),
              initial_weight in 0u16..u16::MAX,
              total_weight in 1u16..u16::MAX,

              has_next_topic_weight in any::<bool>(),
              next_topic_initial_weight in 0u16..u16::MAX,

              has_preceding_topic_accumulated in any::<bool>(),

              topic_variant in 0u8..5,
              attempt in 0u32..100,
              round in 0u8..2,
              cosign_block in any::<u64>(),
              batch_id in any::<[u8; 32]>(),
              validator_weight in 1u16..u16::MAX,
              block_number in 1u64..u64::MAX,
              data in prop::collection::vec(any::<u8>(), 0..64),

              num_validators in 1u16..u16::MAX,
              cur_validator in 0u16..u16::MAX,
              validator_in_list in any::<bool>(),
          ) {
              let round =
              if round == 0 { SigningProtocolRound::Preprocess } else { SigningProtocolRound::Share };

              let topic = match topic_variant % 5 {
                  0 => Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
                  1 => Topic::DkgConfirmation { attempt: attempt % 100, round },
                  2 => Topic::SlashReport,
                  3 => Topic::Sign {
                      id: VariantSignId::Cosign(cosign_block),
                      attempt: attempt % 100,
                      round,
                  },
                  _ => {
                      Topic::Sign { id: VariantSignId::Batch(batch_id), attempt: attempt % 100, round }
                  }
              };

              let mut db = MemDb::new();
              let set = default_test_validator_set();

              let validators: Vec<SeraiAddress> =
              (0 .. num_validators).map(|_i| random_serai_address(&mut OsRng)).collect();

              let validator_weight = validator_weight.min(total_weight).max(1);

              let mut txn = db.txn();

              if has_initial_weight {
                  AccumulatedWeight::set(&mut txn, set, topic, &initial_weight);
              }

              if has_next_topic_weight {
                  if let Some(next_attempt_topic) = topic.next_attempt_topic() {
                      AccumulatedWeight::set(&mut txn, set, next_attempt_topic, &next_topic_initial_weight);
                  }
              }

              // When validator_in_list is false, the accumulating validator is an outsider
              // not present in the validators slice. This exercises the `participated = false`
              // branch when the threshold is crossed.
              let cur_validator = (cur_validator as usize) % validators.len();
              let validator = if validator_in_list {
                  validators[cur_validator]
              } else {
                  random_serai_address(&mut OsRng)
              };

              if has_preceding_topic_accumulated {
                  if let Some(preceding_topic) = topic.preceding_topic() {
                      Accumulated::set(&mut txn, set, preceding_topic, validator, &data)
                  }
              }

              let pre_weight = AccumulatedWeight::get(&txn, set, topic);
              let pre_slashed = TributaryDb::is_fatally_slashed(&txn, set, validator);

              let result = TributaryDb::accumulate::<Vec<u8>>(
                  &mut txn,
                  set,
                  &validators,
                  total_weight,
                  block_number,
                  topic,
                  validator,
                  validator_weight,
                  &data,
              );

              txn.commit();

              verify_accumulate_invariants(
                  &db,
                  set,
                  total_weight,
                  block_number,
                  topic,
                  validator,
                  validator_weight,
                  &data,
                  pre_weight,
                  pre_slashed,
                  has_preceding_topic_accumulated,
                  has_next_topic_weight,
                  validator_in_list,
                  &result,
              );
          }
      }
    }
  }
}
