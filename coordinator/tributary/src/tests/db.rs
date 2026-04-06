use rand::{Rng, RngCore, rngs::OsRng};
use messages::sign::{SignId, VariantSignId};

use serai_db::{Db, DbTxn, MemDb};
use serai_primitives::{
  address::SeraiAddress,
  validator_sets::ExternalValidatorSet,
  test_helpers::{
    random_bytes_32, random_bytes_64, random_serai_address, random_block_number,
    default_test_validator_set, random_validator_set, random_vec_u8, random_block_hash,
  },
};

use crate::{
  db::*,
  tests::*,
  transaction::{RoundPayloads, Preprocess, Share, SigningProtocolRound},
};

/// One of each topic kind, and attempts: at 0, a random attempt, and u32::MAX.
fn all_topics_and_attempts() -> Vec<Topic> {
  let random_attempt = OsRng.gen_range(1u32 .. u32::MAX);
  vec![
    // RemoveParticipant
    Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
    // DkgConfirmation Preprocess
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: random_attempt, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Preprocess },
    // DkgConfirmation Share
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share },
    Topic::DkgConfirmation { attempt: random_attempt, round: SigningProtocolRound::Share },
    Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Share },
    // SlashReport
    Topic::SlashReport,
    // Sign Preprocess
    Topic::Sign {
      id: random_transaction_id(),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: random_attempt,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: u32::MAX,
      round: SigningProtocolRound::Preprocess,
    },
    // Sign Share
    Topic::Sign { id: random_transaction_id(), attempt: 0, round: SigningProtocolRound::Share },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: random_attempt,
      round: SigningProtocolRound::Share,
    },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: u32::MAX,
      round: SigningProtocolRound::Share,
    },
  ]
}

/// Share-round topics only, with attempts: at 0, random, and u32::MAX.
fn all_share_topics_and_attempts() -> Vec<Topic> {
  all_topics_and_attempts()
    .into_iter()
    .filter(|t| {
      matches!(
        t,
        Topic::DkgConfirmation { round: SigningProtocolRound::Share, .. } |
          Topic::Sign { round: SigningProtocolRound::Share, .. }
      )
    })
    .collect()
}

/// Preprocess-round topics only, with attempts: at 0, random, and u32::MAX.
fn all_preprocess_topics_and_attempts() -> Vec<Topic> {
  all_topics_and_attempts()
    .into_iter()
    .filter(|t| {
      matches!(
        t,
        Topic::DkgConfirmation { round: SigningProtocolRound::Preprocess, .. } |
          Topic::Sign { round: SigningProtocolRound::Preprocess, .. }
      )
    })
    .collect()
}

type NoEachFn = fn(usize, &DataSet<Share>);

/// Cross threshold by accumulating from all validators, returning the final result.
fn accumulate_to_threshold<D: Borshy, F1, F2>(
  txn: &mut impl DbTxn,
  set: ExternalValidatorSet,
  validators: &[SeraiAddress],
  total_weight: u16,
  block_number: u64,
  topic: Topic,
  make_data: F2,
  mut on_each: Option<F1>,
) -> DataSet<D>
where
  F1: FnMut(usize, &DataSet<D>),
  F2: Fn(usize) -> D,
{
  let mut result = DataSet::None;
  for (i, v) in validators.iter().enumerate() {
    let data = make_data(i);
    result = TributaryDb::accumulate::<D>(
      txn,
      set,
      validators,
      total_weight,
      block_number,
      topic,
      *v,
      1,
      &data,
    );
    if let Some(ref mut f) = on_each {
      f(i, &result);
    }
  }

  result
}

mod required_participation_tests {
  use super::*;

  #[test]
  fn passes() {
    assert_eq!(required_participation(0), 1);

    // No panics
    {
      let random_n = (OsRng.next_u32() as u16) % (u16::MAX / 2);
      let _ = required_participation(random_n);
      let _ = required_participation(u16::MAX / 2);
    }
  }

  #[test]
  #[should_panic = "overflowed"]
  fn panics_on_overflow() {
    // u16::MAX * 2 overflows u16
    required_participation(u16::MAX);
  }
}

mod topic {
  use super::*;

  #[test]
  fn next_attempt_topic() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::DkgConfirmation { attempt, .. } => assert_eq!(
          topic.next_attempt_topic(),
          attempt.checked_add(1).map(|next| Topic::DkgConfirmation {
            attempt: next,
            round: SigningProtocolRound::Preprocess,
          })
        ),
        Topic::Sign { id, attempt, .. } => assert_eq!(
          topic.next_attempt_topic(),
          attempt.checked_add(1).map(|next| Topic::Sign {
            id,
            attempt: next,
            round: SigningProtocolRound::Preprocess
          })
        ),
        _ => assert_eq!(topic.next_attempt_topic(), None),
      }
    }
  }

  #[test]
  fn reattempt_topic() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::DkgConfirmation { attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            attempt.checked_add(1).map(|next| {
              (
                next,
                Topic::DkgConfirmation { attempt: next, round: SigningProtocolRound::Preprocess },
              )
            })
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            attempt.checked_add(1).map(|next| {
              (next, Topic::Sign { id, attempt: next, round: SigningProtocolRound::Preprocess })
            })
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        _ => assert_eq!(topic.reattempt_topic(), None),
      }
    }
  }

  #[test]
  fn sign_id() {
    let set = random_validator_set(&mut OsRng);
    for topic in all_topics_and_attempts() {
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
    let set = random_validator_set(&mut OsRng);
    for topic in all_topics_and_attempts() {
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
  fn preceding_topic() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share } => assert_eq!(
          topic.preceding_topic(),
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess })
        ),
        Topic::Sign { id, attempt, round: SigningProtocolRound::Share } => assert_eq!(
          topic.preceding_topic(),
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess })
        ),
        _ => assert_eq!(topic.preceding_topic(), None),
      }

      // preceding and succeeding should be inverses
      if let Some(preceding) = topic.preceding_topic() {
        assert_eq!(preceding.succeeding_topic(), Some(topic));
      }
      if let Some(succeeding) = topic.succeeding_topic() {
        assert_eq!(succeeding.preceding_topic(), Some(topic));
      }
    }
  }

  #[test]
  fn succeeding_topic() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess } => assert_eq!(
          topic.succeeding_topic(),
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share })
        ),
        Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess } => assert_eq!(
          topic.succeeding_topic(),
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Share })
        ),
        _ => assert_eq!(topic.succeeding_topic(), None),
      }
    }
  }

  #[test]
  fn requires_recognition() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::DkgConfirmation { attempt, .. } => {
          assert_eq!(topic.requires_recognition(), attempt != 0)
        }
        Topic::Sign { .. } => assert_eq!(topic.requires_recognition(), true),
        _ => assert_eq!(topic.requires_recognition(), false),
      }
    }
  }

  #[test]
  fn participating() {
    for topic in all_topics_and_attempts() {
      match topic {
        Topic::RemoveParticipant { .. } | Topic::SlashReport => {
          assert_eq!(topic.participating(), Participating::Everyone)
        }
        Topic::DkgConfirmation { .. } | Topic::Sign { .. } => {
          assert_eq!(topic.participating(), Participating::Participated)
        }
      }
    }
  }
}

mod tributary_db {
  use super::*;

  #[test]
  fn start_and_finish_cosigning() {
    let mut db = MemDb::new();
    let set = random_validator_set(&mut OsRng);
    let block_hash1 = random_block_hash(&mut OsRng);
    let block_number1 = random_block_number(&mut OsRng);

    let expected_topic = expected_topic_after_start_cosigning(VariantSignId::Cosign(block_number1));

    // Recognizes topic
    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number1);
      assert_cosigning_invariants(&mut txn, set, block_hash1, block_number1);
      txn.commit();
    }

    // Same set cannot recognize again until finished
    {
      let mut txn = db.txn();
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash1));

      let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let block_hash2 = random_block_hash(&mut OsRng);
        let block_number2 = random_block_number(&mut OsRng);
        TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      }));

      assert!(retry.is_err());

      // Previous topic still recognized
      assert!(TributaryDb::recognized(&txn, set, expected_topic));

      txn.commit();
    }

    // Finish cosigning
    {
      let mut txn = db.txn();
      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), None);

      // Previous topic remains recognized
      assert!(TributaryDb::recognized(&txn, set, expected_topic));

      txn.commit();
    }

    // Start cosigning new block
    {
      let mut txn = db.txn();
      let block_hash2 = random_block_hash(&mut OsRng);
      let block_number2 = random_block_number(&mut OsRng);

      TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash2));

      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), None);

      // The new topic is now recognized
      assert!(TributaryDb::recognized(
        &txn,
        set,
        expected_topic_after_start_cosigning(VariantSignId::Cosign(block_number2))
      ));
      // Previous topic also remains recognized
      assert!(TributaryDb::recognized(&txn, set, expected_topic));

      txn.commit();
    }
  }

  #[test]
  fn start_of_block() {
    let _ = env_logger::try_init();
    let set = random_validator_set(&mut OsRng);

    let reattemptable_topics: Vec<Topic> = all_topics_and_attempts()
      .into_iter()
      .filter_map(|t| t.reattempt_topic().map(|(_, reattempt_topic)| reattempt_topic))
      .collect();

    serai_env::info!(
      "start_of_block fuzz: reattemptable_topics={reattemptable_topics:?}, \
     all_topics_and_attempts count={}",
      all_topics_and_attempts().len()
    );

    for iteration in 0 .. 100 {
      for topic in all_topics_and_attempts() {
        // Fresh DB per topic so recognized state doesn't leak between iterations
        let mut db = MemDb::new();
        let mut txn = db.txn();
        let block_number = random_block_number(&mut OsRng);

        // Randomly select which reattempt topics are queued for this block
        let reattempts: Vec<Topic> =
          reattemptable_topics.iter().copied().filter(|_| OsRng.next_u64() % 2 == 0).collect();

        serai_env::trace!(
          "iteration={iteration}, topic={topic:?}, block_number={block_number}, \
         reattempts={reattempts:?}"
        );

        if !reattempts.is_empty() {
          Reattempt::set(&mut txn, set, block_number, &reattempts);
          serai_env::trace!("set {} reattempt(s) for block {block_number}", reattempts.len());
        }

        TributaryDb::start_of_block(&mut txn, set, block_number);

        // Verify each queued reattempt topic was recognized and its message sent
        for reattempt in &reattempts {
          assert!(TributaryDb::recognized(&txn, set, *reattempt));
          if reattempt.sign_id(set).is_some() {
            assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
            serai_env::trace!("verified ProcessorMessage for {reattempt:?}");
          } else if reattempt.dkg_confirmation_sign_id(set).is_some() {
            assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
            serai_env::trace!("verified DkgConfirmationMessage for {reattempt:?}");
          }
        }

        // When no reattempts were set, verify the current topic's reattempt was not recognized
        if reattempts.is_empty() {
          if let Some((_, reattempt_topic)) = topic.reattempt_topic() {
            assert_eq!(TributaryDb::recognized(&txn, set, reattempt_topic), false);
            serai_env::trace!("verified {reattempt_topic:?} not recognized (no reattempts)");
          }
        }

        // No extra messages should remain in either queue
        assert!(ProcessorMessages::try_recv(&mut txn, set).is_none());
        assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_none());

        txn.commit();
      }
    }

    serai_env::log::info!("start_of_block fuzz: completed 100 iterations");
  }

  #[test]
  fn fatal_slash() {
    let mut db = MemDb::new();
    let set = random_validator_set(&mut OsRng);
    let validator = random_serai_address(&mut OsRng);

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, validator, "test reason");
      txn.commit();
    }

    assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
    assert_eq!(SlashPoints::get(&db, set, validator), Some(u32::MAX));
  }

  mod accumulate {
    use super::*;

    /// Common test setup: random validator set, 3 validators of weight 1, total_weight = 3.
    fn default_accumulate_setup(
    ) -> (ExternalValidatorSet, SeraiAddress, Vec<SeraiAddress>, u16, u16) {
      let set = random_validator_set(&mut OsRng);
      let (_, validators, _, total_weight) = setup_test_validators_and_weights();
      let validator = validators[0];
      let validator_weight = 1;
      (set, validator, validators, total_weight, validator_weight)
    }

    mod accumulate_preceding_topic {
      use super::*;

      #[test]
      fn no_preceding_data_slashes_validator() {
        for share_topic in all_share_topics_and_attempts() {
          let (set, validator, validators, total_weight, validator_weight) =
            default_accumulate_setup();
          let mut db = MemDb::new();
          let mut txn = db.txn();

          // Recognize the share topic so we reach the preceding-topic check
          if share_topic.requires_recognition() {
            TributaryDb::recognize_topic(&mut txn, set, share_topic);
          }

          // Do not store any preceding Preprocess data
          // Validator should be slashed with reason:
          // "participated in topic without participating in prior"
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            share_topic,
            validator,
            validator_weight,
            &random_bytes_32(&mut OsRng),
          );
          txn.commit();

          assert!(matches!(result, DataSet::None));
          assert!(
            TributaryDb::is_fatally_slashed(&db, set, validator),
            "validator should be slashed for not participating in prior: {share_topic:?}"
          );
        }
      }

      #[test]
      fn preceding_topic_passes_existence_check() {
        // Different types: stores Preprocess, accumulates Share
        for share_topic in all_share_topics_and_attempts() {
          let (set, validator, validators, total_weight, validator_weight) =
            default_accumulate_setup();
          let mut db = MemDb::new();
          let mut txn = db.txn();

          // Recognize the share topic so we reach the preceding-topic check
          if share_topic.requires_recognition() {
            TributaryDb::recognize_topic(&mut txn, set, share_topic);
          }

          // Store preceding preprocess data (Preprocess)
          Accumulated::<Preprocess>::set(
            &mut txn,
            set,
            share_topic.preceding_topic().unwrap(),
            validator,
            &random_bytes_64(&mut OsRng),
          );

          // Accumulate a share (Share)
          // The preceding check should find the key despite the type mismatch and NOT slash.
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            share_topic,
            validator,
            validator_weight,
            &random_bytes_32(&mut OsRng),
          );
          txn.commit();

          assert_eq!(TributaryDb::is_fatally_slashed(&db, set, validator), false);

          // Below threshold (1 of 3) so result is None but data is stored
          assert!(matches!(result, DataSet::None));
          // Confirm data is stored
          assert!(Accumulated::<Share>::get(&db, set, share_topic, validator).is_some());
        }

        // Same types: stores type of RoundPayloads for both Preprocess and Share.
        // Only topics where the preprocess data survives after threshold
        // (reattempt exists).
        for share_topic in all_share_topics_and_attempts()
          .into_iter()
          .filter(|t| t.preceding_topic().unwrap().reattempt_topic().is_some())
        {
          let (set, validator, validators, total_weight, validator_weight) =
            default_accumulate_setup();

          let mut db = MemDb::new();
          let mut txn = db.txn();

          let preprocess_topic = share_topic.preceding_topic().unwrap();

          if preprocess_topic.requires_recognition() {
            TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);
          }

          // Accumulate the preprocess to threshold
          accumulate_to_threshold(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            preprocess_topic,
            |_| vec![random_vec_u8(&mut OsRng)],
            None::<fn(usize, &DataSet<RoundPayloads>)>,
          );

          // Accumulate a share with the same RoundPayloads type
          let share_data: RoundPayloads = vec![random_vec_u8(&mut OsRng)];
          let result = TributaryDb::accumulate::<RoundPayloads>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            share_topic,
            validator,
            validator_weight,
            &share_data,
          );
          txn.commit();

          assert_eq!(
            TributaryDb::is_fatally_slashed(&db, set, validator),
            false,
            "preceding key exists (same type) so validator should not be slashed"
          );
          assert!(matches!(result, DataSet::None), "below threshold (1 of 3)");
          assert_eq!(
            Accumulated::<RoundPayloads>::get(&db, set, share_topic, validator),
            Some(share_data)
          );
        }
      }
    }

    mod accumulate_next_attempt_topic {
      use super::*;

      #[test]
      fn accumulates_to_threshold() {
        for topic in all_preprocess_topics_and_attempts() {
          let (set, _validator, validators, total_weight, _validator_weight) =
            default_accumulate_setup();
          let mut db = MemDb::new();
          let block_number = random_block_number(&mut OsRng);

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }

            let result = accumulate_to_threshold(
              &mut txn,
              set,
              &validators,
              total_weight,
              block_number,
              topic,
              |i| [i as u8; 32],
              Some(|i: usize, result: &DataSet<Share>| {
                if i < 2 {
                  assert!(matches!(result, DataSet::None));
                } else {
                  match result {
                    DataSet::Participating(data_set) => assert_eq!(data_set.len(), 3),
                    DataSet::None => panic!("expected Participating after crossing threshold"),
                  }
                }
              }),
            );
            assert!(matches!(result, DataSet::Participating(_)));

            txn.commit();
          }

          let has_reattempt = topic.reattempt_topic().is_some();

          for v in &validators {
            assert!(!TributaryDb::is_fatally_slashed(&db, set, *v));
            if has_reattempt {
              assert!(
                Accumulated::<Share>::get(&db, set, topic, *v).is_some(),
                "data should be preserved when reattempt exists: {topic:?}"
              );
            } else {
              assert!(
                Accumulated::<Share>::get(&db, set, topic, *v).is_none(),
                "data should be cleaned up when no reattempt: {topic:?}"
              );
            }
          }

          assert_eq!(AccumulatedWeight::get(&db, set, topic), Some(3));
        }
      }

      /// Accumulating for a topic proceeds when the next attempt's topic has no
      /// weight, regardless of whether an unrelated topic already has weight.
      #[test]
      fn not_nopd_without_next_attempt_weight() {
        for topic in all_preprocess_topics_and_attempts() {
          let (set, _validator, validators, total_weight, validator_weight) =
            default_accumulate_setup();

          let mut db = MemDb::new();

          // Accumulate for an unrelated topic so some weight exists in the DB
          let unrelated = Topic::SlashReport;
          {
            let mut txn = db.txn();
            let result = TributaryDb::accumulate::<Share>(
              &mut txn,
              set,
              &validators,
              total_weight,
              random_block_number(&mut OsRng),
              unrelated,
              validators[0],
              validator_weight,
              &random_bytes_32(&mut OsRng),
            );
            assert!(matches!(result, DataSet::None));
            txn.commit();
          }

          assert_eq!(AccumulatedWeight::get(&db, set, unrelated), Some(validator_weight));

          // Accumulating for our topic proceeds (not NOP'd by unrelated weight)
          let data = random_bytes_32(&mut OsRng);
          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }
            let result = TributaryDb::accumulate::<Share>(
              &mut txn,
              set,
              &validators,
              total_weight,
              random_block_number(&mut OsRng),
              topic,
              validators[1],
              validator_weight,
              &data,
            );
            assert!(matches!(result, DataSet::None), "below threshold (1 of 3)");
            txn.commit();
          }

          // Data was stored (not NOP'd)
          assert_eq!(Accumulated::<Share>::get(&db, set, topic, validators[1]), Some(data));
          assert_eq!(AccumulatedWeight::get(&db, set, topic), Some(validator_weight));
        }
      }
    }

    mod accumulate_reattempt_topic {
      use super::*;

      #[test]
      fn data_preserved_or_cleaned_up_based_on_reattempt() {
        for topic in all_preprocess_topics_and_attempts() {
          let (set, _validator, validators, total_weight, _validator_weight) =
            default_accumulate_setup();
          let mut db = MemDb::new();
          let block_number = 1_000_000u64;

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }

            let result = accumulate_to_threshold(
              &mut txn,
              set,
              &validators,
              total_weight,
              block_number,
              topic,
              |i| [i as u8; 32],
              None::<NoEachFn>,
            );
            assert!(matches!(result, DataSet::Participating(_)));
            txn.commit();
          }

          if topic.reattempt_topic().is_some() {
            for (i, v) in validators.iter().enumerate() {
              assert_eq!(
                Accumulated::<Share>::get(&db, set, topic, *v),
                Some([i as u8; 32]),
                "data should be preserved when reattempt exists: {topic:?}"
              );
            }
          } else {
            assert!(
              Reattempt::get(&db, set, block_number).is_none(),
              "no reattempt should be queued: {topic:?}"
            );
            for v in &validators {
              assert!(
                Accumulated::<Share>::get(&db, set, topic, *v).is_none(),
                "data should be cleaned up when no reattempt: {topic:?}"
              );
            }
          }
        }
      }

      /// Reattempt scheduling panics on overflow instead of silently scheduling
      /// at an unreachable block.
      #[test]
      fn reattempt_schedule_panics_on_overflow() {
        let (set, _validator, validators, total_weight, _validator_weight) =
          default_accumulate_setup();

        // attempt just below u32::MAX so reattempt_topic() returns Some(u32::MAX)
        let topic =
          Topic::DkgConfirmation { attempt: u32::MAX - 1, round: SigningProtocolRound::Preprocess };
        assert_eq!(topic.reattempt_topic().unwrap().0, u32::MAX);

        // block_number near u64::MAX forces checked_add to overflow
        let block_number = u64::MAX - 1;

        let mut db = MemDb::new();
        let mut txn = db.txn();
        TributaryDb::recognize_topic(&mut txn, set, topic);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
          accumulate_to_threshold(
            &mut txn,
            set,
            &validators,
            total_weight,
            block_number,
            topic,
            |i| [i as u8; 32],
            None::<NoEachFn>,
          );
        }));

        assert!(result.is_err(), "should panic on reattempt block number overflow");
      }

      #[test]
      fn succeeding_topic_recognized_after_threshold() {
        for topic in all_preprocess_topics_and_attempts() {
          let (set, _validator, validators, total_weight, _validator_weight) =
            default_accumulate_setup();
          let mut db = MemDb::new();

          let succeeding = topic.succeeding_topic().unwrap();

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }
            accumulate_to_threshold(
              &mut txn,
              set,
              &validators,
              total_weight,
              random_block_number(&mut OsRng),
              topic,
              |i| [i as u8; 32],
              None::<NoEachFn>,
            );
            txn.commit();
          }

          assert_eq!(
            AccumulatedWeight::get(&db, set, succeeding),
            Some(0),
            "succeeding topic should be recognized after threshold: {topic:?}"
          );
        }
      }
    }

    /// Tests the invariant documented at fn accumulate:
    /// "This function will only be called once for a (validator, topic) tuple"
    mod duplicate_accumulate {
      use super::*;

      /// Calling accumulate twice for the same (validator, topic) panics,
      /// enforcing the invariant that the nonce system prevents duplicate calls.
      #[test]
      #[should_panic = "accumulate called twice for the same (validator, topic) tuple"]
      fn double_call_before_threshold_panics() {
        let topic = Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) };
        let (set, validator, validators, total_weight, validator_weight) =
          default_accumulate_setup();
        let mut db = MemDb::new();
        let mut txn = db.txn();

        // First call succeeds
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          set,
          &validators,
          total_weight,
          random_block_number(&mut OsRng),
          topic,
          validator,
          validator_weight,
          &vec![1, 2, 3],
        );

        // Second call with same (validator, topic) should panic
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          set,
          &validators,
          total_weight,
          random_block_number(&mut OsRng),
          topic,
          validator,
          validator_weight,
          &vec![4, 5, 6],
        );
      }

      /// After threshold with a reattempt topic, Accumulated entries are
      /// preserved (for the reattempt protocol), so the duplicate assert fires.
      #[test]
      #[should_panic = "accumulate called twice for the same (validator, topic) tuple"]
      fn double_call_after_threshold_with_reattempt_panics() {
        // DkgConfirmation Preprocess has a reattempt topic, so entries survive post-threshold
        let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };
        let (set, _validator, validators, total_weight, _validator_weight) =
          default_accumulate_setup();
        let mut db = MemDb::new();
        let mut txn = db.txn();
        let block_number = random_block_number(&mut OsRng);

        TributaryDb::recognize_topic(&mut txn, set, topic);

        accumulate_to_threshold::<Vec<u8>, _, _>(
          &mut txn,
          set,
          &validators,
          total_weight,
          block_number,
          topic,
          |i| vec![i as u8],
          None::<fn(usize, &DataSet<Vec<u8>>)>,
        );

        // Entries preserved for reattempt, duplicate panics
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          set,
          &validators,
          total_weight,
          block_number,
          topic,
          validators[0],
          1,
          &vec![99],
        );
      }

      /// After threshold without a reattempt topic, Accumulated entries are
      /// cleaned up. The duplicate call does not hit the assertion (key is gone)
      /// and instead falls through to the weight >= threshold NOP.
      #[test]
      fn double_call_after_threshold_without_reattempt_is_nop() {
        // RemoveParticipant has no reattempt, so entries are cleaned up post-threshold
        let topic = Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) };
        let (set, _validator, validators, total_weight, _validator_weight) =
          default_accumulate_setup();
        let mut db = MemDb::new();
        let mut txn = db.txn();
        let block_number = random_block_number(&mut OsRng);

        accumulate_to_threshold::<Vec<u8>, _, _>(
          &mut txn,
          set,
          &validators,
          total_weight,
          block_number,
          topic,
          |i| vec![i as u8],
          None::<fn(usize, &DataSet<Vec<u8>>)>,
        );

        let weight_after_threshold = AccumulatedWeight::get(&txn, set, topic).unwrap();

        // Entry was cleaned up, so assertion doesn't fire.
        // Falls through to the `accumulated_weight >= required_participation` NOP.
        let result = TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          set,
          &validators,
          total_weight,
          block_number,
          topic,
          validators[0],
          1,
          &vec![99],
        );

        assert!(matches!(result, DataSet::None), "should be NOP after threshold");
        assert_eq!(
          AccumulatedWeight::get(&txn, set, topic).unwrap(),
          weight_after_threshold,
          "weight should not change"
        );
      }
    }

    mod fuzz {
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

        // Branch 3: Already accumulated past the threshold - NOP.
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
            let blocks_till = u64::from(reattempt_attempt)
              .checked_mul(u64::from(BASE_REATTEMPT_DELAY))
              .expect("reattempt delay overflowed u64");
            let recognize_at =
              block_number.checked_add(blocks_till).expect("reattempt block number overflowed u64");

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

      #[test]
      fn fuzz_accumulate() {
        for _ in 0 .. 1000 {
          let has_initial_weight = OsRng.gen::<bool>();
          let initial_weight = OsRng.gen_range(0u16 .. u16::MAX);
          let total_weight = OsRng.gen_range(1u16 .. u16::MAX);

          let has_next_topic_weight = OsRng.gen::<bool>();
          let next_topic_initial_weight = OsRng.gen_range(0u16 .. u16::MAX);

          let has_preceding_topic_accumulated = OsRng.gen::<bool>();

          let topic_variant = OsRng.gen_range(0u8 .. 5);
          let attempt = OsRng.gen_range(0u32 .. 100);
          let round = if OsRng.gen::<bool>() {
            SigningProtocolRound::Preprocess
          } else {
            SigningProtocolRound::Share
          };
          let cosign_block = OsRng.next_u64();
          let batch_id: [u8; 32] = OsRng.gen();
          let validator_weight = OsRng.gen_range(1u16 .. u16::MAX);
          let block_number = OsRng.gen_range(1u64 .. u64::MAX);
          let data: Vec<u8> = (0 .. OsRng.gen_range(0usize .. 64)).map(|_| OsRng.gen()).collect();

          let num_validators = OsRng.gen_range(1u16 .. u16::MAX);
          let cur_validator = OsRng.gen_range(0u16 .. u16::MAX);
          let validator_in_list = OsRng.gen::<bool>();

          let topic = match topic_variant % 5 {
            0 => Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
            1 => Topic::DkgConfirmation { attempt: attempt % 100, round },
            2 => Topic::SlashReport,
            3 => {
              Topic::Sign { id: VariantSignId::Cosign(cosign_block), attempt: attempt % 100, round }
            }
            _ => Topic::Sign { id: VariantSignId::Batch(batch_id), attempt: attempt % 100, round },
          };

          let mut db = MemDb::new();
          let set = default_test_validator_set();

          let validators: Vec<SeraiAddress> =
            (0 .. num_validators).map(|_i| random_serai_address(&mut OsRng)).collect();

          let validator_weight = validator_weight.min(total_weight).max(1);

          let db_clone = db.clone();
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

          let catch_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
              &db_clone,
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
          }));

          if let Err(panic) = catch_result {
            let msg = panic
              .downcast_ref::<String>()
              .map(|s| s.as_str())
              .or_else(|| panic.downcast_ref::<&str>().copied())
              .unwrap_or("");
            if msg.contains("overflowed") {
              continue;
            }
            std::panic::resume_unwind(panic);
          }
        }
      }
    }
  }
}
