use rand::{RngCore, rngs::OsRng};

use messages::sign::VariantSignId;

use serai_db::{Db, DbTxn, MemDb};
use serai_primitives::{
  address::SeraiAddress,
  validator_sets::ExternalValidatorSet,
  test_helpers::{
    random_bytes_32, random_bytes_64, random_serai_address, random_block_number,
    default_test_validator_set, random_validator_set, random_vec_u8,
  },
};

use crate::{
  db::*,
  tests::random_transaction_id,
  transaction::{GenericDataset, Preprocess, Share, SigningProtocolRound},
};

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

/// A random Share topic that has a preceding Preprocess topic.
fn random_share_topic_with_preceding() -> Topic {
  if OsRng.next_u64() % 2 == 0 {
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share }
  } else {
    Topic::Sign { id: random_transaction_id(), attempt: 0, round: SigningProtocolRound::Share }
  }
}

/// A random topic with `attempt = u32::MAX` and `round = Preprocess` that has
/// `reattempt_topic()` and `next_attempt_topic()` returning `Some`.
fn random_reattemptable_topic_at_max_attempt() -> Topic {
  if OsRng.next_u64() % 2 == 0 {
    Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Preprocess }
  } else {
    Topic::Sign {
      id: random_transaction_id(),
      attempt: u32::MAX,
      round: SigningProtocolRound::Preprocess,
    }
  }
}

fn all_topics_at_max_attempts() -> Vec<Topic> {
  vec![
    Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
    Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Share },
    Topic::SlashReport,
    Topic::Sign {
      id: random_transaction_id(),
      attempt: u32::MAX,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: random_transaction_id(),
      attempt: u32::MAX,
      round: SigningProtocolRound::Share,
    },
  ]
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

#[test]
fn required_participation() {
  use crate::db::required_participation;

  assert_eq!(required_participation(0), Ok(1));
  // Random value within non-overflow range
  let random_n = (OsRng.next_u32() as u16) % (u16::MAX / 2);
  assert_eq!(required_participation(random_n), Ok(random_n * 2 / 3 + 1));

  assert!(required_participation(u16::MAX / 2).is_ok());
  assert!(required_participation(u16::MAX / 2 + 1).is_err());
  assert!(required_participation(u16::MAX).is_err());
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

    for topic in all_topics_at_max_attempts() {
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

    for topic in all_topics_at_max_attempts() {
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
    let set = random_validator_set(&mut OsRng);
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
    let set = random_validator_set(&mut OsRng);
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
  fn preceding_topic() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.preceding_topic(), None),
        Topic::DkgConfirmation { attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(topic.preceding_topic(), None),
          SigningProtocolRound::Share => assert_eq!(
            topic.preceding_topic(),
            Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess })
          ),
        },
        Topic::SlashReport => assert_eq!(topic.preceding_topic(), None),
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(topic.preceding_topic(), None),
          SigningProtocolRound::Share => assert_eq!(
            topic.preceding_topic(),
            Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess })
          ),
        },
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
  use serai_primitives::test_helpers::random_block_hash;
  use super::*;

  #[test]
  fn start_and_finish_cosigning() {
    let mut db = MemDb::new();
    let set = random_validator_set(&mut OsRng);
    let block_hash1 = random_block_hash(&mut OsRng);
    let block_number1 = random_block_number(&mut OsRng);

    let expected_topic = Topic::Sign {
      id: VariantSignId::Cosign(block_number1),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    };

    // Recognizes topic
    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number1);
      assert!(TributaryDb::try_recv_topic_requiring_recognition(&mut txn, set).is_some());
      assert!(TributaryDb::recognized(&txn, set, expected_topic));
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
        Topic::Sign {
          id: VariantSignId::Cosign(block_number2),
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        }
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

    let reattemptable_topics: Vec<Topic> = all_topics()
      .into_iter()
      .filter_map(|t| t.reattempt_topic().map(|(_, reattempt_topic)| reattempt_topic))
      .collect();

    serai_env::info!(
      "start_of_block fuzz: reattemptable_topics={reattemptable_topics:?}, \
     all_topics count={}",
      all_topics().len()
    );

    for iteration in 0 .. 100 {
      for topic in all_topics() {
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
      let validators: Vec<SeraiAddress> =
        (0 .. 3).map(|_| random_serai_address(&mut OsRng)).collect();
      let validator = validators[0];
      let total_weight = 3;
      let validator_weight = 1;
      (set, validator, validators, total_weight, validator_weight)
    }

    mod accumulate_preceding_topic {

      use super::*;

      /// Set up a random Share topic (which requires participation in a preceding
      /// Preprocess topic) with 3 validators of weight 1 each.
      fn setup() -> (ExternalValidatorSet, SeraiAddress, Vec<SeraiAddress>, u16, u16, Topic) {
        let (set, validator, validators, total_weight, validator_weight) =
          default_accumulate_setup();
        let share_topic = random_share_topic_with_preceding();
        (set, validator, validators, total_weight, validator_weight, share_topic)
      }

      #[test]
      fn no_preceding_data_slashes_validator() {
        let (set, validator, validators, total_weight, validator_weight, share_topic) = setup();
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
        assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
      }

      #[test]
      fn preceding_topic_passes_existence_check() {
        // Different types: DkgConfirmation stores Preprocess, accumulates Share
        {
          let (set, validator, validators, total_weight, validator_weight, share_topic) = setup();
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

        // Same types: Sign stores GenericDataset for both preprocess and share
        {
          let (set, validator, validators, total_weight, validator_weight, share_topic) = setup();

          let mut db = MemDb::new();
          let mut txn = db.txn();

          let preprocess_topic = share_topic.preceding_topic().unwrap();

          // Recognize and accumulate the preprocess to threshold
          accumulate_to_threshold(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            preprocess_topic,
            |_| vec![random_vec_u8(&mut OsRng)],
            None::<fn(usize, &DataSet<GenericDataset>)>,
          );

          // Accumulate a share with the same GenericDataset type
          let share_data: GenericDataset = vec![random_vec_u8(&mut OsRng)];
          let result = TributaryDb::accumulate::<GenericDataset>(
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
            Accumulated::<GenericDataset>::get(&db, set, share_topic, validator),
            Some(share_data)
          );
        }
      }
    }

    mod accumulate_next_attempt_topic {
      use super::*;

      /// Set up a random reattemptable topic with `attempt = u32::MAX`.
      fn setup() -> (ExternalValidatorSet, SeraiAddress, Vec<SeraiAddress>, u16, u16, Topic) {
        let (set, validator, validators, total_weight, validator_weight) =
          default_accumulate_setup();
        let topic = random_reattemptable_topic_at_max_attempt();
        (set, validator, validators, total_weight, validator_weight, topic)
      }

      #[test]
      fn accumulates_normally_despite_overflow() {
        let (set, _validator, validators, total_weight, _validator_weight, topic) = setup();
        let mut db = MemDb::new();
        let block_number = random_block_number(&mut OsRng);

        {
          let mut txn = db.txn();

          // DkgConfirmation with attempt = u32::MAX requires recognition
          TributaryDb::recognize_topic(&mut txn, set, topic);

          // Accumulate from all 3 validators to cross threshold
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
                // Third validator crosses the threshold
                match result {
                  DataSet::Participating(data_set) => assert_eq!(data_set.len(), 3),
                  DataSet::None => panic!("expected Participating after crossing threshold"),
                }
              }
            }),
          );
          assert!(matches!(result, DataSet::Participating(_)));

          // reattempt_topic() wraps attempt u32::MAX to 0, so blocks_till_reattempt = 0.
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
          assert_eq!(Accumulated::<Share>::get(&db, set, topic, *v), Some([i as u8; 32]));
        }

        assert_eq!(AccumulatedWeight::get(&db, set, topic), Some(3));
      }

      /// When attempt 0 has already accumulated data, accumulating for attempt u32::MAX should be
      /// NOP'd because `next_attempt_topic(u32::MAX)` wraps to attempt 0, which already exists.
      #[test]
      fn attempt_max_nopd_when_attempt_zero_exists() {
        let (set, _validator, validators, total_weight, validator_weight, topic_max) = setup();
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
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            topic_0,
            validators[0],
            validator_weight,
            &random_bytes_32(&mut OsRng),
          );
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        // Attempt 0 has accumulated weight
        assert_eq!(AccumulatedWeight::get(&db, set, topic_0), Some(validator_weight));

        // Now try to accumulate for attempt u32::MAX
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_max);
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            topic_max,
            validators[1],
            validator_weight,
            &random_bytes_32(&mut OsRng),
          );
          // NOP'd: next_attempt_topic(u32::MAX) = attempt 0, which already has weight
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        // Attempt u32::MAX should have no accumulated data (it was NOP'd)
        assert!(Accumulated::<Share>::get(&db, set, topic_max, validators[1]).is_none());
        // Weight for u32::MAX stays at initial recognized value (0)
        assert_eq!(AccumulatedWeight::get(&db, set, topic_max), Some(0));
      }

      #[test]
      fn attempt_max_proceeds() {
        let (set, _validator, validators, total_weight, validator_weight, topic_max) = setup();
        let topic_0 = topic_max.next_attempt_topic().unwrap();

        let mut db = MemDb::new();

        // First: accumulate for attempt u32::MAX (below threshold)
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_max);
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
            topic_max,
            validators[0],
            validator_weight,
            &random_bytes_32(&mut OsRng),
          );
          assert!(matches!(result, DataSet::None));
          txn.commit();
        }

        assert_eq!(AccumulatedWeight::get(&db, set, topic_max), Some(validator_weight));

        let data = random_bytes_32(&mut OsRng);

        // Now accumulate for attempt 0
        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic_0);
          let result = TributaryDb::accumulate::<Share>(
            &mut txn,
            set,
            &validators,
            total_weight,
            random_block_number(&mut OsRng),
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
        assert_eq!(Accumulated::<Share>::get(&db, set, topic_0, validators[1]), Some(data));
        assert_eq!(AccumulatedWeight::get(&db, set, topic_0), Some(validator_weight));
      }
    }

    mod accumulate_reattempt_topic {
      use super::*;

      /// Set up a random reattemptable topic with `attempt = u32::MAX`.
      fn setup() -> (ExternalValidatorSet, SeraiAddress, Vec<SeraiAddress>, u16, u16, Topic) {
        let (set, validator, validators, total_weight, validator_weight) =
          default_accumulate_setup();
        let topic = random_reattemptable_topic_at_max_attempt();
        (set, validator, validators, total_weight, validator_weight, topic)
      }

      #[test]
      fn reattempt_wraps_to_zero_on_overflow() {
        let (set, _validator, validators, total_weight, _validator_weight, topic) = setup();
        let mut db = MemDb::new();
        let block_number = 1_000_000u64;

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);

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

        // Overflow wraps attempt to 0, so blocks_till_reattempt = 0 * BASE_DELAY = 0.
        // Reattempt is queued at block_number itself.
        assert!(Reattempt::get(&db, set, block_number).is_some());
        // But not at any subsequent block
        assert!(Reattempt::get(&db, set, block_number + 1).is_none());
      }

      #[test]
      fn data_preserved_when_overflow_wraps() {
        let (set, _validator, validators, total_weight, _validator_weight, topic) = setup();
        let mut db = MemDb::new();

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);
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

        // reattempt_topic() wraps to attempt 0, so data is preserved for the reattempt
        for (i, v) in validators.iter().enumerate() {
          assert_eq!(Accumulated::<Share>::get(&db, set, topic, *v), Some([i as u8; 32]));
        }
      }

      #[test]
      fn data_preserved_with_normal_attempt() {
        let set = default_test_validator_set();
        let validators: Vec<SeraiAddress> =
          (0 .. 3).map(|_| random_serai_address(&mut OsRng)).collect();
        let total_weight = 3;

        // attempt = 0 so reattempt_topic() returns Some
        let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };
        assert!(topic.reattempt_topic().is_some());

        let mut db = MemDb::new();

        {
          let mut txn = db.txn();
          // attempt 0 Preprocess doesn't require recognition
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

        // reattempt_topic() is Some, so data is preserved for the reattempt
        for (i, v) in validators.iter().enumerate() {
          assert_eq!(Accumulated::<Share>::get(&db, set, topic, *v), Some([i as u8; 32]),);
        }
      }

      #[test]
      fn succeeding_topic_recognized_with_overflow_wrap() {
        let (set, _validator, validators, total_weight, _validator_weight, topic) = setup();
        let mut db = MemDb::new();

        let succeeding = topic.succeeding_topic().unwrap();
        assert_eq!(
          succeeding,
          Topic::DkgConfirmation { attempt: u32::MAX, round: SigningProtocolRound::Share }
        );

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);
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

        // The succeeding topic is recognized
        assert_eq!(AccumulatedWeight::get(&db, set, succeeding), Some(0));
      }

      #[test]
      fn sign_topic_reattempt_wraps_on_overflow() {
        let set = default_test_validator_set();
        let validators: Vec<SeraiAddress> =
          (0 .. 3).map(|_| random_serai_address(&mut OsRng)).collect();
        let total_weight = 3;
        let block_number = 500_000u64;

        let topic = Topic::Sign {
          id: VariantSignId::Cosign(42),
          attempt: u32::MAX,
          round: SigningProtocolRound::Preprocess,
        };
        // Overflow wraps to attempt 0
        assert_eq!(
          topic.reattempt_topic(),
          Some((
            0,
            Topic::Sign {
              id: VariantSignId::Cosign(42),
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
            }
          ))
        );

        let mut db = MemDb::new();

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);
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
          txn.commit();
        }

        // Reattempt queued at block_number (delay = 0 for attempt 0)
        assert!(Reattempt::get(&db, set, block_number).is_some());
        for offset in 1 ..= 2000 {
          assert!(Reattempt::get(&db, set, block_number + offset).is_none());
        }

        // Data preserved for reattempt
        for (i, v) in validators.iter().enumerate() {
          assert_eq!(Accumulated::<Share>::get(&db, set, topic, *v), Some([i as u8; 32]));
        }

        // Succeeding topic (Share) still recognized
        let succeeding = topic.succeeding_topic().unwrap();
        assert_eq!(AccumulatedWeight::get(&db, set, succeeding), Some(0));
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
        let required = crate::db::required_participation(total_weight);
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
        let Ok(required) = required else {
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
