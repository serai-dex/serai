use rand::{Rng as _, RngCore, CryptoRng};

use serai_primitives::{
  test_helpers::{random_bytes, random_block_hash, random_external_validator_set, random_vec_u8},
};
use serai_tributary_types::test_helpers::u16_to_participant;

use messages::sign::{SignId, VariantSignId};
use serai_db::{Db as _, DbTxn, MemDb};
use crate::{
  transaction::SigningProtocolRound,
  db::{*, ProcessorMessages, DkgConfirmationMessages},
  tests::*,
};

fn capped_block_number<R: RngCore + CryptoRng>(rng: &mut R) -> u64 {
  rng.gen_range(0u64 .. u64::MAX / u64::from(BASE_REATTEMPT_DELAY))
}

/// One of each topic kind, and attempts: at 0 and a random attempt.
fn all_topics_and_attempts<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Topic> {
  // Cap the random attempt `attempt * BASE_REATTEMPT_DELAY` cannot overflow. The dedicated
  // `reattempt_schedule_panics_on_overflow` test exercises the overflow path explicitly.
  let max_attempt = u64::MAX / u64::from(BASE_REATTEMPT_DELAY);
  let random_attempt = rng.gen_range(1u64 .. max_attempt);
  vec![
    // RemoveParticipant
    Topic::RemoveParticipant { participant: random_participant(rng) },
    // DkgConfirmation Preprocess
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: random_attempt, round: SigningProtocolRound::Preprocess },
    // DkgConfirmation Share
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share },
    Topic::DkgConfirmation { attempt: random_attempt, round: SigningProtocolRound::Share },
    // SlashReport
    Topic::SlashReport,
    // Sign Preprocess
    Topic::Sign {
      id: random_variant_sign_id(rng),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: random_variant_sign_id(rng),
      attempt: random_attempt,
      round: SigningProtocolRound::Preprocess,
    },
    // Sign Share
    Topic::Sign { id: random_variant_sign_id(rng), attempt: 0, round: SigningProtocolRound::Share },
    Topic::Sign {
      id: random_variant_sign_id(rng),
      attempt: random_attempt,
      round: SigningProtocolRound::Share,
    },
  ]
}

/// Share-round topics only, with attempts: at 0 and random.
fn all_share_topics_and_attempts<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Topic> {
  all_topics_and_attempts(rng)
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

/// Preprocess-round topics only, with attempts: at 0 and random.
fn all_preprocess_topics_and_attempts<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Topic> {
  all_topics_and_attempts(rng)
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

type NoEachFn = fn(usize, &DataSet<[u8; 32]>);

/// Cross threshold by accumulating from all validators, returning the final result.
fn accumulate_all_participants<D: Borshy, F1, F2>(
  txn: &mut impl DbTxn,
  tributary_validator_set_info: &TributaryValidatorSetInfo,
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
  for (participant, _) in
    tributary_validator_set_info.tributary_validator_set.consensus_participants()
  {
    let i = usize::from(u16::from(participant));
    let data = make_data(i);
    result = TributaryDb::accumulate::<D>(
      txn,
      tributary_validator_set_info,
      block_number,
      topic,
      participant,
      &data,
    );
    if let Some(f) = &mut on_each {
      f(i, &result);
    }
  }

  result
}

mod topic {
  use super::*;

  #[test]
  fn next_attempt_topic() {
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
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
        Topic::RemoveParticipant { .. } | Topic::SlashReport => {
          assert_eq!(topic.next_attempt_topic(), None);
        }
      }
    }
  }

  #[test]
  fn reattempt_topic() {
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::DkgConfirmation { attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            Some((
              attempt + 1,
              Topic::DkgConfirmation {
                attempt: attempt + 1,
                round: SigningProtocolRound::Preprocess
              },
            ))
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => assert_eq!(
            topic.reattempt_topic(),
            Some((
              attempt + 1,
              Topic::Sign { id, attempt: attempt + 1, round: SigningProtocolRound::Preprocess }
            ))
          ),
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::RemoveParticipant { .. } | Topic::SlashReport => {
          assert_eq!(topic.reattempt_topic(), None);
        }
      }
    }
  }

  #[test]
  fn sign_id() {
    let mut rng = new_test_rng();
    let set = random_external_validator_set(&mut rng);
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::Sign { id, attempt, round: _ } => {
          assert_eq!(topic.sign_id(set), Some(SignId { session: set.session, id, attempt }));
        }
        Topic::RemoveParticipant { .. } | Topic::DkgConfirmation { .. } | Topic::SlashReport => {
          assert_eq!(topic.sign_id(set), None);
        }
      }
    }
  }

  #[test]
  fn dkg_confirmation_sign_id() {
    let mut rng = new_test_rng();
    let set = random_external_validator_set(&mut rng);
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::DkgConfirmation { attempt, round: _ } => {
          assert_eq!(
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
          );
        }
        Topic::RemoveParticipant { .. } | Topic::SlashReport | Topic::Sign { .. } => {
          assert_eq!(topic.dkg_confirmation_sign_id(set), None);
        }
      }
    }
  }

  #[test]
  fn preceding_topic() {
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share } => assert_eq!(
          topic.preceding_topic(),
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess })
        ),
        Topic::Sign { id, attempt, round: SigningProtocolRound::Share } => assert_eq!(
          topic.preceding_topic(),
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess })
        ),
        Topic::RemoveParticipant { .. } |
        Topic::DkgConfirmation { round: SigningProtocolRound::Preprocess, .. } |
        Topic::SlashReport |
        Topic::Sign { round: SigningProtocolRound::Preprocess, .. } => {
          assert_eq!(topic.preceding_topic(), None);
        }
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
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess } => assert_eq!(
          topic.succeeding_topic(),
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share })
        ),
        Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess } => assert_eq!(
          topic.succeeding_topic(),
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Share })
        ),
        Topic::RemoveParticipant { .. } |
        Topic::DkgConfirmation { round: SigningProtocolRound::Share, .. } |
        Topic::SlashReport |
        Topic::Sign { round: SigningProtocolRound::Share, .. } => {
          assert_eq!(topic.succeeding_topic(), None);
        }
      }
    }
  }

  #[test]
  fn requires_recognition() {
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::DkgConfirmation { attempt, .. } => {
          assert_eq!(topic.requires_recognition(), attempt != 0);
        }
        Topic::Sign { .. } => assert!(topic.requires_recognition()),
        Topic::RemoveParticipant { .. } | Topic::SlashReport => {
          assert!(!topic.requires_recognition());
        }
      }
    }
  }

  #[test]
  fn participating() {
    let mut rng = new_test_rng();
    for topic in all_topics_and_attempts(&mut rng) {
      match topic {
        Topic::RemoveParticipant { .. } | Topic::SlashReport => {
          assert_eq!(topic.participating(), Participating::Everyone);
        }
        Topic::DkgConfirmation { .. } | Topic::Sign { .. } => {
          assert_eq!(topic.participating(), Participating::Participated);
        }
      }
    }
  }
}

mod tributary_db {
  use super::*;

  #[test]
  fn start_and_finish_cosigning() {
    let mut rng = new_test_rng();
    let mut db = MemDb::new();
    let set = random_external_validator_set(&mut rng);
    let block_hash1 = random_block_hash(&mut rng);
    let block_number1 = rng.next_u64();

    let expected_topic = initial_sign_topic(VariantSignId::Cosign(block_number1));

    // Recognizes topic
    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number1);
      assert_start_cosigning_invariants(&mut txn, set, block_hash1, block_number1);
      txn.commit();
    }

    // Same set cannot recognize again until finished
    {
      let mut txn = db.txn();
      assert_eq!(ActivelyCosigningHash::get(&txn, set), Some(block_hash1));

      let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let block_hash2 = random_block_hash(&mut rng);
        let block_number2 = rng.next_u64();
        TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      }));

      assert!(retry.is_err());

      // Previous topic still recognized
      assert!(TributaryDb::is_topic_recognized(&txn, set, expected_topic));
    }

    // Finish cosigning
    {
      let mut txn = db.txn();
      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigningHash::get(&txn, set), None);

      // Previous topic remains recognized
      assert!(TributaryDb::is_topic_recognized(&txn, set, expected_topic));

      txn.commit();
    }

    // Start cosigning new block
    {
      let mut txn = db.txn();
      let block_hash2 = random_block_hash(&mut rng);
      let block_number2 = rng.next_u64();

      TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      assert_eq!(ActivelyCosigningHash::get(&txn, set), Some(block_hash2));

      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigningHash::get(&txn, set), None);

      // The new topic is now recognized
      assert!(TributaryDb::is_topic_recognized(
        &txn,
        set,
        initial_sign_topic(VariantSignId::Cosign(block_number2))
      ));
      // Previous topic also remains recognized
      assert!(TributaryDb::is_topic_recognized(&txn, set, expected_topic));

      txn.commit();
    }
  }

  #[test]
  fn start_of_block() {
    let mut rng = new_test_rng();
    let set = random_external_validator_set(&mut rng);

    let reattemptable_topics: Vec<Topic> = all_topics_and_attempts(&mut rng)
      .into_iter()
      .filter_map(|t| t.reattempt_topic().map(|(_, reattempt_topic)| reattempt_topic))
      .collect();

    serai_env::info!(
      "start_of_block fuzz: reattemptable_topics={reattemptable_topics:?}, \
     all_topics_and_attempts count={}",
      all_topics_and_attempts(&mut rng).len()
    );

    for iteration in 0 .. 100 {
      for topic in all_topics_and_attempts(&mut rng) {
        // Fresh DB per topic so recognized state doesn't leak between iterations
        let mut db = MemDb::new();
        let mut txn = db.txn();
        let block_number = rng.next_u64();

        // Randomly select which reattempt topics are queued for this block
        let reattempts: Vec<Topic> =
          reattemptable_topics.iter().copied().filter(|_| rng.next_u64() % 2 == 0).collect();

        serai_env::trace!(
          "iteration={iteration}, topic={topic:?}, block_number={block_number}, \
         reattempts={reattempts:?}"
        );

        if !reattempts.is_empty() {
          BlocksReattemptTopics::set(&mut txn, set, block_number, &reattempts);
          serai_env::trace!("set {} reattempt(s) for block {block_number}", reattempts.len());
        }

        TributaryDb::start_of_block(&mut txn, set, block_number);

        // Verify each queued reattempt topic was recognized and its message sent
        for reattempt in &reattempts {
          assert!(TributaryDb::is_topic_recognized(&txn, set, *reattempt));
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
            assert!(!TributaryDb::is_topic_recognized(&txn, set, reattempt_topic));
            serai_env::trace!("verified {reattempt_topic:?} not recognized (no reattempts)");
          }
        }

        // No extra messages should remain in either queue
        assert_no_pending_messages(&mut txn, set);

        txn.commit();
      }
    }

    serai_env::info!("start_of_block fuzz: completed 100 iterations");
  }

  #[test]
  fn fatal_slash() {
    let mut rng = new_test_rng();
    let mut db = MemDb::new();
    let set = random_external_validator_set(&mut rng);
    let participant = random_participant(&mut rng);

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, participant, "test reason");
      txn.commit();
    }

    assert!(TributaryDb::is_fatally_slashed(&db, set, participant));
    assert_eq!(ParticipantTributarySlashPoints::get(&db, set, participant), Some(u32::MAX));
  }

  mod accumulate {
    use super::*;

    mod accumulate_preceding_topic {
      use super::*;

      #[test]
      fn no_preceding_preprocess_slashes_share_participant() {
        let mut rng = new_test_rng();
        for share_topic in all_share_topics_and_attempts(&mut rng) {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;
          let mut db = MemDb::new();
          let mut txn = db.txn();

          // Recognize the share topic so we reach the preceding-topic check
          if share_topic.requires_recognition() {
            TributaryDb::recognize_topic(&mut txn, set, share_topic);
          }

          // Do not store any preceding Preprocess data
          // Validator should be slashed with reason:
          // "participated in topic without participating in prior"
          let first_participant = u16_to_participant(1);
          let result = TributaryDb::accumulate::<[u8; 32]>(
            &mut txn,
            &tributary_validator_set_info,
            rng.next_u64(),
            share_topic,
            first_participant,
            &random_bytes(&mut rng),
          );
          txn.commit();

          assert!(matches!(result, DataSet::None));
          assert!(
            TributaryDb::is_fatally_slashed(&db, set, first_participant),
            "validator should be slashed for not participating in prior: {share_topic:?}"
          );
        }
      }

      #[test]
      fn preceding_topic_passes_existence_check() {
        let mut rng = new_test_rng();
        // Different types: stores Preprocess, accumulates Share
        {
          for share_topic in all_share_topics_and_attempts(&mut rng) {
            let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
            let set = tributary_validator_set_info.set;
            let mut db = MemDb::new();

            // Recognize the share topic so we reach the preceding-topic check
            if share_topic.requires_recognition() {
              let mut txn = db.txn();
              TributaryDb::recognize_topic(&mut txn, set, share_topic);
              txn.commit();
            }

            // Store preceding preprocess data
            {
              let mut txn = db.txn();
              let preceding_topic = share_topic.preceding_topic().unwrap();
              let first_participant = u16_to_participant(1);
              TopicsParticipantAccumulatedEntries::<[u8; 64]>::set(
                &mut txn,
                set,
                preceding_topic,
                first_participant,
                &random_bytes(&mut rng),
              );
              txn.commit();
            }

            let mut txn = db.txn();

            // Accumulate a share
            // The preceding topic check should find the stored preprocess dataset as a
            // `TopicsParticipantAccumulatedEntries`, despite the new data being a different type
            // (prev: [u8; 64], now: [u8; 32]), and not slash the valid participation.
            let first_participant = u16_to_participant(1);
            let result = TributaryDb::accumulate::<[u8; 32]>(
              &mut txn,
              &tributary_validator_set_info,
              rng.next_u64(),
              share_topic,
              first_participant,
              &random_bytes(&mut rng),
            );
            txn.commit();

            assert!(!TributaryDb::is_fatally_slashed(&db, set, first_participant));

            // Below threshold (only 1 of 3 accumulated) so result is None but data is stored
            assert!(matches!(result, DataSet::None));
            // Confirm data is stored
            assert!(TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(
              &db,
              set,
              share_topic,
              first_participant
            )
            .is_some());
          }
        }

        // Same types: stores type of Vec<Vec<u8>> for both Preprocess and Share.
        // Only topics where the preprocess data survives after threshold
        // (= reattempt exists).
        for share_topic in all_share_topics_and_attempts(&mut rng)
          .into_iter()
          .filter(|t| t.preceding_topic().unwrap().reattempt_topic().is_some())
        {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;

          let mut db = MemDb::new();

          let preprocess_topic = share_topic.preceding_topic().unwrap();

          if preprocess_topic.requires_recognition() {
            let mut txn = db.txn();
            TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);
            txn.commit();
          }

          // The share topic may also require recognition (e.g. attempt != 0)
          if share_topic.requires_recognition() {
            let mut txn = db.txn();
            TributaryDb::recognize_topic(&mut txn, set, share_topic);
            txn.commit();
          }

          // Store preceding preprocess data
          {
            let mut txn = db.txn();
            let preceding_topic = share_topic.preceding_topic().unwrap();
            let first_participant = u16_to_participant(1);
            TopicsParticipantAccumulatedEntries::set(
              &mut txn,
              set,
              preceding_topic,
              first_participant,
              &vec![random_vec_u8(&mut rng, 0 ..= 128)],
            );
            txn.commit();
          }

          let mut txn = db.txn();

          // Accumulate a share with the same Vec<Vec<u8>> type
          let share_data: Vec<Vec<u8>> = vec![random_vec_u8(&mut rng, 0 ..= 128)];
          let first_participant = u16_to_participant(1);
          let result = TributaryDb::accumulate::<Vec<Vec<u8>>>(
            &mut txn,
            &tributary_validator_set_info,
            rng.next_u64(),
            share_topic,
            first_participant,
            &share_data,
          );
          txn.commit();

          assert!(
            !TributaryDb::is_fatally_slashed(&db, set, first_participant),
            "preceding key exists (same type) so validator should not be slashed"
          );
          // Below threshold (only 1 of 3 accumulated) so result is None but data is stored
          assert!(matches!(result, DataSet::None));
          // Confirm data is stored
          assert_eq!(
            TopicsParticipantAccumulatedEntries::<Vec<Vec<u8>>>::get(
              &db,
              set,
              share_topic,
              first_participant
            ),
            Some(share_data)
          );
        }
      }
    }

    mod accumulate_next_attempt_topic {
      use super::*;

      #[test]
      fn accumulates_to_threshold() {
        let mut rng = new_test_rng();
        for topic in all_preprocess_topics_and_attempts(&mut rng) {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;
          let mut db = MemDb::new();
          // Cap `block_number` so `block_number + blocks_till_reattempt` cannot overflow.
          // `reattempt_schedule_panics_on_overflow` exercises the overflow path explicitly.
          let block_number = capped_block_number(&mut rng);

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }

            let mut saw_participating = false;
            accumulate_all_participants(
              &mut txn,
              &tributary_validator_set_info,
              block_number,
              topic,
              |i| [u8::try_from(i).unwrap(); 32],
              Some(|i: usize, result: &DataSet<[u8; 32]>| {
                let required = usize::from(
                  tributary_validator_set_info.tributary_validator_set.required_participation(),
                );
                if i < required {
                  assert!(matches!(result, DataSet::None));
                } else if matches!(result, DataSet::Participating(_)) {
                  saw_participating = true;
                }
                // After threshold is crossed, subsequent accumulate calls are NOPs (None).
                // Only the call that actually crosses the threshold returns Participating.
              }),
            );
            assert!(saw_participating, "expected at least one Participating result");

            txn.commit();
          }

          let has_reattempt = topic.reattempt_topic().is_some();
          let required = usize::from(
            tributary_validator_set_info.tributary_validator_set.required_participation(),
          );

          for (i, (participant, _)) in tributary_validator_set_info
            .tributary_validator_set
            .consensus_participants()
            .enumerate()
          {
            assert!(!TributaryDb::is_fatally_slashed(&db, set, participant));
            // Only participants who accumulated before the threshold have stored data.
            // After the threshold is crossed, accumulate returns None without storing.
            let accumulated_before_threshold = i < required;
            if has_reattempt && accumulated_before_threshold {
              assert!(
                TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(&db, set, topic, participant)
                  .is_some(),
                "data should be preserved when reattempt exists: {topic:?}"
              );
            } else {
              assert!(
                TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(&db, set, topic, participant)
                  .is_none(),
                "data should be cleaned up or never stored when no reattempt or after \
                      threshold: {topic:?}"
              );
            }
          }

          // Weight only accumulates up to the threshold; subsequent calls are NOPs.
          let expected_weight =
            tributary_validator_set_info.tributary_validator_set.required_participation();
          assert_eq!(
            TopicsAccumulatedWeight::get(&db, set, topic),
            Some(expected_weight),
            "weight should equal required_participation after crossing threshold: {topic:?}"
          );
        }
      }

      /// Accumulating for a topic proceeds when the next attempt's topic has no
      /// weight, regardless of whether an unrelated topic already has weight.
      #[test]
      fn not_nopd_without_next_attempt_weight() {
        let mut rng = new_test_rng();
        for topic in all_preprocess_topics_and_attempts(&mut rng) {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;

          let mut db = MemDb::new();

          // Accumulate for an unrelated topic so some weight exists in the DB
          let unrelated_topic = Topic::SlashReport;
          let first_participant = u16_to_participant(1);
          {
            let mut txn = db.txn();
            let result = TributaryDb::accumulate::<[u8; 32]>(
              &mut txn,
              &tributary_validator_set_info,
              rng.next_u64(),
              unrelated_topic,
              first_participant,
              &random_bytes(&mut rng),
            );
            assert!(matches!(result, DataSet::None));
            txn.commit();
          }

          assert_eq!(TopicsAccumulatedWeight::get(&db, set, unrelated_topic), Some(1));

          // Accumulating for our topic proceeds (not NOP'd by unrelated weight)
          let data = random_bytes(&mut rng);
          let second_participant = u16_to_participant(2);
          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }
            let result = TributaryDb::accumulate::<[u8; 32]>(
              &mut txn,
              &tributary_validator_set_info,
              rng.next_u64(),
              topic,
              second_participant,
              &data,
            );
            assert!(matches!(result, DataSet::None), "below threshold (1 of 3)");
            txn.commit();
          }

          // Data was stored (not NOP'd)
          assert_eq!(
            TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(
              &db,
              set,
              topic,
              second_participant
            ),
            Some(data)
          );
          assert_eq!(TopicsAccumulatedWeight::get(&db, set, topic), Some(1));
        }
      }
    }

    mod accumulate_reattempt_topic {
      use super::*;

      #[test]
      fn data_preserved_or_cleaned_up_based_on_reattempt() {
        let mut rng = new_test_rng();
        for topic in all_preprocess_topics_and_attempts(&mut rng) {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;
          let mut db = MemDb::new();
          let block_number = rng.next_u64();

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }

            let mut saw_participating = false;
            accumulate_all_participants(
              &mut txn,
              &tributary_validator_set_info,
              block_number,
              topic,
              |i| [u8::try_from(i).unwrap(); 32],
              Some(|_: usize, result: &DataSet<[u8; 32]>| {
                if matches!(result, DataSet::Participating(_)) {
                  saw_participating = true;
                }
              }),
            );
            assert!(saw_participating, "expected at least one Participating result");
            txn.commit();
          }

          let required = usize::from(
            tributary_validator_set_info.tributary_validator_set.required_participation(),
          );

          if topic.reattempt_topic().is_some() {
            for (i, (participant, _)) in tributary_validator_set_info
              .tributary_validator_set
              .consensus_participants()
              .enumerate()
            {
              let accumulated_before_threshold = i < required;
              if accumulated_before_threshold {
                let expected = [u8::try_from(u16::from(participant)).unwrap(); 32];
                assert_eq!(
                  TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(
                    &db,
                    set,
                    topic,
                    participant
                  ),
                  Some(expected),
                  "data should be preserved when reattempt exists: {topic:?}"
                );
              } else {
                assert!(
                  TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(
                    &db,
                    set,
                    topic,
                    participant
                  )
                  .is_none(),
                  "data should be cleaned up when no reattempt or after threshold: {topic:?}"
                );
              }
            }
          } else {
            assert!(
              BlocksReattemptTopics::get(&db, set, block_number).is_none(),
              "no reattempt should be queued: {topic:?}"
            );
            for (participant, _) in
              tributary_validator_set_info.tributary_validator_set.consensus_participants()
            {
              assert!(
                TopicsParticipantAccumulatedEntries::<[u8; 32]>::get(&db, set, topic, participant)
                  .is_none(),
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
        let mut rng = new_test_rng();
        let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
        let set = tributary_validator_set_info.set;

        // block_number near u64::MAX forces checked_add to overflow
        let block_number = u64::MAX - 1;

        // attempt just below u64::MAX so reattempt_topic() returns Some(u64::MAX)
        let topic =
          Topic::DkgConfirmation { attempt: block_number, round: SigningProtocolRound::Preprocess };
        assert_eq!(topic.reattempt_topic().unwrap().0, u64::MAX);

        let mut db = MemDb::new();

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);
          txn.commit();
        }

        let mut txn = db.txn();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
          accumulate_all_participants(
            &mut txn,
            &tributary_validator_set_info,
            block_number,
            topic,
            |i| [u8::try_from(i).unwrap(); 32],
            None::<NoEachFn>,
          );
        }));

        assert!(result.is_err(), "should panic on reattempt block number overflow");
      }

      #[test]
      fn succeeding_topic_recognized_after_threshold() {
        let mut rng = new_test_rng();
        for topic in all_preprocess_topics_and_attempts(&mut rng) {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;
          let mut db = MemDb::new();

          let succeeding_topic = topic.succeeding_topic().unwrap();

          // Cap `block_number` so `block_number + blocks_till_reattempt` cannot overflow.
          // `reattempt_schedule_panics_on_overflow` exercises the overflow path explicitly.
          let block_number = capped_block_number(&mut rng);

          {
            let mut txn = db.txn();
            if topic.requires_recognition() {
              TributaryDb::recognize_topic(&mut txn, set, topic);
            }
            accumulate_all_participants(
              &mut txn,
              &tributary_validator_set_info,
              block_number,
              topic,
              |i| [u8::try_from(i).unwrap(); 32],
              None::<NoEachFn>,
            );
            txn.commit();
          }

          assert!(TributaryDb::is_topic_recognized(&db, set, succeeding_topic));
          assert_eq!(
            TopicsAccumulatedWeight::get(&db, set, succeeding_topic),
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
      #[should_panic = "accumulate called twice for the same (topic, participant) tuple"]
      fn double_call_before_threshold_panics() {
        let mut rng = new_test_rng();
        let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
        let mut db = MemDb::new();
        let mut txn = db.txn();

        let topic = Topic::RemoveParticipant { participant: random_participant(&mut rng) };

        // First call succeeds
        let first_participant = u16_to_participant(1);
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          &tributary_validator_set_info,
          rng.next_u64(),
          topic,
          first_participant,
          &random_vec_u8(&mut rng, 0 ..= 128),
        );

        // Second call with same (validator, topic) should panic
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          &tributary_validator_set_info,
          rng.next_u64(),
          topic,
          first_participant,
          &random_vec_u8(&mut rng, 0 ..= 128),
        );
      }

      /// After threshold with a reattempt topic, Accumulated entries are
      /// preserved (for the reattempt protocol), so the duplicate assert fires.
      #[test]
      #[should_panic = "accumulate called twice for the same (topic, participant) tuple"]
      fn double_call_after_threshold_with_reattempt_panics() {
        let mut rng = new_test_rng();
        // DkgConfirmation Preprocess has a reattempt topic, so entries survive post-threshold
        let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };
        assert!(topic.reattempt_topic().is_some());
        let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
        let set = tributary_validator_set_info.set;
        let mut db = MemDb::new();
        let block_number = rng.next_u64();

        {
          let mut txn = db.txn();
          TributaryDb::recognize_topic(&mut txn, set, topic);
          txn.commit();
        }

        let mut txn = db.txn();

        accumulate_all_participants::<Vec<u8>, _, _>(
          &mut txn,
          &tributary_validator_set_info,
          block_number,
          topic,
          |i| vec![u8::try_from(i).unwrap()],
          None::<fn(usize, &DataSet<Vec<u8>>)>,
        );

        // Entries preserved for reattempt, duplicate panics
        let first_participant = u16_to_participant(1);
        TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          &tributary_validator_set_info,
          block_number,
          topic,
          first_participant,
          &random_vec_u8(&mut rng, 0 ..= 128),
        );
      }

      /// After threshold without a reattempt topic, Accumulated entries are
      /// cleaned up. The duplicate call does not hit the assertion (key is gone)
      /// and instead falls through to the weight >= threshold NOP.
      /*
        TODO: This test is unclear.

        It should test an unreachable case (double accumulate), which is why that is allowed to
        generally panic. This test shows the literal behavior where if the topic's data is pruned,
        then those asserts for an unreachable case disappear, which is fine. Why are we testing
        this behavior though? It should be unreachable and unobservable. This is more akin to a bug
        report that sanity checks disappear than functionality we want to assert the behavior of.
      */
      #[test]
      fn double_call_after_threshold_without_reattempt_is_nop() {
        let mut rng = new_test_rng();
        // RemoveParticipant has no reattempt, so entries are cleaned up post-threshold
        let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
        let set = tributary_validator_set_info.set;
        let mut db = MemDb::new();
        let mut txn = db.txn();
        let block_number = rng.next_u64();

        let topic = Topic::RemoveParticipant { participant: random_participant(&mut rng) };

        accumulate_all_participants::<Vec<u8>, _, _>(
          &mut txn,
          &tributary_validator_set_info,
          block_number,
          topic,
          |i| vec![u8::try_from(i).unwrap()],
          None::<fn(usize, &DataSet<Vec<u8>>)>,
        );

        let weight_after_threshold = TopicsAccumulatedWeight::get(&txn, set, topic).unwrap();

        // Entry was cleaned up, so assertion doesn't fire.
        // Falls through to the `accumulated_weight >= required_participation` NOP.
        let first_participant = u16_to_participant(1);
        let result = TributaryDb::accumulate::<Vec<u8>>(
          &mut txn,
          &tributary_validator_set_info,
          block_number,
          topic,
          first_participant,
          &random_vec_u8(&mut rng, 0 ..= 128),
        );

        assert!(matches!(result, DataSet::None), "should be NOP after threshold");
        assert_eq!(
          TopicsAccumulatedWeight::get(&txn, set, topic).unwrap(),
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
        tributary_validator_set_info: &TributaryValidatorSetInfo,
        block_number: u64,
        topic: Topic,
        participant: Participant,
        data: &Vec<u8>,
        pre_weight: Option<u16>,
        pre_slashed: bool,
        has_preceding_accumulated: bool,
        has_next_topic_weight: bool,
        result: &DataSet<Vec<u8>>,
      ) {
        let set = tributary_validator_set_info.set;
        let total_weight = tributary_validator_set_info.tributary_validator_set.total_weight();
        let required = required_participation(total_weight);

        // Outsider (participant not in validator set) is always fatally slashed by accumulate
        let is_outsider = tributary_validator_set_info
          .tributary_validator_set
          .get_tributary_validator_by_consensus_index(&participant)
          .is_none();
        if is_outsider {
          let post_slashed = TributaryDb::is_fatally_slashed(db, set, participant);
          assert!(post_slashed, "outsider should be fatally slashed");
          assert!(matches!(result, DataSet::None));
          return;
        }

        let post_slashed = TributaryDb::is_fatally_slashed(db, set, participant);
        let post_weight = TopicsAccumulatedWeight::get(db, set, topic);

        // Slash for participating in unrecognized topic requiring recognition.
        if topic.requires_recognition() && pre_weight.is_none() {
          assert!(post_slashed, "should be fatally slashed for unrecognized topic");
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, None, "weight should remain None after recognition slash");
          assert!(
            TopicsParticipantAccumulatedEntries::<Vec<u8>>::get(db, set, topic, participant)
              .is_none(),
            "no data should be stored after recognition slash"
          );
          return;
        }

        let weight_before = pre_weight.unwrap_or(0);

        // Slash for participating without completing the preceding topic.
        if topic.preceding_topic().is_some() && (!has_preceding_accumulated) {
          assert!(post_slashed, "should be fatally slashed for missing preceding participation");
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, pre_weight, "weight unchanged after preceding slash");
          return;
        }

        // Already accumulated past the threshold - NOP.
        if weight_before >= required {
          assert!(matches!(result, DataSet::None));
          assert_eq!(post_weight, pre_weight, "weight unchanged when past threshold");
          if !pre_slashed {
            assert!(!post_slashed, "should not be slashed on threshold NOP");
          }
          return;
        }

        // Old attempt, the next attempt's topic already has weight.
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

        // Accumulation happened - get validator weight from tributary_validator_set_info
        let validator_weight = tributary_validator_set_info
          .tributary_validator_set
          .get_tributary_validator_by_consensus_index(&participant)
          .map(|v| v.weight)
          .unwrap_or(1);
        let new_weight = weight_before + validator_weight;
        assert_eq!(post_weight, Some(new_weight), "weight should reflect accumulation");

        if !pre_slashed {
          assert!(!post_slashed, "should not be slashed after valid accumulation");
        }

        if new_weight >= required {
          // Threshold crossed.

          // Reattempt should be queued if topic is reattemptable.
          if let Some((reattempt_attempt, reattempt_topic)) = topic.reattempt_topic() {
            let blocks_till = reattempt_attempt
              .min(10)
              .checked_mul(u64::from(BASE_REATTEMPT_DELAY))
              .expect("reattempt delay overflowed u64");
            let recognize_at =
              block_number.checked_add(blocks_till).expect("reattempt block number overflowed u64");

            let queued = BlocksReattemptTopics::get(db, set, recognize_at);
            assert!(queued.is_some(), "reattempt should be queued at block {recognize_at}");
            assert!(
              queued.unwrap().contains(&reattempt_topic),
              "reattempt queue should contain {reattempt_topic:?}"
            );
          }

          // Succeeding topic should be recognized (weight set to 0).
          if let Some(succeeding) = topic.succeeding_topic() {
            assert_eq!(
              TopicsAccumulatedWeight::get(db, set, succeeding),
              Some(0),
              "succeeding topic should be recognized with weight=0"
            );
          }

          // Accumulated data cleanup depends on whether a reattempt exists.
          let has_reattempt = topic.reattempt_topic().is_some();
          if has_reattempt {
            assert_eq!(
              TopicsParticipantAccumulatedEntries::<Vec<u8>>::get(db, set, topic, participant),
              Some(data.clone()),
              "data should be preserved (reattempt={has_reattempt}"
            );
          } else {
            assert!(
              TopicsParticipantAccumulatedEntries::<Vec<u8>>::get(db, set, topic, participant)
                .is_none(),
              "data should be cleaned up when no reattempt and validator in list"
            );
          }

          // Result depends on whether the validator was in the collection list.
          match result {
            DataSet::Participating(data_set) => {
              assert!(
                data_set.contains_key(&participant),
                "validator should be in result data set"
              );
              assert_eq!(
                data_set.get(&participant).unwrap(),
                data,
                "result data should match input"
              );
            }
            DataSet::None => {
              panic!("result should be Participating when threshold crossed by listed validator");
            }
          }
        } else {
          // Below threshold
          // data stored, result is None.
          assert!(matches!(result, DataSet::None), "result should be None when below threshold");
          assert_eq!(
            TopicsParticipantAccumulatedEntries::<Vec<u8>>::get(db, set, topic, participant),
            Some(data.clone()),
            "accumulated data should be stored"
          );
        }
      }

      #[test]
      fn fuzz_accumulate() {
        let mut rng = new_test_rng();
        for _ in 0 .. 100 {
          let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
          let set = tributary_validator_set_info.set;
          let total_weight = tributary_validator_set_info.tributary_validator_set.total_weight();

          let has_initial_weight = rng.gen::<bool>();
          let initial_weight = rng.gen_range(0u16 .. total_weight);

          let has_next_topic_weight = rng.gen::<bool>();

          let has_preceding_topic_accumulated = rng.gen::<bool>();

          let topic_variant = rng.gen_range(0u8 .. 5);
          let attempt = rng.gen_range(0u64 .. 100);
          let round = if rng.gen::<bool>() {
            SigningProtocolRound::Preprocess
          } else {
            SigningProtocolRound::Share
          };
          let cosign_block = rng.next_u64();
          let batch_id: [u8; 32] = rng.gen();
          let block_number = rng.gen_range(1u64 .. u64::MAX);
          let data: Vec<u8> = (0 .. rng.gen_range(0usize .. 64)).map(|_| rng.gen()).collect();

          let participants: Vec<Participant> = tributary_validator_set_info
            .tributary_validator_set
            .consensus_participants()
            .map(|(p, _)| p)
            .collect();

          let topic = match topic_variant % 5 {
            0 => Topic::RemoveParticipant { participant: random_participant(&mut rng) },
            1 => Topic::DkgConfirmation { attempt: attempt % 100, round },
            2 => Topic::SlashReport,
            3 => {
              Topic::Sign { id: VariantSignId::Cosign(cosign_block), attempt: attempt % 100, round }
            }
            _ => Topic::Sign { id: VariantSignId::Batch(batch_id), attempt: attempt % 100, round },
          };

          let mut db = MemDb::new();
          let mut txn = db.txn();

          if has_initial_weight {
            TopicsAccumulatedWeight::set(&mut txn, set, topic, &initial_weight);
          }

          if has_next_topic_weight {
            if let Some(next_attempt_topic) = topic.next_attempt_topic() {
              TopicsAccumulatedWeight::set(&mut txn, set, next_attempt_topic, &initial_weight);
            }
          }

          // Pick a validator from the set or use an outsider
          let signer = {
            let idx = rng.gen_range(0 .. participants.len());
            participants[idx]
          };

          if has_preceding_topic_accumulated {
            if let Some(preceding_topic) = topic.preceding_topic() {
              TopicsParticipantAccumulatedEntries::set(
                &mut txn,
                set,
                preceding_topic,
                signer,
                &data,
              );
            }
          }

          let pre_weight = TopicsAccumulatedWeight::get(&txn, set, topic);
          let pre_slashed = TributaryDb::is_fatally_slashed(&txn, set, signer);

          let result = TributaryDb::accumulate::<Vec<u8>>(
            &mut txn,
            &tributary_validator_set_info,
            block_number,
            topic,
            signer,
            &data,
          );

          txn.commit();

          verify_accumulate_invariants(
            &db,
            &tributary_validator_set_info,
            block_number,
            topic,
            signer,
            &data,
            pre_weight,
            pre_slashed,
            has_preceding_topic_accumulated,
            has_next_topic_weight,
            &result,
          );
        }
      }
    }
  }
}
