use rand::{RngCore, rngs::OsRng};

use serai_primitives::{
  address::SeraiAddress,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use messages::sign::VariantSignId;

use serai_db::{Db, DbTxn, MemDb};
use serai_substrate_tests::random_serai_address;

use crate::{db::*, transaction::SigningProtocolRound};

fn default_set() -> ExternalValidatorSet {
  // The external validator set does not change any functionality that is being tested
  // use this as default
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}

fn all_topics() -> Vec<Topic> {
  vec![
    Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
    Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Share },
    Topic::SlashReport,
    Topic::Sign {
      id: VariantSignId::Transaction([0; 32]),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    },
    Topic::Sign {
      id: VariantSignId::Transaction([0; 32]),
      attempt: 0,
      round: SigningProtocolRound::Share,
    },
  ]
}

mod topic {
  use messages::sign::SignId;
  use super::*;

  #[test]
  fn next_attempt_topic() {
    for topic in all_topics() {
      match topic {
        Topic::RemoveParticipant { .. } => assert_eq!(topic.next_attempt_topic(), None),
        Topic::DkgConfirmation { attempt, round: _ } => {
          if let Some(next_attempt) = attempt.checked_add(1) {
            assert_eq!(
              topic.next_attempt_topic(),
              Some(Topic::DkgConfirmation {
                attempt: next_attempt,
                round: SigningProtocolRound::Preprocess,
              })
            );
          } else {
            assert_eq!(topic.next_attempt_topic(), None);
          }
        }
        Topic::SlashReport => assert_eq!(topic.next_attempt_topic(), None),
        Topic::Sign { id, attempt, round: _ } => {
          if let Some(next_attempt) = attempt.checked_add(1) {
            assert_eq!(
              topic.next_attempt_topic(),
              Some(Topic::Sign {
                id,
                attempt: next_attempt,
                round: SigningProtocolRound::Preprocess
              })
            );
          } else {
            assert_eq!(topic.next_attempt_topic(), None);
          }
        }
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
            if let Some(next_attempt) = attempt.checked_add(1) {
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
            } else {
              assert_eq!(topic.reattempt_topic(), None);
            }
          }
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
        Topic::SlashReport => assert_eq!(topic.reattempt_topic(), None),
        Topic::Sign { id, attempt, round } => match round {
          SigningProtocolRound::Preprocess => {
            if let Some(next_attempt) = attempt.checked_add(1) {
              assert_eq!(
                topic.reattempt_topic(),
                Some((
                  next_attempt,
                  Topic::Sign {
                    id,
                    attempt: next_attempt,
                    round: SigningProtocolRound::Preprocess
                  },
                ))
              );
            } else {
              assert_eq!(topic.reattempt_topic(), None);
            }
          }
          SigningProtocolRound::Share => assert_eq!(topic.reattempt_topic(), None),
        },
      }
    }
  }

  #[test]
  fn sign_id() {
    let set = default_set();
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
    let set = default_set();
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
    let set = default_set();
    let block_hash1 = random_block_hash(&mut OsRng);
    let block_number1 = OsRng.next_u64();

    let topic = Topic::Sign {
      id: VariantSignId::Cosign(block_number1),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    };

    // Recognizes topic
    {
      let mut txn = db.txn();
      TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number1);

      assert!(TributaryDb::recognized(&txn, set, topic,));
      txn.commit();
    }

    // Same set cannot recognize again until finished
    {
      let mut txn = db.txn();
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash1));

      let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let block_hash2 = random_block_hash(&mut OsRng);
        let block_number2 = OsRng.next_u64();
        TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      }));

      assert!(retry.is_err());
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

    // Start new cosigning
    {
      let mut txn = db.txn();
      let block_hash2 = random_block_hash(&mut OsRng);
      let block_number2 = OsRng.next_u64();

      TributaryDb::start_cosigning(&mut txn, set, block_hash2, block_number2);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash2));

      TributaryDb::finish_cosigning(&mut txn, set);
      assert_eq!(ActivelyCosigning::get(&mut txn, set), None);

      // New topic recognized
      assert!(TributaryDb::recognized(
        &txn,
        set,
        Topic::Sign {
          id: VariantSignId::Cosign(block_number2),
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        }
      ));

      txn.commit();
    }
  }
}

#[test]
fn db_start_of_block() {
  let _ = env_logger::try_init();
  let set = default_set();

  let reattemptable_topics: Vec<Topic> = all_topics()
    .into_iter()
    .filter_map(|t| t.reattempt_topic().map(|(_, reattempt_topic)| reattempt_topic))
    .collect();

  serai_log::log::info!(
    "db_start_of_block fuzz: reattemptable_topics={reattemptable_topics:?}, \
     all_topics count={}",
    all_topics().len()
  );

  for iteration in 0 .. 100 {
    for topic in all_topics() {
      // Fresh DB per topic so recognized state doesn't leak between iterations
      let mut db = MemDb::new();
      let block_number = OsRng.next_u64();
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

  serai_log::log::info!("db_start_of_block fuzz: completed 100 iterations");
}

#[test]
fn db_fatal_slash() {
  let mut db = MemDb::new();
  let set = default_set();
  let validator = random_serai_address(&mut OsRng);

  {
    let mut txn = db.txn();
    TributaryDb::fatal_slash(&mut txn, set, validator, "test reason");
    txn.commit();
  }

  assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
  assert_eq!(SlashPoints::get(&db, set, validator), Some(u32::MAX));
}

mod fuzz {
  use super::*;
  use proptest::prelude::*;

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

    // Branch 3: required_participation overflows (total_weight > 32767).
    let Some(required) = required else {
      assert!(matches!(result, DataSet::None));
      assert_eq!(post_weight, pre_weight, "weight unchanged when required_participation overflows");
      if !pre_slashed {
        assert!(!post_slashed, "should not be slashed on overflow NOP");
      }
      return;
    };

    // Branch 4: Already accumulated past the threshold - NOP.
    if weight_before >= required {
      assert!(matches!(result, DataSet::None));
      assert_eq!(post_weight, Some(weight_before), "weight unchanged when past threshold");
      if !pre_slashed {
        assert!(!post_slashed, "should not be slashed on threshold NOP");
      }
      return;
    }

    // Branch 5: Old attempt - the next attempt's topic already has weight.
    let next_attempt_superseded = has_next_topic_weight && topic.next_attempt_topic().is_some();
    if next_attempt_superseded {
      assert!(matches!(result, DataSet::None));
      assert_eq!(post_weight, Some(weight_before), "weight unchanged for superseded attempt");
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
      // When no reattempt, the data is cleaned up in the collection loop.
      let has_reattempt = topic.reattempt_topic().is_some();
      if has_reattempt {
        assert_eq!(
          Accumulated::<Vec<u8>>::get(db, set, topic, validator),
          Some(data.clone()),
          "data should be preserved when reattempt exists"
        );
      } else {
        assert!(
          Accumulated::<Vec<u8>>::get(db, set, topic, validator).is_none(),
          "data should be cleaned up when no reattempt"
        );
      }

      // 7d: Result should be DataSet::Participating (validator just accumulated).
      match result {
        DataSet::Participating(data_set) => {
          assert!(data_set.contains_key(&validator), "validator should be in result data set");
          assert_eq!(data_set.get(&validator).unwrap(), data, "result data should match input");
        }
        DataSet::None => {
          panic!(
            "result should be Participating when threshold crossed by participating validator"
          );
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
          let set = default_set();

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

          let cur_validator = (cur_validator as usize) % validators.len();
          let validator = validators[cur_validator];

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
              &result,
          );
      }
  }
}
