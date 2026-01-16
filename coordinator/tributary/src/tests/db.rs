use serai_primitives::{
  address::SeraiAddress,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
  BlockHash,
};

use messages::sign::VariantSignId;

use serai_db::{Db, DbTxn, MemDb};

use crate::{db::*, transaction::SigningProtocolRound};

type TestData = Vec<u8>;

struct Test;
impl Test {
  pub fn new_test_set() -> ExternalValidatorSet {
    ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
  }

  pub fn new_test_validator(byte: u8) -> SeraiAddress {
    let mut addr = [byte; 32];
    addr[0] = byte;
    SeraiAddress(addr)
  }

  pub fn new_all_topics() -> Vec<Topic> {
    vec![
      Topic::RemoveParticipant { participant: Self::new_test_validator(1) },
      Topic::SlashReport,
      Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess },
      Topic::DkgConfirmation { attempt: 1, round: SigningProtocolRound::Preprocess },
      Topic::Sign {
        id: VariantSignId::Transaction([0; 32]),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
      },
    ]
  }
}

#[test]
fn topic_sign_id_returns_some_for_sign_topics() {
  let set = Test::new_test_set();

  for topic in Test::new_all_topics() {
    match topic {
      Topic::Sign { .. } => assert!(topic.sign_id(set).is_some(), "Expected Some for Sign"),

      _ => assert!(topic.sign_id(set).is_none(), "Expected None for {:?}", topic),
    }
  }
}

#[test]
fn topic_dkg_confirmation_sign_id_returns_some_for_dkg_confirmation_topics() {
  let set = Test::new_test_set();

  for topic in Test::new_all_topics() {
    match topic {
      Topic::DkgConfirmation { .. } => {
        assert!(topic.dkg_confirmation_sign_id(set).is_some(), "Expected Some for DkgConfirmation")
      }

      _ => assert!(topic.dkg_confirmation_sign_id(set).is_none(), "Expected None for {:?}", topic),
    }
  }
}

#[test]
fn topic_requires_recognition() {
  for topic in Test::new_all_topics() {
    match topic {
      Topic::Sign { .. } |
      Topic::DkgConfirmation { attempt: 1, round: SigningProtocolRound::Preprocess } => {
        assert!(topic.requires_recognition(), "Expected {:?} to require recognition", topic)
      }

      _ => assert_eq!(
        topic.requires_recognition(),
        false,
        "Expected {:?} to not require recognition",
        topic
      ),
    }
  }
}

#[test]
fn db_last_handled_tributary_block() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();

  assert!(TributaryDb::last_handled_tributary_block(&db, set).is_none());

  {
    let mut txn = db.txn();
    TributaryDb::set_last_handled_tributary_block(&mut txn, set, 1, [1; 32]);
    txn.commit();
  }

  assert_eq!(TributaryDb::last_handled_tributary_block(&db, set), Some((1, [1; 32])));
}

#[test]
fn db_latest_substrate_block_to_cosign() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();

  assert!(TributaryDb::latest_substrate_block_to_cosign(&db, set).is_none());

  let block_hash: BlockHash = BlockHash([1; 32]);

  {
    let mut txn = db.txn();
    TributaryDb::set_latest_substrate_block_to_cosign(&mut txn, set, block_hash);
    txn.commit();
  }

  assert_eq!(TributaryDb::latest_substrate_block_to_cosign(&db, set), Some(block_hash));
}

#[test]
fn db_actively_cosigning() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();
  let block_number = 1;
  let block_hash1: BlockHash = BlockHash([block_number; 32]);
  let topic = Topic::Sign {
    id: VariantSignId::Cosign(block_number.into()),
    attempt: 0,
    round: SigningProtocolRound::Preprocess,
  };

  {
    let mut txn = db.txn();
    assert!(TributaryDb::actively_cosigning(&mut txn, set).is_none());
    assert_eq!(TributaryDb::recognized(&mut txn, set, topic), false);
    TributaryDb::start_cosigning(&mut txn, set, block_hash1, block_number.into());
    txn.commit();
  }

  {
    let mut txn = db.txn();
    assert_eq!(TributaryDb::actively_cosigning(&mut txn, set), Some(block_hash1));
    assert!(TributaryDb::recognized(&mut txn, set, topic));
  }

  let re_start = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let block_hash2: BlockHash = BlockHash([2; 32]);
    let mut txn = db.txn();
    TributaryDb::start_cosigning(&mut txn, set, block_hash2, 2);
  }));

  assert!(re_start.is_err());

  {
    let mut txn = db.txn();
    TributaryDb::finish_cosigning(&mut txn, set);
    txn.commit();
  }

  let mut txn = db.txn();
  assert!(TributaryDb::actively_cosigning(&mut txn, set).is_none());
  assert!(TributaryDb::recognized(&mut txn, set, topic));
}

#[test]
fn db_mark_cosigned() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();
  let block_hash: BlockHash = BlockHash([8; 32]);

  let mut txn = db.txn();
  assert_eq!(TributaryDb::cosigned(&mut txn, set, block_hash), false);

  TributaryDb::mark_cosigned(&mut txn, set, block_hash);

  assert!(TributaryDb::cosigned(&mut txn, set, block_hash));
}

#[test]
fn db_recognize_topic() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();

  let topic = Topic::Sign {
    id: VariantSignId::Transaction([0; 32]),
    attempt: 0,
    round: SigningProtocolRound::Preprocess,
  };

  assert!(!TributaryDb::recognized(&db, set, topic));

  let mut txn = db.txn();
  TributaryDb::recognize_topic(&mut txn, set, topic);
  txn.commit();

  assert!(TributaryDb::recognized(&db, set, topic));
}

#[test]
fn db_start_of_block() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();
  let mut block_number = 1u64;

  {
    let mut txn = db.txn();
    // nothing happens
    TributaryDb::start_of_block(&mut txn, set, block_number);
    block_number += 1;
    txn.commit();
  }

  for topic in Test::new_all_topics() {
    let mut txn = db.txn();

    let assert_did_send_messages = |txn: &mut _| {
      if let Some(_id) = topic.sign_id(set) {
        assert!(ProcessorMessages::try_recv(txn, set).is_some());
      } else if let Some(_id) = topic.dkg_confirmation_sign_id(set) {
        assert!(DkgConfirmationMessages::try_recv(txn, set).is_some());
      }
    };
    let assert_no_sent_messages = |txn: &mut _| {
      if let Some(_id) = topic.sign_id(set) {
        assert!(ProcessorMessages::try_recv(txn, set).is_none());
      } else if let Some(_id) = topic.dkg_confirmation_sign_id(set) {
        assert!(DkgConfirmationMessages::try_recv(txn, set).is_none());
      }
    };
    let assert_not_recognized = |txn: &mut _, topic: Topic| {
      assert_eq!(TributaryDb::recognized(txn, set, topic), false);
    };
    let assert_recognized = |txn: &mut _, topic: Topic| {
      assert!(TributaryDb::recognized(txn, set, topic));
    };

    let reattempt_topic = topic.reattempt_topic();

    match topic {
      Topic::DkgConfirmation { .. } | Topic::Sign { .. } => assert!(reattempt_topic.is_some()),
      _ => assert!(reattempt_topic.is_none(), "Expected None for {:?}", topic),
    }

    let mut queued_reattempts = Vec::with_capacity(Test::new_all_topics().len());
    let mut queued_topics = Vec::with_capacity(Test::new_all_topics().len());

    if let Some((_attempt, reattempt_topic)) = reattempt_topic {
      // test with no Reattempt set beforehand
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_no_sent_messages(&mut txn);
      assert_not_recognized(&mut txn, reattempt_topic);

      // test with only reattempt_topic set as Reattempt
      Reattempt::set(&mut txn, set, block_number, &vec![reattempt_topic]);
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_did_send_messages(&mut txn);
      assert_recognized(&mut txn, reattempt_topic);

      // test with queued reattempt_topics
      queued_reattempts.push(reattempt_topic);
      Reattempt::set(&mut txn, set, block_number, &queued_reattempts);
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_did_send_messages(&mut txn);
      assert_recognized(&mut txn, reattempt_topic);
    } else {
      // test with no Reattempt set beforehand
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_no_sent_messages(&mut txn);
      assert_not_recognized(&mut txn, topic);

      // test with only topic set as Reattempt
      Reattempt::set(&mut txn, set, block_number, &vec![topic]);
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_no_sent_messages(&mut txn);
      assert_recognized(&mut txn, topic);

      // test with queued topics
      queued_topics.push(topic);
      Reattempt::set(&mut txn, set, block_number, &queued_topics);
      TributaryDb::start_of_block(&mut txn, set, block_number);
      assert_no_sent_messages(&mut txn);
      assert_recognized(&mut txn, topic);
    }

    txn.commit();
    block_number += 1;
  }
}

#[test]
fn db_fatal_slash() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();
  let validator = Test::new_test_validator(1);

  assert_eq!(TributaryDb::is_fatally_slashed(&db, set, validator), false);
  assert_eq!(SlashPoints::get(&db, set, validator), None);

  {
    let mut txn = db.txn();
    TributaryDb::fatal_slash(&mut txn, set, validator, "test reason");
    txn.commit();
  }

  assert!(TributaryDb::is_fatally_slashed(&db, set, validator));
  assert_eq!(SlashPoints::get(&db, set, validator), Some(u32::MAX));
}

#[test]
fn db_accumulate() {
  let mut db = MemDb::new();
  let set = Test::new_test_set();
  let mut block_number = 1u64;
  let total_weight = 3u16;

  let validators =
    vec![Test::new_test_validator(1), Test::new_test_validator(2), Test::new_test_validator(3)];

  fn assert_less_participation_accumulate_result<D: Db>(
    txn: &mut D::Transaction<'_>,
    set: ExternalValidatorSet,
    total_weight: u16,
    topic: Topic,
    validator: SeraiAddress,
    result: &DataSet<TestData>,
  ) {
    if topic.requires_recognition() {
      assert!(
        TributaryDb::is_fatally_slashed(txn, set, validator),
        concat!(
          "should have been slashed ",
          "for participating in unrecognized topic which requires recognition"
        )
      );
      assert!(matches!(result, DataSet::None));
      return;
    }

    let preceding_topic = topic.preceding_topic();
    if let Some(preceding_topic) = preceding_topic {
      if Accumulated::<TestData>::get(txn, set, preceding_topic, validator).is_none() {
        assert!(
          TributaryDb::is_fatally_slashed(txn, set, validator),
          "should have been slashed for participating in topic without participating in prior"
        );
        assert!(matches!(result, DataSet::None));
        return;
      }
    }

    let accumulated_weight = AccumulatedWeight::get(txn, set, topic).unwrap_or(0);
    if accumulated_weight >= required_participation(total_weight).unwrap() {
      assert!(matches!(result, DataSet::None));
      return;
    }

    if let Some(next_attempt_topic) = topic.next_attempt_topic() {
      if AccumulatedWeight::get(txn, set, next_attempt_topic).is_some() {
        assert!(matches!(result, DataSet::None));
        return;
      }
    }

    assert!(AccumulatedWeight::get(txn, set, topic).is_some());
    assert!(Accumulated::<TestData>::get(txn, set, topic, validator).is_some());
  }

  for topic in Test::new_all_topics() {
    let mut txn = db.txn();

    let accumulated_weight = AccumulatedWeight::get(&mut txn, set, topic);
    assert!(accumulated_weight.is_none());

    // First validator accumulates - should return None (not enough weight yet)
    let validator = validators[0];
    let result = TributaryDb::accumulate::<TestData>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validator,
      1,
      &vec![0u8; 32],
    );
    assert_less_participation_accumulate_result::<MemDb>(
      &mut txn,
      set,
      total_weight,
      topic,
      validator,
      &result,
    );

    // Second validator accumulates - should return None (still not enough)
    let validator = validators[1];
    let result = TributaryDb::accumulate::<TestData>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validator,
      1,
      &vec![1u8; 32],
    );
    assert_less_participation_accumulate_result::<MemDb>(
      &mut txn,
      set,
      total_weight,
      topic,
      validator,
      &result,
    );

    // Third validator accumulates - should cross threshold (2/3 + 1 = 3)
    let _result = TributaryDb::accumulate::<TestData>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validators[2],
      1,
      &vec![2u8; 32],
    );

    txn.commit();
    block_number += 1;
  }

  // assert!(matches!(result, DataSet::Participating(_)));
  // if let DataSet::Participating(data) = result {
  //   assert_eq!(data.len(), 3);
  // }
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn fuzz_accumulate(
        has_initial_weight in any::<bool>(),
        initial_weight in any::<u16>(),
        total_weight in 1u16..u16::MAX,

        has_next_weight in any::<bool>(),
        next_initial_weight in any::<u16>(),

        has_preceding_accumulated in any::<bool>(),

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
        0 => Topic::RemoveParticipant { participant: Test::new_test_validator(1) },
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
        let set = Test::new_test_set();

        let validators: Vec<SeraiAddress> =
          (0 .. num_validators).map(|i| Test::new_test_validator(i as u8)).collect();

        let validator_weight = validator_weight.min(total_weight).max(1);

        let mut txn = db.txn();

        if has_initial_weight {
            AccumulatedWeight::set(&mut txn, set, topic, &initial_weight);
        }

        if has_next_weight {
            if let Some(next_attempt_topic) = topic.next_attempt_topic() {
                AccumulatedWeight::set(&mut txn, set, next_attempt_topic, &next_initial_weight);
            }
        }

        let cur_validator = (cur_validator as usize) % validators.len();
        let validator = validators[cur_validator];

        if has_preceding_accumulated {
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
    }
}
