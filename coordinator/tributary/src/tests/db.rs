use serai_primitives::{
  address::SeraiAddress,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
  BlockHash,
};

use messages::sign::VariantSignId;

use serai_db::{Db, DbTxn, MemDb};

use crate::{db::*, transaction::SigningProtocolRound};

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

  pub fn new_scenarios() -> Vec<Topic> {
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

  for topic in Test::new_scenarios() {
    match topic {
      Topic::Sign { .. } => assert!(topic.sign_id(set).is_some(), "Expected Some for Sign"),

      _ => assert!(topic.sign_id(set).is_none(), "Expected None for {:?}", topic),
    }
  }
}

#[test]
fn topic_dkg_confirmation_sign_id_returns_some_for_dkg_confirmation_topics() {
  let set = Test::new_test_set();

  for topic in Test::new_scenarios() {
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
  for topic in Test::new_scenarios() {
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

  for topic in Test::new_scenarios() {
    let reattempt_topic = topic.reattempt_topic();

    match topic {
      Topic::DkgConfirmation { .. } | Topic::Sign { .. } => assert!(reattempt_topic.is_some()),

      _ => assert!(reattempt_topic.is_none(), "Expected None for {:?}", topic),
    }

    let mut txn = db.txn();

    if let Some((attempt, reattempt_topic)) = reattempt_topic {
      // 5 seconds
      const BASE_REATTEMPT_DELAY: u32 =
        (5u32 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

      let blocks_till_reattempt = u64::from(attempt * BASE_REATTEMPT_DELAY);

      let recognize_at = block_number + blocks_till_reattempt;
      let mut queued = Reattempt::get(&mut txn, set, recognize_at).unwrap_or(Vec::with_capacity(1));
      queued.push(reattempt_topic);
      Reattempt::set(&mut txn, set, recognize_at, &queued);

      TributaryDb::start_of_block(&mut txn, set, recognize_at);

      assert!(TributaryDb::recognized(&mut txn, set, reattempt_topic));

      if let Some(_id) = topic.sign_id(set) {
        assert!(ProcessorMessages::peek(&mut txn, set).is_some());
      }
      if let Some(_id) = topic.dkg_confirmation_sign_id(set) {
        assert!(DkgConfirmationMessages::peek(&mut txn, set).is_some());
      }
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
    result: &DataSet<Vec<u32>>,
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
      if Accumulated::<Vec<u32>>::get(txn, set, preceding_topic, validator).is_none() {
        assert!(
          TributaryDb::is_fatally_slashed(txn, set, validator),
          "should have been slashed for participating in topic without participating in prior"
        );
        assert!(matches!(result, DataSet::None));
        return;
      }
    }

    let accumulated_weight = AccumulatedWeight::get(txn, set, topic).unwrap_or(0);
    if accumulated_weight >= required_participation(total_weight) {
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
    assert!(Accumulated::<Vec<u32>>::get(txn, set, topic, validator).is_some());
  }

  for topic in Test::new_scenarios() {
    let mut txn = db.txn();

    let accumulated_weight = AccumulatedWeight::get(&mut txn, set, topic);
    assert!(accumulated_weight.is_none());

    // First validator accumulates - should return None (not enough weight yet)
    let validator = validators[0];
    let result = TributaryDb::accumulate::<Vec<u32>>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validator,
      1,
      &vec![0, 0, 0],
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
    let result = TributaryDb::accumulate::<Vec<u32>>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validator,
      1,
      &vec![0, 0, 0],
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
    let result = TributaryDb::accumulate::<Vec<u32>>(
      &mut txn,
      set,
      &validators,
      total_weight,
      block_number,
      topic,
      validators[2],
      1,
      &vec![0, 0, 0],
    );

    txn.commit();
    block_number += 1;
  }

  // assert!(matches!(result, DataSet::Participating(_)));
  // if let DataSet::Participating(data) = result {
  //   assert_eq!(data.len(), 3);
  // }
}
