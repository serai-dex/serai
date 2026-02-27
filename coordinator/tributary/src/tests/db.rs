use rand::{RngCore, rngs::OsRng};

use serai_primitives::{
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
