use serai_db::{Db as _, DbTxn as _, MemDb};
use dkg::Participant;
use crate::{Transaction, ParticipantTributarySlashPoints, TributaryDb, slash_report_transaction};
use super::*;

fn consensus_participant_at(index: usize) -> Participant {
  Participant::new(u16::try_from(index + 1).unwrap()).unwrap()
}

// TODO: Test the resulting slash report the Tributary would yield in response to consensus on this
#[test]
fn slash_report() {
  let mut rng = new_test_rng();
  // No slash points set: all zeros
  {
    let db = MemDb::new();
    let set_info = setup_n_validators(&mut rng, 4);

    assert_eq!(
      slash_report_transaction(&db, &set_info),
      Transaction::SlashReport { slash_points: vec![0, 0, 0, 0], signed: Signed::default() }
    );
  }

  // Respects validator order
  {
    let mut db = MemDb::new();
    let tributary_validator_set_info = setup_n_validators(&mut rng, 4);
    let set = tributary_validator_set_info.set;

    let (slash1, slash2, slash3, slash4) =
      (rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32());

    {
      let mut txn = db.txn();
      ParticipantTributarySlashPoints::set(&mut txn, set, consensus_participant_at(0), &slash1);
      // SlashPoints sets validator 3 before 2 here,
      // but this order doesn't affect the validators order of tributary_validator_set_info
      ParticipantTributarySlashPoints::set(&mut txn, set, consensus_participant_at(2), &slash3);
      ParticipantTributarySlashPoints::set(&mut txn, set, consensus_participant_at(1), &slash2);
      ParticipantTributarySlashPoints::set(&mut txn, set, consensus_participant_at(3), &slash4);
      txn.commit();
    }

    assert_eq!(
      slash_report_transaction(&db, &tributary_validator_set_info),
      Transaction::SlashReport {
        slash_points: vec![slash1, slash2, slash3, slash4],
        signed: Signed::default()
      }
    );
  }

  // Fatal slash yields u32::MAX
  {
    let mut db = MemDb::new();
    let set_info = setup_n_validators(&mut rng, 2);
    let set = set_info.set;

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, consensus_participant_at(0), "test reason");
      txn.commit();
    }

    assert_eq!(
      slash_report_transaction(&db, &set_info),
      Transaction::SlashReport { slash_points: vec![u32::MAX, 0], signed: Signed::default() }
    );
  }
}
