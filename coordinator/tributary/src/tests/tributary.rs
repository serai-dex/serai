use serai_db::{Db as _, Transaction as _, MemDb};
use crate::{Transaction, SlashPoints, TributaryDb, slash_report_transaction};
use super::*;

// TODO: Test the resulting slash report the Tributary would yield in response to consensus on this
#[test]
fn slash_report() {
  // No slash points set: all zeros
  {
    let db = MemDb::new();
    let validators = vec![
      (random_serai_address(&mut OsRng), 1),
      (random_serai_address(&mut OsRng), 1),
      (random_serai_address(&mut OsRng), 1),
    ];
    let set_info = new_test_set_info(&validators);

    assert_eq!(
      slash_report_transaction(&db, &set_info),
      Transaction::SlashReport { slash_points: vec![0, 0, 0], signed: Signed::default() }
    );
  }

  // Respects validator order
  {
    let mut db = MemDb::new();
    let (v1, v2, v3, v4) = (
      random_serai_address(&mut OsRng),
      random_serai_address(&mut OsRng),
      random_serai_address(&mut OsRng),
      random_serai_address(&mut OsRng),
    );
    let set_info = new_test_set_info(&[(v1, 1), (v2, 1), (v3, 1), (v4, 1)]);
    let set = set_info.set;

    let (slash1, slash2, slash3, slash4) =
      (OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32());

    {
      let mut txn = db.txn();
      SlashPoints::set(&mut txn, set, v1, &slash1);
      // SlashPoints sets validator 3 before 2 here,
      // but this order doesn't affect the validators order of set_info
      SlashPoints::set(&mut txn, set, v3, &slash3);
      SlashPoints::set(&mut txn, set, v2, &slash2);
      SlashPoints::set(&mut txn, set, v4, &slash4);
      txn.commit();
    }

    assert_eq!(
      slash_report_transaction(&db, &set_info),
      Transaction::SlashReport {
        slash_points: vec![slash1, slash2, slash3, slash4],
        signed: Signed::default()
      }
    );
  }

  // Fatal slash yields u32::MAX
  {
    let mut db = MemDb::new();
    let (v1, v2) = (random_serai_address(&mut OsRng), random_serai_address(&mut OsRng));
    let set_info = new_test_set_info(&[(v1, 1), (v2, 1)]);
    let set = set_info.set;

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, v1, "test reason");
      txn.commit();
    }

    assert_eq!(
      slash_report_transaction(&db, &set_info),
      Transaction::SlashReport { slash_points: vec![u32::MAX, 0], signed: Signed::default() }
    );
  }
}
