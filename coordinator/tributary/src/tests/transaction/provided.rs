use std::collections::{HashSet, HashMap};

use rand::rngs::OsRng;

use crate::{Transaction, verify_transaction, tests::random_provided_transaction};

#[test]
fn provided_transaction() {
  let tx = random_provided_transaction(&mut OsRng);

  // Make sure this works when provided
  let mut provided = HashSet::from([tx.hash()]);
  verify_transaction(&tx, [0x88; 32], &mut provided, &mut HashMap::new()).unwrap();
  assert_eq!(provided.len(), 0);

  // Make sure this fails when not provided
  assert!(verify_transaction(&tx, [0x88; 32], &mut HashSet::new(), &mut HashMap::new()).is_err());
}
