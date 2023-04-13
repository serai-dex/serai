use std::collections::HashSet;

use rand::{RngCore, rngs::OsRng};

#[test]
fn merkle() {
  let mut used = HashSet::new();
  // Test this produces a unique root
  let mut test = |hashes: &[[u8; 32]]| {
    let hash = crate::merkle(hashes);
    assert!(!used.contains(&hash));
    used.insert(hash);
  };

  // Zero should be a special case which return 0
  assert_eq!(crate::merkle(&[]), [0; 32]);
  test(&[]);

  let mut one = [0; 32];
  OsRng.fill_bytes(&mut one);
  let mut two = [0; 32];
  OsRng.fill_bytes(&mut two);
  let mut three = [0; 32];
  OsRng.fill_bytes(&mut three);

  // Make sure it's deterministic
  assert_eq!(crate::merkle(&[one]), crate::merkle(&[one]));

  // Test a few basic structures
  test(&[one]);
  test(&[one, two]);
  test(&[one, two, three]);
  test(&[one, three]);
}
