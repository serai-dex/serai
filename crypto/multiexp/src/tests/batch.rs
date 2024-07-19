use rand_core::OsRng;

use zeroize::Zeroize;

use rand_core::RngCore;

use ff::{Field, PrimeFieldBits};
use group::Group;

use crate::BatchVerifier;

pub(crate) fn test_batch<G: Group<Scalar: PrimeFieldBits + Zeroize> + Zeroize>() {
  let valid = |batch: BatchVerifier<_, G>| {
    assert!(batch.verify());
    assert!(batch.verify_vartime());
    assert_eq!(batch.blame_vartime(), None);
    assert_eq!(batch.verify_with_vartime_blame(), Ok(()));
    assert_eq!(batch.verify_vartime_with_vartime_blame(), Ok(()));
  };

  let invalid = |batch: BatchVerifier<_, G>, id| {
    assert!(!batch.verify());
    assert!(!batch.verify_vartime());
    assert_eq!(batch.blame_vartime(), Some(id));
    assert_eq!(batch.verify_with_vartime_blame(), Err(id));
    assert_eq!(batch.verify_vartime_with_vartime_blame(), Err(id));
  };

  // Test an empty batch
  let batch = BatchVerifier::new(0);
  valid(batch);

  // Test a batch with one set of statements
  let valid_statements = vec![(-G::Scalar::ONE, G::generator()), (G::Scalar::ONE, G::generator())];
  let mut batch = BatchVerifier::new(1);
  batch.queue(&mut OsRng, 0, valid_statements.clone());
  valid(batch);

  // Test a batch with an invalid set of statements fails properly
  let invalid_statements = vec![(-G::Scalar::ONE, G::generator())];
  let mut batch = BatchVerifier::new(1);
  batch.queue(&mut OsRng, 0, invalid_statements.clone());
  invalid(batch, 0);

  // Test blame can properly identify faulty participants
  // Run with 17 statements, rotating which one is faulty
  for i in 0 .. 17 {
    let mut batch = BatchVerifier::new(17);
    for j in 0 .. 17 {
      batch.queue(
        &mut OsRng,
        j,
        if i == j { invalid_statements.clone() } else { valid_statements.clone() },
      );
    }
    invalid(batch, i);
  }

  // Test blame always identifies the left-most invalid statement
  for i in 1 .. 32 {
    for j in 1 .. i {
      let mut batch = BatchVerifier::new(j);
      let mut leftmost = None;

      // Create j statements
      for k in 0 .. j {
        batch.queue(
          &mut OsRng,
          k,
          // The usage of i / 10 makes this less likely to add invalid elements, and increases
          // the space between them
          // For high i values, yet low j values, this will make it likely that random elements
          // are at/near the end
          if ((OsRng.next_u64() % u64::try_from(1 + (i / 4)).unwrap()) == 0) ||
            (leftmost.is_none() && (k == (j - 1)))
          {
            if leftmost.is_none() {
              leftmost = Some(k);
            }
            invalid_statements.clone()
          } else {
            valid_statements.clone()
          },
        );
      }

      invalid(batch, leftmost.unwrap());
    }
  }
}
