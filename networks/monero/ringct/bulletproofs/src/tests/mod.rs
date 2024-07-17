use rand_core::{RngCore, OsRng};

use curve25519_dalek::scalar::Scalar;

use monero_primitives::Commitment;
use crate::{batch_verifier::BatchVerifier, Bulletproof, BulletproofError};

mod original;
mod plus;

macro_rules! bulletproofs_tests {
  ($name: ident, $max: ident, $plus: literal) => {
    #[test]
    fn $name() {
      // Create Bulletproofs for all possible output quantities
      let mut verifier = BatchVerifier::new();
      for i in 1 ..= 16 {
        let commitments = (1 ..= i)
          .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
          .collect::<Vec<_>>();

        let bp = if $plus {
          Bulletproof::prove_plus(&mut OsRng, commitments.clone()).unwrap()
        } else {
          Bulletproof::prove(&mut OsRng, commitments.clone()).unwrap()
        };

        let commitments = commitments.iter().map(Commitment::calculate).collect::<Vec<_>>();
        assert!(bp.verify(&mut OsRng, &commitments));
        assert!(bp.batch_verify(&mut OsRng, &mut verifier, &commitments));
      }
      assert!(verifier.verify());
    }

    #[test]
    fn $max() {
      // Check Bulletproofs errors if we try to prove for too many outputs
      let mut commitments = vec![];
      for _ in 0 .. 17 {
        commitments.push(Commitment::new(Scalar::ZERO, 0));
      }
      assert_eq!(
        (if $plus {
          Bulletproof::prove_plus(&mut OsRng, commitments)
        } else {
          Bulletproof::prove(&mut OsRng, commitments)
        })
        .unwrap_err(),
        BulletproofError::TooManyCommitments,
      );
    }
  };
}

bulletproofs_tests!(bulletproofs, bulletproofs_max, false);
bulletproofs_tests!(bulletproofs_plus, bulletproofs_plus_max, true);
