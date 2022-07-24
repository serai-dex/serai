use rand::rngs::OsRng;

use crate::{Commitment, random_scalar, ringct::bulletproofs::Bulletproofs};

#[test]
fn bulletproofs() {
  // Create Bulletproofs for all possible output quantities
  for i in 1 .. 17 {
    let commitments =
      (1 ..= i).map(|i| Commitment::new(random_scalar(&mut OsRng), i)).collect::<Vec<_>>();

    assert!(Bulletproofs::new(&mut OsRng, &commitments)
      .unwrap()
      .verify(&mut OsRng, &commitments.iter().map(Commitment::calculate).collect::<Vec<_>>()));
  }

  // Check it errors if we try to create too many
  assert!(
    Bulletproofs::new(&mut OsRng, &[Commitment::new(random_scalar(&mut OsRng), 1); 17]).is_err()
  );
}
