use std::time::Instant;

use rand_core::OsRng;

use ff::{Field, PrimeFieldBits};
use group::Group;

use k256::ProjectivePoint;
use dalek_ff_group::EdwardsPoint;

use crate::{straus, pippenger, multiexp, multiexp_vartime};

#[allow(dead_code)]
fn benchmark_internal<G: Group>(straus_bool: bool)
where
  G::Scalar: PrimeFieldBits,
{
  let runs: usize = 20;

  let mut start = 0;
  let mut increment: usize = 5;
  let mut total: usize = 250;
  let mut current = 2;

  if !straus_bool {
    start = 100;
    increment = 25;
    total = 1000;
    current = 4;
  };

  let mut pairs = Vec::with_capacity(total);
  let mut sum = G::identity();

  for _ in 0..start {
    pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
    sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
  }

  for _ in 0..(total / increment) {
    for _ in 0..increment {
      pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
      sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    }

    let now = Instant::now();
    for _ in 0..runs {
      if straus_bool {
        assert_eq!(straus(&pairs, current), sum);
      } else {
        assert_eq!(pippenger(&pairs, current), sum);
      }
    }
    let current_per = now.elapsed().as_micros() / u128::try_from(pairs.len()).unwrap();

    let now = Instant::now();
    for _ in 0..runs {
      if straus_bool {
        assert_eq!(straus(&pairs, current + 1), sum);
      } else {
        assert_eq!(pippenger(&pairs, current + 1), sum);
      }
    }
    let next_per = now.elapsed().as_micros() / u128::try_from(pairs.len()).unwrap();

    if next_per < current_per {
      current += 1;
      println!(
        "{} {} is more efficient at {} with {}µs per",
        if straus_bool { "Straus" } else { "Pippenger" },
        current,
        pairs.len(),
        next_per
      );
      if current >= 8 {
        return;
      }
    }
  }
}

fn test_multiexp<G: Group>()
where
  G::Scalar: PrimeFieldBits,
{
  let mut pairs = Vec::with_capacity(1000);
  let mut sum = G::identity();
  for _ in 0..10 {
    for _ in 0..100 {
      pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
      sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    }
    assert_eq!(multiexp(&pairs), sum);
    assert_eq!(multiexp_vartime(&pairs), sum);
  }
}

#[test]
fn test_secp256k1() {
  test_multiexp::<ProjectivePoint>();
}

#[test]
fn test_ed25519() {
  test_multiexp::<EdwardsPoint>();
}

#[ignore]
#[test]
fn benchmark() {
  // Activate the processor's boost clock
  for _ in 0..30 {
    test_multiexp::<ProjectivePoint>();
  }

  benchmark_internal::<ProjectivePoint>(true);
  benchmark_internal::<ProjectivePoint>(false);

  benchmark_internal::<EdwardsPoint>(true);
  benchmark_internal::<EdwardsPoint>(false);
}
