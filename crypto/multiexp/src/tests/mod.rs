use std::time::Instant;

use rand_core::OsRng;

use zeroize::Zeroize;

use ff::{Field, PrimeFieldBits};
use group::Group;

use k256::ProjectivePoint;
use dalek_ff_group::EdwardsPoint;

use crate::{straus, straus_vartime, pippenger, pippenger_vartime, multiexp, multiexp_vartime};

#[cfg(feature = "batch")]
mod batch;
#[cfg(feature = "batch")]
use batch::test_batch;

#[allow(dead_code)]
fn benchmark_internal<G: Group<Scalar: PrimeFieldBits + Zeroize>>(straus_bool: bool) {
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

  for _ in 0 .. start {
    pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
    sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
  }

  for _ in 0 .. (total / increment) {
    for _ in 0 .. increment {
      pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
      sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    }

    let now = Instant::now();
    for _ in 0 .. runs {
      if straus_bool {
        assert_eq!(straus(&pairs, current), sum);
      } else {
        assert_eq!(pippenger(&pairs, current), sum);
      }
    }
    let current_per = now.elapsed().as_micros() / u128::try_from(pairs.len()).unwrap();

    let now = Instant::now();
    for _ in 0 .. runs {
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

fn test_multiexp<G: Group<Scalar: PrimeFieldBits + Zeroize>>() {
  let test = |pairs: &[_], sum| {
    // These should automatically determine the best algorithm
    assert_eq!(multiexp(pairs), sum);
    assert_eq!(multiexp_vartime(pairs), sum);

    // Also explicitly test straus/pippenger for each bit size
    if !pairs.is_empty() {
      for window in 1 .. 8 {
        assert_eq!(straus(pairs, window), sum);
        assert_eq!(straus_vartime(pairs, window), sum);
        assert_eq!(pippenger(pairs, window), sum);
        assert_eq!(pippenger_vartime(pairs, window), sum);
      }
    }
  };

  // Test an empty multiexp is identity
  test(&[], G::identity());

  // Test an multiexp of identity/zero elements is identity
  test(&[(G::Scalar::ZERO, G::generator())], G::identity());
  test(&[(G::Scalar::ONE, G::identity())], G::identity());

  // Test a variety of multiexp sizes
  let mut pairs = Vec::with_capacity(1000);
  let mut sum = G::identity();
  for _ in 0 .. 10 {
    // Test a multiexp of a single item
    // On successive loop iterations, this will test a multiexp with an odd number of pairs
    pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
    sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    test(&pairs, sum);

    for _ in 0 .. 100 {
      pairs.push((G::Scalar::random(&mut OsRng), G::generator() * G::Scalar::random(&mut OsRng)));
      sum += pairs[pairs.len() - 1].1 * pairs[pairs.len() - 1].0;
    }
    test(&pairs, sum);
  }
}

#[test]
fn test_secp256k1() {
  test_multiexp::<ProjectivePoint>();
  #[cfg(feature = "batch")]
  test_batch::<ProjectivePoint>();
}

#[test]
fn test_ed25519() {
  test_multiexp::<EdwardsPoint>();
  #[cfg(feature = "batch")]
  test_batch::<EdwardsPoint>();
}

#[ignore]
#[test]
fn benchmark() {
  // Activate the processor's boost clock
  for _ in 0 .. 30 {
    test_multiexp::<ProjectivePoint>();
  }

  benchmark_internal::<ProjectivePoint>(true);
  benchmark_internal::<ProjectivePoint>(false);

  benchmark_internal::<EdwardsPoint>(true);
  benchmark_internal::<EdwardsPoint>(false);
}
