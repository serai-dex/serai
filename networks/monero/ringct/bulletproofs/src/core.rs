use std_shims::{vec, vec::Vec};

use curve25519_dalek::{
  traits::{MultiscalarMul, VartimeMultiscalarMul},
  scalar::Scalar,
  edwards::EdwardsPoint,
};

pub(crate) use monero_generators::{MAX_COMMITMENTS, COMMITMENT_BITS, LOG_COMMITMENT_BITS};

pub(crate) fn multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  let mut buf_scalars = Vec::with_capacity(pairs.len());
  let mut buf_points = Vec::with_capacity(pairs.len());
  for (scalar, point) in pairs {
    buf_scalars.push(scalar);
    buf_points.push(point);
  }
  EdwardsPoint::multiscalar_mul(buf_scalars, buf_points)
}

pub(crate) fn multiexp_vartime(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  let mut buf_scalars = Vec::with_capacity(pairs.len());
  let mut buf_points = Vec::with_capacity(pairs.len());
  for (scalar, point) in pairs {
    buf_scalars.push(scalar);
    buf_points.push(point);
  }
  EdwardsPoint::vartime_multiscalar_mul(buf_scalars, buf_points)
}

/*
This has room for optimization worth investigating further. It currently takes
an iterative approach. It can be optimized further via divide and conquer.

Assume there are 4 challenges.

Iterative approach (current):
  1. Do the optimal multiplications across challenge column 0 and 1.
  2. Do the optimal multiplications across that result and column 2.
  3. Do the optimal multiplications across that result and column 3.

Divide and conquer (worth investigating further):
  1. Do the optimal multiplications across challenge column 0 and 1.
  2. Do the optimal multiplications across challenge column 2 and 3.
  3. Multiply both results together.

When there are 4 challenges (n=16), the iterative approach does 28 multiplications
versus divide and conquer's 24.
*/
pub(crate) fn challenge_products(challenges: &[(Scalar, Scalar)]) -> Vec<Scalar> {
  let mut products = vec![Scalar::ONE; 1 << challenges.len()];

  if !challenges.is_empty() {
    products[0] = challenges[0].1;
    products[1] = challenges[0].0;

    for (j, challenge) in challenges.iter().enumerate().skip(1) {
      let mut slots = (1 << (j + 1)) - 1;
      while slots > 0 {
        products[slots] = products[slots / 2] * challenge.0;
        products[slots - 1] = products[slots / 2] * challenge.1;

        slots = slots.saturating_sub(2);
      }
    }

    // Sanity check since if the above failed to populate, it'd be critical
    for product in &products {
      debug_assert!(*product != Scalar::ZERO);
    }
  }

  products
}
