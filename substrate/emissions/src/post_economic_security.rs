use sp_core::U256;

use serai_abi::primitives::balance::Amount;

/// The fraction of rewards which should go to an external network's validators, per the
/// post-Economic Security policy.
///
/// This is programmed to never panic. The fraction will be within the range `0 ..= 1`. The
/// numerator and denominator will fit within `u192`, enabling further scaling by a `u64`, and
/// the denominator will be non-zero, ensuring it can be divided by.
/*
  This can be hard to immediately understand. It's calculating the ratio of two values themselves
  represented as fractions to calculate the specified ratio, before returning not the ratio but the
  fraction of the total one side of the ratio represents.

  In order to understand this, the following walkthrough on the premise is recommended.

  ```py
  DESIRED_UNUSED_CAPACITY = 0.1
  DESIRED_DISTRIBUTION = 1 - DESIRED_UNUSED_CAPACITY
  def ratio(CURRENT_DISTRIBUTION):
    print(
      str(DESIRED_UNUSED_CAPACITY) +
        ':' +
        str(((1 - CURRENT_DISTRIBUTION) * DESIRED_DISTRIBUTION) / CURRENT_DISTRIBUTION)
    )
  ```

  For `CURRENT_DISTRIBUTION`, a number in range `0 ..= 1` representing the percentage of capacity
  actively consumed by requirements, this will print the ratio specified in the Economics
  specification.

  ```
  >>> ratio(0.9)
  0.1:0.09999999999999998
  ```

  When 90% of the current capacity is consumed, as is our target, the ratio is effectively `1 : 1`.
  Note the literal numeric values are `0.1 : 0.1` but that doesn't matter as all that matters is
  their relation to each other.

  ```
  >>> ratio(0.95)
  0.1:0.04736842105263162
  ```

  When 95% of capacity is consumed, as over our target, validators receive more than
  _twice as much_ of the rewards than the liquidity pools.

  ```
  >>> ratio(0.85)
  0.1:0.15882352941176475
  ```

  But when only 85% of capacity is consumed, as under our target, liquidity pools receive more than
  50% more of the rewards than the validators.

  ```
  >>> ratio(1)
  0.1:0.0
  ```

  And of course, if the entire capacity is consumed, all rewards go to the validators as the ratio
  becomes infinite.

  This function computes the ratio before computing what fraction of the total the validators, the
  left-hand term of the ratio, represent. For a ratio `2 : 3` (as approximate to the case when 85%
  of capacity is consumed), this will yield `2 / 5`, saying the validators should receive 40% of
  the rewards (and the liquidity pools the rest, the 60%).

  The complexity is that this function does so while avoiding floating point numbers, requiring
  keeping track of all fractions as their numerator/denominators, making sure to note the bounds
  as needed to prevent over/underflows, and while not dividing by zero.
*/
pub(crate) fn external_network_validator_rewards_fraction(
  used_capacity: Amount,
  capacity_of_network: Amount,
) -> (U256, U256) {
  /*
    `DESIRED_UNUSED_CAPACITY = 0.1`

    This fraction has to be any non-zero accurate representation where it should be irreducible to
    minimize the risks of overflows.
  */
  const DESIRED_UNUSED_CAPACITY: (u8, u8) = (1, 10);
  /*
    `DESIRED_DISTRIBUTION = 1 - DESIRED_UNUSED_CAPACITY`

    This is `(1 / 1) - DESIRED_UNUSED_CAPACITY`, with `1 / 1` represented as
    `DESIRED_UNUSED_CAPACITY_DENOM / DESIRED_UNUSED_CAPACITY_DENOM` to allow us to perform the
    subtraction.
  */
  const DESIRED_DISTRIBUTION: (u8, u8) =
    (DESIRED_UNUSED_CAPACITY.1 - DESIRED_UNUSED_CAPACITY.0, DESIRED_UNUSED_CAPACITY.1);

  // There cannot be more capacity used than in existence, even if we _require_ more than exists
  let used_capacity = used_capacity.min(capacity_of_network);

  // If this network lacks capacity, state it should receive `1/1` of the rewards
  if capacity_of_network == Amount(0) {
    return (U256::one(), U256::one());
  } else if used_capacity == Amount(0) {
    // If this network has capacity but none is used, say the validators should get `0/1`
    // (so the pools receive `1/1`)
    return (U256::zero(), U256::one());
  }

  let current_distribution = (used_capacity.0, capacity_of_network.0);

  // These values are bounded `0 ..= u8::MAX`
  let ratio_term_for_validators = DESIRED_UNUSED_CAPACITY;

  // `((1 - CURRENT_DISTRIBUTION) * DESIRED_DISTRIBUTION) / CURRENT_DISTRIBUTION`
  let ratio_term_for_pools = {
    let one_minus_current_distribution_times_desired_distribution = {
      // This won't trap as `current_distribution <= 1`
      // These values are bounded `0 ..= u64::MAX`
      let one_minus_current_distribution =
        (current_distribution.1 - current_distribution.0, current_distribution.1);
      // These values are bounded `0 ..= u72::MAX`
      (
        u128::from(one_minus_current_distribution.0) *
          u128::from(u16::from(DESIRED_DISTRIBUTION.0)),
        u128::from(one_minus_current_distribution.1) *
          u128::from(u16::from(DESIRED_DISTRIBUTION.1)),
      )
    };
    // These values are bounded `0 ..= u136::MAX`
    (
      U256::from(one_minus_current_distribution_times_desired_distribution.0) *
        U256::from(u128::from(current_distribution.1)),
      U256::from(one_minus_current_distribution_times_desired_distribution.1) *
        U256::from(u128::from(current_distribution.0)),
    )
  };

  // `ratio_term_for_validators / ratio_term_for_pools`
  // These values are bounded `0 ..= u144::MAX`
  let ratio = (
    U256::from(u16::from(ratio_term_for_validators.0)) * ratio_term_for_pools.1,
    U256::from(u16::from(ratio_term_for_validators.1)) * ratio_term_for_pools.0,
  );

  // Now that we have the ratio, we convert to the validators' fraction, as useful by consumers.
  // These values are bounded `0 ..= u145::MAX` which is a subset of `0 ..= u192::MAX`, the
  // documented bound for the returned values from this function
  (ratio.0, ratio.0 + ratio.1)
}

#[test]
fn test_values() {
  let mut used_capacity = Amount(0);
  let mut capacity_of_network = Amount(0);

  // validators should get 100% if network has no capacity
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num / den, U256::from(1));

  // at 0% utilization ratio, validators should get 0%
  capacity_of_network = Amount(100);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num / den, U256::from(0));

  // at 50% utilization ratio, validators should get 10%
  used_capacity = Amount(50);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num * 10, den);

  // at 75% utilization ratio, validators should get 25%
  used_capacity = Amount(75);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num * 4, den);

  // 90% is our ideal utilization ratio. Validators and pools should get 50% in this case.
  used_capacity = Amount(90);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num * 2, den);

  // at 100% utilization ratio, validators should get 100%
  used_capacity = Amount(100);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num, den);

  // anything more than 100%, validators should still get 100%
  used_capacity = Amount(110);
  let (num, den) = external_network_validator_rewards_fraction(used_capacity, capacity_of_network);
  assert_eq!(num, den);
}

#[test]
#[expect(
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::cast_precision_loss,
  clippy::cast_sign_loss
)]
fn fuzz_test() {
  use rand_core::{RngCore as _, OsRng};

  // edge values to include alongside random inputs
  let edge_values = [0, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX];

  // test all edge value combinations
  for &used in &edge_values {
    for &capacity in &edge_values {
      let (num, den) = external_network_validator_rewards_fraction(Amount(used), Amount(capacity));

      // denominator must always be non-zero
      assert!(den > U256::zero());
      // fraction must be <= 1
      assert!(num <= den);
    }
  }

  // test on random inputs
  for _ in 0 .. 100_000 {
    let used = OsRng.next_u64();
    let capacity = OsRng.next_u64();
    let (num, den) = external_network_validator_rewards_fraction(Amount(used), Amount(capacity));

    assert!(den > U256::zero());
    assert!(num <= den);
    assert!(den.bits() <= 192);

    // Calculate this with floats, as the Python pseudo-code would
    let desired_unused_capacity = 0.1f64;
    let desired_distribution = 1f64 - desired_unused_capacity;
    let current_distribution = (used.min(capacity) as f64) / (capacity as f64);
    if !current_distribution.is_normal() {
      assert_eq!(num, U256::zero());
    } else {
      let ratio_lhs = desired_unused_capacity;
      let ratio_rhs = ((1f64 - current_distribution) * desired_distribution) / current_distribution;
      let float_num = ratio_lhs;
      let float_denom = ratio_lhs + ratio_rhs;

      // Compare that these values are equivalent within an error of term of 1/1_000_000_000
      let via_float = (((u64::MAX as f64) * float_num) / float_denom) as u64;
      let via_fraction = u64::try_from((U256::from(u64::MAX) * num) / den).unwrap();
      assert!(via_float.abs_diff(via_fraction) < (u64::MAX / 10u64.pow(9)));
    }
  }
}
