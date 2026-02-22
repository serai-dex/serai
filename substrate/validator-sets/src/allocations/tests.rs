use super::*;

#[test]
fn test_get_iter_update_allocations() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    let prior_network = NetworkId::deserialize_reader(&mut [0].as_slice()).unwrap();
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();
    let following_network = NetworkId::deserialize_reader(&mut [2].as_slice()).unwrap();

    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(prior_network, Amount(1));
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(network, Amount(1));
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
      following_network,
      Amount(1),
    );

    // Create allocations
    let rand_allocation = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      let key = SeraiAddress(key);
      let amount = Amount(OsRng.next_u64() >> 8);
      (key, amount)
    };
    const ALLOCATIONS: usize = 100;
    let mut allocations = vec![];
    for _ in 0 .. ALLOCATIONS {
      let (key, amount) = rand_allocation();
      allocations.push((key, amount));
      assert_eq!(update_allocation::<MockStorage>(network, key, amount), None);
      assert_eq!(MockStorage::allocation(network, key), Some(amount));
      assert_eq!(
        <MockStorage as AllocationsStorage>::SumAllocations::get(network),
        allocations.iter().fold(Amount(0), |accum, (_, alloc)| (accum + (*alloc)).unwrap())
      );
    }
    // Sort them from highest amount to lowest
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();

    // Set allocations for the previous and next network, by byte, to ensure the map isn't solely
    // these allocations. This ensures we don't read from another network accidentally
    {
      let (key, amount) = rand_allocation();
      assert_eq!(update_allocation::<MockStorage>(prior_network, key, amount), None);
      assert_eq!(update_allocation::<MockStorage>(following_network, key, amount), None);
    }

    // Check the iterator works
    {
      let mut a = MockStorage::iter_allocations(network, Amount(0));
      let mut b = allocations.clone().into_iter();
      for _ in 0 .. allocations.len() {
        let next = a.next().unwrap();
        assert_eq!(b.next().unwrap(), next);

        let (validator, amount) = next;
        assert_eq!(MockStorage::allocation(network, validator), Some(amount));
      }
      assert!(a.next().is_none());
      assert!(b.next().is_none());
    }

    // Check the minimum works
    {
      assert_eq!(
        MockStorage::iter_allocations(network, allocations[0].1).next(),
        Some(allocations[0])
      );
      assert_eq!(
        MockStorage::iter_allocations(
          network,
          // Fails with probability ~1/2**57
          (allocations[0].1 + Amount(1)).expect("1/2**57")
        )
        .next(),
        None,
      );
    }

    // Check updating an allocation works
    for _ in 0 .. (allocations.len() / 2) {
      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let i = (OsRng.next_u64() as usize) % allocations.len();
      if (OsRng.next_u64() & 1) == 1 {
        let new_amount = Amount(OsRng.next_u64() >> 8);
        assert_eq!(
          update_allocation::<MockStorage>(network, allocations[i].0, new_amount),
          Some(allocations[i].1)
        );
        allocations[i].1 = new_amount;
        assert_eq!(
          <MockStorage as AllocationsStorage>::SumAllocations::get(network),
          allocations.iter().fold(Amount(0), |accum, (_, alloc)| (accum + (*alloc)).unwrap())
        );
      } else {
        assert_eq!(
          update_allocation::<MockStorage>(network, allocations[i].0, Amount(0)),
          Some(allocations[i].1)
        );
        allocations.swap_remove(i);
        assert_eq!(
          <MockStorage as AllocationsStorage>::SumAllocations::get(network),
          allocations.iter().fold(Amount(0), |accum, (_, alloc)| (accum + (*alloc)).unwrap())
        );
      }
    }
    allocations.sort_by_key(|item| item.1);
    allocations.reverse();
    {
      let mut a = MockStorage::iter_allocations(network, Amount(0));
      let mut b = allocations.clone().into_iter();
      for _ in 0 .. allocations.len() {
        let next = a.next().unwrap();
        assert_eq!(b.next().unwrap(), next);

        let (validator, amount) = next;
        assert_eq!(MockStorage::allocation(network, validator), Some(amount));
      }
      assert!(a.next().is_none());
      assert!(b.next().is_none());
    }
  });
}

#[test]
fn test_expected_key_shares() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use serai_abi::primitives::coin::Coin;
  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    // 10k SRI
    const ALLOCATIONS_PER_KEY_SHARE: Amount = Amount(10_000 * 10u64.pow(Coin::Serai.decimals()));
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();

    let mut total_key_shares = 0;
    while total_key_shares < (2 * KeyShares::MAX_PER_SET) {
      // get random key share amount
      let (key, amount) = {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        let key = SeraiAddress(key);
        // allow up to 10 key share
        let amount = Amount(OsRng.next_u64() % (ALLOCATIONS_PER_KEY_SHARE.0 * 10));
        (key, amount)
      };
      let key_share = u16::try_from(amount.0 / ALLOCATIONS_PER_KEY_SHARE.0).unwrap();
      if key_share < 1 {
        continue;
      }

      // allocate the amount
      total_key_shares = total_key_shares.checked_add(key_share).expect("no overflow");
      assert_eq!(update_allocation::<MockStorage>(network, key, amount), None);

      // check we produce correct number of key shares
      assert_eq!(
        KeyShares::saturating_from(total_key_shares),
        expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE)
      );
    }
  });
}

#[test]
fn test_currently_tolerates_single_point_of_failure() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use serai_abi::primitives::coin::Coin;
  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    // 10k SRI
    const ALLOCATIONS_PER_KEY_SHARE: Amount = Amount(10_000 * 10u64.pow(Coin::Serai.decimals()));
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();

    let rand_key = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      SeraiAddress(key)
    };

    // should return false if no allocation yet
    assert!(!currently_tolerates_single_point_of_failure::<MockStorage>(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
      expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE)
    ));

    // should return true if no single allocation is >= 1/3 of total key shares
    for _ in 0 .. 5 {
      let (key, amount) = {
        let key = rand_key();
        // allow between 1-2 key share
        let amount = Amount(
          ALLOCATIONS_PER_KEY_SHARE.0 + (OsRng.next_u64() % (ALLOCATIONS_PER_KEY_SHARE.0 * 2)),
        );
        (key, amount)
      };
      assert_eq!(update_allocation::<MockStorage>(network, key, amount), None);
    }
    assert!(currently_tolerates_single_point_of_failure::<MockStorage>(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
      expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE)
    ));

    // should return false if a single allocation is exactly 1/3 of total key shares
    // this as we want `n >= 3f + 1` which means `(n - f) >= 2f + 1`
    let mut current_total =
      u16::from(expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE));
    if current_total % 2 == 1 {
      assert_eq!(
        update_allocation::<MockStorage>(network, rand_key(), ALLOCATIONS_PER_KEY_SHARE),
        None
      );
      current_total += 1;
    }
    let big_key = rand_key();
    let key_shares_for_big_key = current_total / 2;
    assert_eq!(
      update_allocation::<MockStorage>(
        network,
        big_key,
        Amount(u64::from(key_shares_for_big_key) * ALLOCATIONS_PER_KEY_SHARE.0)
      ),
      None
    );

    assert_eq!(
      key_shares_for_big_key * 3,
      u16::from(expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE))
    );
    assert!(!currently_tolerates_single_point_of_failure::<MockStorage>(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
      expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE)
    ));

    // should return false if a single allocation > 1/3 of total key shares
    update_allocation::<MockStorage>(
      network,
      big_key,
      Amount(u64::from(current_total / 2 + 1) * ALLOCATIONS_PER_KEY_SHARE.0),
    );
    assert!(!currently_tolerates_single_point_of_failure::<MockStorage>(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
      expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE)
    ));
  });
}

#[test]
fn test_increase_allocation_without_updating_other_contexts() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use serai_abi::primitives::coin::Coin;
  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    // 10k SRI
    const ALLOCATIONS_PER_KEY_SHARE: Amount = Amount(10_000 * 10u64.pow(Coin::Serai.decimals()));
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();
    let reward = false;
    let rand_key = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      SeraiAddress(key)
    };

    let validator = rand_key();
    let mut allocation_amount = ALLOCATIONS_PER_KEY_SHARE.0 - 1;

    // should fail before we set the auxiliary keys for the validator
    assert_eq!(
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(allocation_amount),
        reward,
      ),
      Err(AllocationError::MissingAuxiliaryKeys)
    );

    // set the keys
    MockStorage::set_random_auxiliary_keys(validator);

    // should fail if there is no ALLOCATIONS_PER_KEY_SHARE set
    assert_eq!(
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(allocation_amount),
        reward,
      ),
      Err(AllocationError::NoAllocationPerKeyShareSet)
    );

    // set allocations per key share
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
    );

    // should fail if amount is less than ALLOCATIONS_PER_KEY_SHARE
    assert_eq!(
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(allocation_amount),
        reward,
      ),
      Err(AllocationError::AllocationLessThanKeyShare)
    );

    // should fail if we guarantee single point of failure
    let mut key_shares = ((KeyShares::MAX_PER_SET - 1) / 3) + 1;
    allocation_amount = u64::from(key_shares) * ALLOCATIONS_PER_KEY_SHARE.0;
    assert_eq!(
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(allocation_amount),
        reward,
      ),
      Err(AllocationError::IntroducesSinglePointOfFailure)
    );

    // should succeed otherwise
    key_shares /= 5;
    allocation_amount = u64::from(key_shares) * ALLOCATIONS_PER_KEY_SHARE.0;
    MockStorage::increase_allocation_without_updating_other_contexts(
      network,
      validator,
      Amount(allocation_amount),
      reward,
    )
    .unwrap();

    // allocate a few more times so we can tolerate single point of failure
    for _ in 0 .. 5 {
      let validator = rand_key();
      MockStorage::set_random_auxiliary_keys(validator);
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(allocation_amount),
        reward,
      )
      .unwrap();
    }

    // now try to allocate such that we become the single point of failure
    // we have an existing allocation same as everybody else, we now try to allocate 1/3 of the
    // total making us more than 1/3 since we already have existing allocation.
    let current_total = expected_key_shares::<MockStorage>(network, ALLOCATIONS_PER_KEY_SHARE);
    assert_eq!(u16::from(current_total), 48);

    // we try to allocate 16 + we already have 8 making us 24 out of 48 + 16 = 64.
    // since 64 / 3 = 21 we can't have more than that. So we would fail here.
    let increase_key_shares = u16::from(current_total) / 3;
    let increase_amount = u64::from(increase_key_shares) * ALLOCATIONS_PER_KEY_SHARE.0;
    assert_eq!(
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator,
        Amount(increase_amount),
        reward,
      ),
      Err(AllocationError::IntroducesSinglePointOfFailure)
    );

    // we should succeed if we try increase by any less amount than that
    // we try to allocate 16 < 21 as a total by subtracting our existing stake.
    let increase_key_shares = (u16::from(current_total) / 3) -
      u16::from(KeyShares::from_allocation(Amount(allocation_amount), ALLOCATIONS_PER_KEY_SHARE));
    let increase_amount = u64::from(increase_key_shares) * ALLOCATIONS_PER_KEY_SHARE.0;
    MockStorage::increase_allocation_without_updating_other_contexts(
      network,
      validator,
      Amount(increase_amount),
      reward,
    )
    .unwrap();

    // TODO: do we need to test reward = true test cases? Making sure all is ignored in that case?
  });
}

#[test]
fn test_decrease_allocation_without_updating_other_contexts() {
  use rand_core::{RngCore as _, OsRng};

  use borsh::BorshDeserialize as _;

  use sp_io::TestExternalities;

  use serai_abi::primitives::coin::Coin;
  use crate::MockStorage;

  TestExternalities::default().execute_with(|| {
    // 10k SRI
    const ALLOCATIONS_PER_KEY_SHARE: Amount = Amount(10_000 * 10u64.pow(Coin::Serai.decimals()));
    let network = NetworkId::deserialize_reader(&mut [1].as_slice()).unwrap();
    let reward = false;
    let rand_key = || {
      let mut key = [0; 32];
      OsRng.fill_bytes(&mut key);
      SeraiAddress(key)
    };

    // set allocations per key share so that we can allocate first
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
    );

    // first allocate some stake for the network
    let key_shares = 5u64;
    let allocation_amount = ALLOCATIONS_PER_KEY_SHARE.0 * key_shares;
    let mut validators = vec![];
    for _ in 0 .. 6 {
      let validator_local = rand_key();
      MockStorage::set_random_auxiliary_keys(validator_local);
      MockStorage::increase_allocation_without_updating_other_contexts(
        network,
        validator_local,
        Amount(allocation_amount),
        reward,
      )
      .unwrap();
      validators.push(validator_local);
    }

    // should fail if no AllocationPerKeyShare set
    let validator = validators.first().unwrap();
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::remove(network);
    assert_eq!(
      MockStorage::decrease_allocation_without_updating_other_contexts(
        network,
        *validator,
        Amount(allocation_amount)
      ),
      Err(DeallocationError::NoAllocationPerKeyShareSet)
    );
    <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
      network,
      ALLOCATIONS_PER_KEY_SHARE,
    );

    // should fail if we try to deallocate more than we allocated
    assert_eq!(
      MockStorage::decrease_allocation_without_updating_other_contexts(
        network,
        *validator,
        Amount(allocation_amount + 1)
      ),
      Err(DeallocationError::NotEnoughAllocated)
    );

    // should fail if we have left less then 1 key share as a result of deallocation
    assert_eq!(
      MockStorage::decrease_allocation_without_updating_other_contexts(
        network,
        *validator,
        Amount(((key_shares - 1) * ALLOCATIONS_PER_KEY_SHARE.0) + 1)
      ),
      Err(DeallocationError::RemainingAllocationLessThanKeyShare)
    );

    // should fail if we are pre-economic security era
    assert_eq!(
      MockStorage::decrease_allocation_without_updating_other_contexts(
        network,
        *validator,
        Amount(allocation_amount),
      ),
      Err(DeallocationError::EconomicSecurity)
    );
    // make sure all other networks reached the economic security
    for n in NetworkId::all() {
      if n == network {
        continue;
      }

      <MockStorage as AllocationsStorage>::AllocationPerKeyShare::insert(
        n,
        ALLOCATIONS_PER_KEY_SHARE,
      );
      let validator_local = rand_key();
      MockStorage::set_random_auxiliary_keys(validator_local);
      MockStorage::increase_allocation_without_updating_other_contexts(
        n,
        validator_local,
        mock::STAKE_REQUIREMENT,
        reward,
      )
      .unwrap();
    }

    // TODO: should also fail if deallocation would remove the ec security of the network
    // but we can't hit it since IntroducesSinglePointOfFailure comes before in this case.
    // Ideally EconomicSecurity error comes before but then we wouldn't hit the
    // IntroducesSinglePointOfFailure error in that case. Maybe a carefully constructed set
    // can hit both of them?

    // should fail if we introduce single point of failure as a result of deallocation
    // we should be able to deallocate until we hit that point.
    for (i, val) in validators.iter().enumerate() {
      if i < ((validators.len() / 2) - 1) {
        MockStorage::decrease_allocation_without_updating_other_contexts(
          network,
          *val,
          Amount(allocation_amount),
        )
        .unwrap();
      } else {
        assert_eq!(
          MockStorage::decrease_allocation_without_updating_other_contexts(
            network,
            *val,
            Amount(allocation_amount),
          ),
          Err(DeallocationError::IntroducesSinglePointOfFailure)
        );
        break;
      }
    }
  });
}
