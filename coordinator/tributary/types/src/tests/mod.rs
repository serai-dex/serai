use rand::{Rng as _, RngCore as _, rngs::OsRng};

use serai_primitives::test_helpers::random_ristretto_public_key_bytes;
use serai_primitives::test_helpers::random_embedwards_key_bytes;

use crate::{
  test_helpers::{random_external_network_key, random_tributary_validator, u16_to_participant},
  *,
};

use serai_env::test_helpers::new_test_rng;

#[test]
fn constants() {
  assert_eq!(PARTICIPATION_THRESHOLD_NUMERATOR, 2);
  assert_eq!(PARTICIPATION_THRESHOLD_DENOMINATOR, 3);
  const {
    assert!(PARTICIPATION_THRESHOLD_NUMERATOR < PARTICIPATION_THRESHOLD_DENOMINATOR);
  }
}

#[test]
fn required_participation_formula() {
  assert_eq!(required_participation(0), 1);
  assert_eq!(required_participation(1), 1);
  assert_eq!(required_participation(2), 2);
  assert_eq!(required_participation(4), 3);
  assert_eq!(required_participation(8), 6);
  assert_eq!(required_participation(u16::MAX), 43691);
  let n: u16 = OsRng.gen();
  assert_eq!(required_participation(n), u16::try_from(u32::from(n) * 2 / 3 + 1).unwrap());
}

#[test]
fn participant_index_to_list_index_formula() {
  // Participant 0 should always be None, so it can never be passed as param
  std::panic::catch_unwind(|| participant_index_to_list_index(u16_to_participant(0))).unwrap_err();

  assert_eq!(participant_index_to_list_index(u16_to_participant(1)), Some(0));
  assert_eq!(
    participant_index_to_list_index(u16_to_participant(u16::MAX)),
    Some(usize::from(u16::MAX) - 1)
  );
  let n: u16 = OsRng.gen();
  assert_eq!(participant_index_to_list_index(u16_to_participant(n)), Some(usize::from(n) - 1));
}

#[test]
fn init_dkg_participant_indexes_scenarios() {
  let mut rng = new_test_rng();

  // Two different validators with all different keys
  {
    let set = TributaryValidatorSet::new(vec![
      random_tributary_validator(&mut rng, 1),
      random_tributary_validator(&mut rng, 2),
    ]);
    assert_eq!(set.evrf_participant_indexes.len(), 2);
    assert_eq!(set.evrf_participant_indexes_reverse_lookup.len(), 3);
    assert_eq!(set.evrf_networks_substrate_keys().len(), 3);
    assert_eq!(set.evrf_networks_external_keys().len(), 3);
    assert_eq!(set.total_weight(), 3);
    assert_eq!(set.evrf_threshold(), required_participation(2));
    assert_eq!(set.required_participation(), required_participation(3));
  }

  // Different validators sharing the same NetworkId::Serai auxiliary key but different
  // (substrate, external)
  {
    let serai_key = random_ristretto_public_key_bytes(&mut rng);
    let set = TributaryValidatorSet::new(vec![
      TributaryValidator::new(
        serai_key,
        random_embedwards_key_bytes(&mut rng),
        random_external_network_key(&mut rng),
        1,
      ),
      TributaryValidator::new(
        serai_key,
        random_embedwards_key_bytes(&mut rng),
        random_external_network_key(&mut rng),
        2,
      ),
    ]);
    // `evrf_participant_indexes` is keyed by the full `TributaryValidator`, so
    // distinct (substrate, external) tuples remain distinct entries even when
    // they share a serai key.
    assert_eq!(set.evrf_participant_indexes.len(), 2);
    assert_eq!(set.evrf_participant_indexes_reverse_lookup.len(), 3);
    assert_eq!(set.evrf_networks_substrate_keys().len(), 3);
    assert_eq!(set.evrf_networks_external_keys().len(), 3);
    // but `consensus_participant_indexes` flattens to just one signing identity with aggregate
    // weight
    assert_eq!(set.consensus_participant_index.len(), 1);
    assert_eq!(set.consensus_tributary_validators.len(), 1);
    assert_eq!(set.total_weight(), 3);
    assert_eq!(set.evrf_threshold(), required_participation(2));
    assert_eq!(set.required_participation(), required_participation(3));
  }

  // Different validators sharing the same (substrate, external) pair but different NetworkId::Serai
  // auxiliary keys
  {
    let shared_substrate = random_embedwards_key_bytes(&mut rng);
    let shared_external = random_external_network_key(&mut rng);

    let set = TributaryValidatorSet::new(vec![
      random_tributary_validator(&mut rng, 1),
      TributaryValidator::new(
        random_ristretto_public_key_bytes(&mut rng),
        shared_substrate,
        shared_external.clone(),
        1,
      ),
      TributaryValidator::new(
        random_ristretto_public_key_bytes(&mut rng),
        shared_substrate,
        shared_external.clone(),
        2,
      ),
    ]);

    // 3 different TributaryValidator items as a different NetworkId::Serai auxiliary key
    // makes them different objects. Even if able to decrypt each other's shares on the
    // processor, each coordinator tracks the amount of shares they're supposed to
    // have by their eVRF public keys.
    assert_eq!(set.evrf_participant_indexes.len(), 3);
    assert_eq!(set.evrf_participant_indexes_reverse_lookup.len(), 4);
    assert_eq!(set.evrf_networks_substrate_keys().len(), 4);
    assert_eq!(set.evrf_networks_external_keys().len(), 4);
    assert_eq!(set.total_weight(), 4);
    assert_eq!(set.evrf_threshold(), required_participation(3));
    assert_eq!(set.required_participation(), required_participation(3));
  }
}

#[test]
fn borsh_roundtrip() {
  let mut rng = new_test_rng();
  let weight_1 = 1;
  let weight_2 = 3;
  let total_weight = weight_1 + weight_2;

  let v1 = random_tributary_validator(&mut rng, weight_1);
  let v2 = random_tributary_validator(&mut rng, weight_2);

  let tributary_validator_set = TributaryValidatorSet::new(vec![v1.clone(), v2.clone()]);

  // Deterministic
  let bytes = borsh::to_vec(&tributary_validator_set).unwrap();
  {
    assert_eq!(
      bytes,
      borsh::to_vec(&tributary_validator_set).unwrap(),
      "borsh serialization should be deterministic"
    );
  }

  // Roundtrip
  {
    let deserialized: TributaryValidatorSet = borsh::from_slice(&bytes).unwrap();

    assert_eq!(
      deserialized.consensus_tributary_validators,
      tributary_validator_set.consensus_tributary_validators
    );
    assert_eq!(
      deserialized.evrf_participant_indexes,
      tributary_validator_set.evrf_participant_indexes
    );
    assert_eq!(
      deserialized.evrf_participant_indexes_reverse_lookup,
      tributary_validator_set.evrf_participant_indexes_reverse_lookup
    );
    assert_eq!(deserialized.evrf_participant_indexes.len(), 2);
    assert_eq!(
      deserialized.evrf_participant_indexes_reverse_lookup.len(),
      usize::from(total_weight)
    );
    assert_eq!(deserialized.total_weight(), tributary_validator_set.total_weight());
    assert_eq!(deserialized.evrf_threshold(), tributary_validator_set.evrf_threshold());
    assert_eq!(
      deserialized.required_participation(),
      tributary_validator_set.required_participation()
    );
  }

  // Comprehensive: the borsh bytes must be in declaration order.
  {
    let expected = borsh::to_vec(&vec![v1.clone(), v2.clone()]).unwrap();
    assert_eq!(bytes, expected);
    let not_expected = borsh::to_vec(&vec![v2.clone(), v1.clone()]).unwrap();
    assert_ne!(bytes, not_expected);
  }

  // Changing any single field must produce different bytes.
  {
    {
      let mut other = tributary_validator_set.clone();
      other.initial_tributary_validators[0].serai_networks_auxiliary_key[0] ^= 1;
      assert_ne!(borsh::to_vec(&other).unwrap(), bytes);
    }
    {
      let mut other = tributary_validator_set.clone();
      other.initial_tributary_validators[0].networks_substrate_key[0] ^= 1;
      assert_ne!(borsh::to_vec(&other).unwrap(), bytes);
    }
    {
      let mut other = tributary_validator_set.clone();
      other.initial_tributary_validators[0].networks_external_key[0] ^= 1;
      assert_ne!(borsh::to_vec(&other).unwrap(), bytes);
    }
    {
      let mut other = tributary_validator_set.clone();
      other.initial_tributary_validators[0].weight = v1.weight.wrapping_add(1).max(1);
      assert_ne!(borsh::to_vec(&other).unwrap(), bytes);
    }
  }

  // Every #[borsh(skip)] field is excluded from serialization, so mutating any of them
  // must not change the bytes.
  {
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.consensus_tributary_validators.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.consensus_participant_index.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.total_weight = mutated.total_weight.wrapping_add(1);
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.evrf_threshold = mutated.evrf_threshold.wrapping_add(1);
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.evrf_participant_indexes.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.evrf_participant_indexes_reverse_lookup.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.evrf_networks_substrate_keys.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
    {
      let mut mutated = tributary_validator_set.clone();
      mutated.evrf_networks_external_keys.clear();
      assert_eq!(borsh::to_vec(&mutated).unwrap(), bytes);
    }
  }
}

/// Assert a [`TributaryValidator`]'s invariants by its [`Participant`] consensus index.
fn assert_invariants_by_consensus_index(
  tributary_validator_set: &TributaryValidatorSet,
  participant: Participant,
  expected: &TributaryValidator,
) {
  use serai_env::log::debug;

  let i = usize::from(u16::from(participant)) - 1;
  debug!(
    "consensus_tributary_validators[{i}]: got {:?} expected {:?}",
    tributary_validator_set.get_tributary_validator_by_consensus_index(&participant).unwrap(),
    expected
  );
  assert_eq!(
    expected,
    tributary_validator_set.get_tributary_validator_by_consensus_index(&participant).unwrap()
  );

  let serai_key = expected.get_serai_networks_auxiliary_key();
  debug!(
    "consensus_participant_indexes_reverse_lookup[{participant}]: got {:?} expected {:?}",
    tributary_validator_set
      .get_tributary_validator_by_consensus_index(&participant)
      .unwrap()
      .get_serai_networks_auxiliary_key(),
    serai_key
  );
  assert_eq!(
    serai_key,
    tributary_validator_set
      .get_tributary_validator_by_consensus_index(&participant)
      .unwrap()
      .get_serai_networks_auxiliary_key()
  );

  debug!(
    "consensus_participant_indexes[{}]: got {} expected {}",
    hex::encode(serai_key.to_bytes()),
    tributary_validator_set.get_consensus_index_by_serai_auxiliary(serai_key.to_bytes()).unwrap(),
    participant
  );
  assert_eq!(
    &participant,
    tributary_validator_set.get_consensus_index_by_serai_auxiliary(serai_key.to_bytes()).unwrap()
  );

  debug!(
    "get_consensus_index_by_tributary_validator({expected:?}): got {:?} expected Some({})",
    tributary_validator_set.get_consensus_index_by_tributary_validator(expected),
    participant
  );
  assert_eq!(
    tributary_validator_set.get_consensus_index_by_tributary_validator(expected),
    Some(&participant)
  );

  debug!(
    "get_consensus_index_by_serai_auxiliary({}): got {:?} expected Some({participant})",
    hex::encode(serai_key.to_bytes()),
    tributary_validator_set.get_consensus_index_by_serai_auxiliary(serai_key.to_bytes()),
  );
  assert_eq!(
    tributary_validator_set.get_consensus_index_by_serai_auxiliary(serai_key.to_bytes()),
    Some(&participant),
  );

  debug!(
    "get_evrf_indexes_by_consensus_index({participant}): got {:?} expected {:?}",
    tributary_validator_set.get_evrf_indexes_by_consensus_index(&participant),
    tributary_validator_set.evrf_participant_indexes.get(expected),
  );
  assert_eq!(
    tributary_validator_set.get_evrf_indexes_by_consensus_index(&participant),
    tributary_validator_set.evrf_participant_indexes.get(expected),
  );
}

/// Assert a [`TributaryValidator`]'s invariants by its [`Participant`] evrf index.
fn assert_invariants_by_evrf_index(
  tributary_validator_set: &TributaryValidatorSet,
  participant: Participant,
  expected: &TributaryValidator,
) {
  use serai_env::log::debug;

  let serai_key = expected.get_serai_networks_auxiliary_key();
  debug!(
    "get_evrf_index_matches_serai_auxiliary({participant}, {}): got {} expected true",
    hex::encode(serai_key.to_bytes()),
    tributary_validator_set
      .get_evrf_index_matches_serai_auxiliary(&participant, &serai_key.to_bytes())
  );
  assert!(tributary_validator_set
    .get_evrf_index_matches_serai_auxiliary(&participant, &serai_key.to_bytes()));

  debug!(
    "evrf_participant_indexes_reverse_lookup[{participant}]: got {:?} expected {:?}",
    &tributary_validator_set.get_tributary_validator_by_evrf_index(&participant),
    expected
  );
  assert_eq!(
    expected,
    tributary_validator_set.get_tributary_validator_by_evrf_index(&participant).unwrap()
  );

  debug!(
    "evrf_participant_indexes[{expected:?}].contains({participant}): got {} expected true",
    tributary_validator_set.evrf_participant_indexes[expected].contains(&participant)
  );
  assert!(tributary_validator_set.evrf_participant_indexes[expected].contains(&participant));

  debug!(
    "evrf_networks_substrate_keys() contains {}: got {} expected true",
    hex::encode(expected.networks_substrate_key),
    tributary_validator_set
      .evrf_networks_substrate_keys()
      .contains(&expected.networks_substrate_key)
  );
  assert!(tributary_validator_set
    .evrf_networks_substrate_keys()
    .contains(&expected.networks_substrate_key));

  debug!(
    "evrf_networks_external_keys() contains {}: got {} expected true",
    hex::encode(&expected.networks_external_key),
    tributary_validator_set.evrf_networks_external_keys().contains(&expected.networks_external_key)
  );
  assert!(tributary_validator_set
    .evrf_networks_external_keys()
    .contains(&expected.networks_external_key));
}

#[test]
fn fuzz_tributary_getters() {
  use serai_env::log::debug;

  let mut rng = new_test_rng();

  const ITERATIONS: usize = 20;
  for iteration in 0 .. 20 {
    let num_validators = usize::try_from(rng.next_u32() % 10 + 2).unwrap(); // 2 ..= 11
    let mut validators = Vec::with_capacity(num_validators);

    // Track serai keys so we can create duplicates.
    let mut serai_keys_used: Vec<[u8; 32]> = Vec::with_capacity(num_validators);
    let should_duplicate = rng.next_u32() % 2 == 0;
    let mut duplicate_created = false;

    debug!("iteration {iteration}/{ITERATIONS}: {num_validators} validators");

    for _ in 0 .. num_validators {
      let serai_key = if should_duplicate && !duplicate_created && !serai_keys_used.is_empty() {
        duplicate_created = true;
        // Pick a random existing key.
        let existing_i = usize::try_from(rng.next_u32()).unwrap() % serai_keys_used.len();
        let key = serai_keys_used[existing_i];
        debug!(
          "validator {}/{}: reusing serai_networks_auxiliary_key from index {existing_i} ({})",
          validators.len(),
          num_validators,
          hex::encode(key)
        );
        key
      } else {
        let key = random_ristretto_public_key_bytes(&mut rng);
        serai_keys_used.push(key);
        debug!(
          "validator {}/{}: generated new serai_networks_auxiliary_key {}",
          validators.len(),
          num_validators,
          hex::encode(key)
        );
        key
      };

      let substrate_key = random_embedwards_key_bytes(&mut rng);
      let external_key = random_external_network_key(&mut rng);
      let weight = (u16::try_from(rng.next_u32() % 5).unwrap()) + 1; // 1 ..= 5
      let validator = TributaryValidator::new(serai_key, substrate_key, external_key, weight);
      debug!(
        "validator {}/{}: weight={weight}, networks_substrate_key={}, networks_external_key={}",
        validators.len(),
        num_validators,
        hex::encode(validator.networks_substrate_key),
        hex::encode(&validator.networks_external_key),
      );
      validators.push(validator);
    }

    let tributary_validator_set = TributaryValidatorSet::new(validators.clone());

    debug!(
      "consensus_validators: got {} expected {}",
      tributary_validator_set.consensus_tributary_validators.len(),
      validators.len(),
    );

    {
      let expected_total_weight: u16 = validators.iter().map(|v| v.weight).sum();
      let expected_threshold = required_participation(u16::try_from(num_validators).unwrap());
      let expected_required_participation = required_participation(expected_total_weight);

      debug!(
        "total_weight(): got {} expected {expected_total_weight}",
        tributary_validator_set.total_weight()
      );
      assert_eq!(tributary_validator_set.total_weight(), expected_total_weight);

      debug!(
        "threshold(): got {} expected {expected_threshold}",
        tributary_validator_set.evrf_threshold()
      );
      assert_eq!(tributary_validator_set.evrf_threshold(), expected_threshold);

      debug!(
        "required_participation(): got {} expected {expected_required_participation}",
        tributary_validator_set.required_participation()
      );
      assert_eq!(tributary_validator_set.required_participation(), expected_required_participation);

      let mut unique_serai: Vec<[u8; 32]> = Vec::with_capacity(num_validators);
      for v in &validators {
        if !unique_serai.contains(&v.serai_networks_auxiliary_key) {
          unique_serai.push(v.serai_networks_auxiliary_key);
        }
      }
      let unique_serai_len = unique_serai.len();

      debug!(
        "consensus_tributary_validators.len(): got {} expected {unique_serai_len}",
        tributary_validator_set.consensus_tributary_validators.len()
      );
      assert_eq!(tributary_validator_set.consensus_tributary_validators.len(), unique_serai_len);

      debug!(
        "evrf_participant_indexes.len(): got {} expected {num_validators}",
        tributary_validator_set.evrf_participant_indexes.len()
      );
      assert_eq!(tributary_validator_set.evrf_participant_indexes.len(), num_validators);

      debug!(
        "evrf_participant_indexes_reverse_lookup.len(): got {} expected {}",
        tributary_validator_set.evrf_participant_indexes_reverse_lookup.len(),
        usize::from(expected_total_weight)
      );
      assert_eq!(
        tributary_validator_set.evrf_participant_indexes_reverse_lookup.len(),
        usize::from(expected_total_weight),
      );

      let consensus_n = tributary_validator_set.consensus_tributary_validators.len();
      for (i_participant, _) in tributary_validator_set.consensus_participants() {
        let i_existing = tributary_validator_set
          .get_tributary_validator_by_consensus_index(&i_participant)
          .unwrap();

        debug!(
          "consensus[{i_participant}/{consensus_n}]: weight={}, serai_networks_auxiliary_key={}, \
           networks_substrate_key={}, networks_external_key={}",
          i_existing.weight,
          hex::encode(i_existing.serai_networks_auxiliary_key),
          hex::encode(i_existing.networks_substrate_key),
          hex::encode(&i_existing.networks_external_key),
        );
        assert_invariants_by_consensus_index(&tributary_validator_set, i_participant, i_existing);

        let weight_usize = usize::from(i_existing.weight);
        for i in 1 ..= weight_usize {
          let j_participant = u16_to_participant(u16::try_from(i).unwrap());
          let j_existing =
            tributary_validator_set.get_tributary_validator_by_evrf_index(&j_participant).unwrap();

          debug!(
            "evrf[{i}/{weight_usize}] for consensus[{i_participant}]: weight={}, \
             serai_networks_auxiliary_key={}, networks_substrate_key={}, \
             networks_external_key={}",
            j_existing.weight,
            hex::encode(j_existing.serai_networks_auxiliary_key),
            hex::encode(j_existing.networks_substrate_key),
            hex::encode(&j_existing.networks_external_key),
          );
          assert_invariants_by_evrf_index(&tributary_validator_set, j_participant, j_existing);
        }
      }

      debug!("iteration {iteration}/{ITERATIONS} passed all assertions");
    }
  }

  debug!("completed {ITERATIONS} iterations");
}

#[test]
fn errors() {
  let mut rng = new_test_rng();

  // Two unique validators with weight=1 each.
  let v1 = random_tributary_validator(&mut rng, 1);
  let v2 = random_tributary_validator(&mut rng, 1);
  let validators = vec![v1.clone(), v2.clone()];
  let tributary_validator_set = TributaryValidatorSet::new(validators.clone());

  let not_in_set = random_tributary_validator(&mut rng, 1);

  {
    assert!(tributary_validator_set
      .get_consensus_index_by_tributary_validator(&not_in_set)
      .is_none());
  }

  {
    let not_in_set_substrate_key = not_in_set.networks_substrate_key;
    assert!(tributary_validator_set
      .get_consensus_index_by_serai_auxiliary(not_in_set_substrate_key)
      .is_none());
    assert!(tributary_validator_set.get_consensus_index_by_serai_auxiliary([0xFFu8; 32]).is_none());
  }

  {
    let not_in_participants = u16_to_participant(99);
    assert!(!tributary_validator_set.get_evrf_index_matches_serai_auxiliary(
      &not_in_participants,
      &random_ristretto_public_key_bytes(&mut rng),
    ));
    assert!(tributary_validator_set
      .get_evrf_indexes_by_consensus_index(&not_in_participants)
      .is_none());
    assert!(tributary_validator_set
      .get_tributary_validator_by_consensus_index(&not_in_participants)
      .is_none());
    assert!(tributary_validator_set
      .get_tributary_validator_by_evrf_index(&not_in_participants)
      .is_none());
  }
}
