use crate::{mock::*, primitives::*};

use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use zeroize::Zeroizing;
use rand_core::OsRng;

use frame_support::{
  assert_noop, assert_ok,
  pallet_prelude::{InvalidTransaction, TransactionSource},
  traits::{OnFinalize, OnInitialize},
};
use frame_system::RawOrigin;

use sp_core::{
  sr25519::{Public, Pair, Signature},
  Pair as PairTrait,
};
use sp_runtime::{traits::ValidateUnsigned, BoundedVec};

use serai_primitives::*;

fn active_network_validators(network: NetworkId) -> Vec<(Public, u64)> {
  if network == NetworkId::Serai {
    Babe::authorities().into_iter().map(|(id, key_share)| (id.into_inner(), key_share)).collect()
  } else {
    ValidatorSets::participants_for_latest_decided_set(network).unwrap().into_inner()
  }
}

fn verify_session_and_active_validators(network: NetworkId, participants: &[Public], session: u32) {
  let mut validators: Vec<Public> = active_network_validators(network)
    .into_iter()
    .map(|(p, ks)| {
      assert_eq!(ks, 1);
      p
    })
    .collect();
  validators.sort();

  assert_eq!(ValidatorSets::session(network).unwrap(), Session(session));
  assert_eq!(participants, validators);

  // TODO: how to make sure block finalizations work as usual here?
}

fn get_session_at_which_changes_activate(network: NetworkId) -> u32 {
  let current_session = ValidatorSets::session(network).unwrap().0;
  // changes should be active in the next session
  if network == NetworkId::Serai {
    // it takes 1 extra session for serai net to make the changes active.
    current_session + 2
  } else {
    current_session + 1
  }
}

fn set_keys_for_session(network: NetworkId) {
  ValidatorSets::set_keys(
    RawOrigin::None.into(),
    network,
    BoundedVec::new(),
    KeyPair(insecure_pair_from_name("Alice").public(), vec![].try_into().unwrap()),
    Signature([0u8; 64]),
  )
  .unwrap();
}

fn set_keys_signature(set: &ValidatorSet, key_pair: &KeyPair, pairs: &[Pair]) -> Signature {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key =
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut pair.public().0.as_ref()).unwrap();
    pub_keys.push(public_key);
  }

  let mut threshold_keys = vec![];
  for i in 0 .. pairs.len() {
    let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
      &mut pairs[i].as_ref().secret.to_bytes()[.. 32].as_ref(),
    )
    .unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    threshold_keys.push(
      musig::<Ristretto>(&musig_context(*set), &Zeroizing::new(secret_key), &pub_keys).unwrap(),
    );
  }

  let mut musig_keys = HashMap::new();
  for tk in threshold_keys {
    musig_keys.insert(tk.params().i(), tk.into());
  }

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys),
    &set_keys_message(set, &[], key_pair),
  );

  Signature(sig.to_bytes())
}

fn get_ordered_keys(network: NetworkId, participants: &[Pair]) -> Vec<Pair> {
  // retrieve the current session validators so that we know the order of the keys
  // that is necessary for the correct musig signature.
  let validators = ValidatorSets::participants_for_latest_decided_set(network).unwrap();

  // collect the pairs of the validators
  let mut pairs = vec![];
  for (v, _) in validators {
    let p = participants.iter().find(|pair| pair.public() == v).unwrap().clone();
    pairs.push(p);
  }

  pairs
}

fn rotate_session_until(network: NetworkId, session: u32) {
  let mut current = ValidatorSets::session(network).unwrap().0;
  while current < session {
    Babe::on_initialize(System::block_number() + 1);
    ValidatorSets::rotate_session();
    set_keys_for_session(network);
    ValidatorSets::retire_set(ValidatorSet { session: Session(current), network });
    current += 1;
  }
  assert_eq!(current, session);
}

#[test]
fn rotate_session() {
  new_test_ext().execute_with(|| {
    let genesis_participants: Vec<Public> =
      genesis_participants().into_iter().map(|p| p.public()).collect();
    let key_shares = key_shares();

    let mut participants = HashMap::from([
      (NetworkId::Serai, genesis_participants.clone()),
      (NetworkId::Bitcoin, genesis_participants.clone()),
      (NetworkId::Monero, genesis_participants.clone()),
      (NetworkId::Ethereum, genesis_participants),
    ]);

    // rotate session
    for network in NETWORKS {
      let participants = participants.get_mut(&network).unwrap();

      // verify for session 0
      participants.sort();
      set_keys_for_session(network);
      verify_session_and_active_validators(network, participants, 0);

      // add 1 participant
      let new_participant = insecure_pair_from_name("new-guy").public();
      Coins::mint(new_participant, Balance { coin: Coin::Serai, amount: key_shares[&network] })
        .unwrap();
      ValidatorSets::allocate(
        RawOrigin::Signed(new_participant).into(),
        network,
        key_shares[&network],
      )
      .unwrap();
      participants.push(new_participant);

      // move network to the activation session
      let activation_session = get_session_at_which_changes_activate(network);
      rotate_session_until(network, activation_session);

      // verify
      participants.sort();
      verify_session_and_active_validators(network, participants, activation_session);

      // remove 1 participant
      let participant_to_remove = participants[0];
      ValidatorSets::deallocate(
        RawOrigin::Signed(participant_to_remove).into(),
        network,
        key_shares[&network],
      )
      .unwrap();
      participants
        .swap_remove(participants.iter().position(|k| *k == participant_to_remove).unwrap());

      // check pending deallocations
      let pending = ValidatorSets::pending_deallocations(
        (network, participant_to_remove),
        Session(if network == NetworkId::Serai {
          activation_session + 3
        } else {
          activation_session + 2
        }),
      );
      assert_eq!(pending, Some(key_shares[&network]));

      // move network to the activation session
      let activation_session = get_session_at_which_changes_activate(network);
      rotate_session_until(network, activation_session);

      // verify
      participants.sort();
      verify_session_and_active_validators(network, participants, activation_session);
    }
  })
}

#[test]
fn allocate() {
  new_test_ext().execute_with(|| {
    let genesis_participants: Vec<Public> =
      genesis_participants().into_iter().map(|p| p.public()).collect();
    let key_shares = key_shares();
    let participant = insecure_pair_from_name("random1").public();
    let network = NetworkId::Ethereum;

    // check genesis TAS
    set_keys_for_session(network);
    assert_eq!(
      ValidatorSets::total_allocated_stake(network).unwrap().0,
      key_shares[&network].0 * u64::try_from(genesis_participants.len()).unwrap()
    );

    // we can't allocate less than a key share
    let amount = Amount(key_shares[&network].0 * 3);
    Coins::mint(participant, Balance { coin: Coin::Serai, amount }).unwrap();
    assert_noop!(
      ValidatorSets::allocate(
        RawOrigin::Signed(participant).into(),
        network,
        Amount(key_shares[&network].0 - 1)
      ),
      validator_sets::Error::<Test>::InsufficientAllocation
    );

    // we can't allocate too much that the net exhibits the ability to handle any single node
    // becoming byzantine
    assert_noop!(
      ValidatorSets::allocate(RawOrigin::Signed(participant).into(), network, amount),
      validator_sets::Error::<Test>::AllocationWouldRemoveFaultTolerance
    );

    // we should be allocate a proper amount
    assert_ok!(ValidatorSets::allocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));
    assert_eq!(Coins::balance(participant, Coin::Serai).0, amount.0 - key_shares[&network].0);

    // check new amount is reflected on TAS on new session
    rotate_session_until(network, 1);
    assert_eq!(
      ValidatorSets::total_allocated_stake(network).unwrap().0,
      key_shares[&network].0 * (u64::try_from(genesis_participants.len()).unwrap() + 1)
    );

    // check that new participants match
    let mut active_participants: Vec<Public> =
      active_network_validators(network).into_iter().map(|(p, _)| p).collect();

    let mut current_participants = genesis_participants.clone();
    current_participants.push(participant);

    current_participants.sort();
    active_participants.sort();
    assert_eq!(current_participants, active_participants);
  })
}

#[test]
fn deallocate_pending() {
  new_test_ext().execute_with(|| {
    let genesis_participants: Vec<Public> =
      genesis_participants().into_iter().map(|p| p.public()).collect();
    let key_shares = key_shares();
    let participant = insecure_pair_from_name("random1").public();
    let network = NetworkId::Bitcoin;

    // check genesis TAS
    set_keys_for_session(network);
    assert_eq!(
      ValidatorSets::total_allocated_stake(network).unwrap().0,
      key_shares[&network].0 * u64::try_from(genesis_participants.len()).unwrap()
    );

    // allocate some amount
    Coins::mint(participant, Balance { coin: Coin::Serai, amount: key_shares[&network] }).unwrap();
    assert_ok!(ValidatorSets::allocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));
    assert_eq!(Coins::balance(participant, Coin::Serai).0, 0);

    // move to next session
    let mut current_session = ValidatorSets::session(network).unwrap().0;
    current_session += 1;
    rotate_session_until(network, current_session);
    assert_eq!(
      ValidatorSets::total_allocated_stake(network).unwrap().0,
      key_shares[&network].0 * (u64::try_from(genesis_participants.len()).unwrap() + 1)
    );

    // we can deallocate all of our allocation
    assert_ok!(ValidatorSets::deallocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));

    // check pending deallocations
    let pending_session =
      if network == NetworkId::Serai { current_session + 3 } else { current_session + 2 };
    assert_eq!(
      ValidatorSets::pending_deallocations((network, participant), Session(pending_session)),
      Some(key_shares[&network])
    );

    // we can't claim it immediately
    assert_noop!(
      ValidatorSets::claim_deallocation(
        RawOrigin::Signed(participant).into(),
        network,
        Session(pending_session),
      ),
      validator_sets::Error::<Test>::NonExistentDeallocation
    );

    // we should be able to claim it in the pending session
    rotate_session_until(network, pending_session);
    assert_ok!(ValidatorSets::claim_deallocation(
      RawOrigin::Signed(participant).into(),
      network,
      Session(pending_session),
    ));
  })
}

#[test]
fn deallocate_immediately() {
  new_test_ext().execute_with(|| {
    let genesis_participants: Vec<Public> =
      genesis_participants().into_iter().map(|p| p.public()).collect();
    let key_shares = key_shares();
    let participant = insecure_pair_from_name("random1").public();
    let network = NetworkId::Monero;

    // check genesis TAS
    set_keys_for_session(network);
    assert_eq!(
      ValidatorSets::total_allocated_stake(network).unwrap().0,
      key_shares[&network].0 * u64::try_from(genesis_participants.len()).unwrap()
    );

    // we can't deallocate when we don't have an allocation
    assert_noop!(
      ValidatorSets::deallocate(
        RawOrigin::Signed(participant).into(),
        network,
        key_shares[&network]
      ),
      validator_sets::Error::<Test>::NonExistentValidator
    );

    // allocate some amount
    Coins::mint(participant, Balance { coin: Coin::Serai, amount: key_shares[&network] }).unwrap();
    assert_ok!(ValidatorSets::allocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));
    assert_eq!(Coins::balance(participant, Coin::Serai).0, 0);

    // we can't deallocate more than our allocation
    assert_noop!(
      ValidatorSets::deallocate(
        RawOrigin::Signed(participant).into(),
        network,
        Amount(key_shares[&network].0 + 1)
      ),
      validator_sets::Error::<Test>::NotEnoughAllocated
    );

    // we can't deallocate an amount that would left us less than a key share as long as it isn't 0
    assert_noop!(
      ValidatorSets::deallocate(
        RawOrigin::Signed(participant).into(),
        network,
        Amount(key_shares[&network].0 / 2)
      ),
      validator_sets::Error::<Test>::DeallocationWouldRemoveParticipant
    );

    // we can deallocate all of our allocation
    assert_ok!(ValidatorSets::deallocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));

    // It should be immediately deallocated since we are not yet in an active set
    assert_eq!(Coins::balance(participant, Coin::Serai), key_shares[&network]);
    assert!(ValidatorSets::pending_deallocations((network, participant), Session(1)).is_none());

    // allocate again
    assert_ok!(ValidatorSets::allocate(
      RawOrigin::Signed(participant).into(),
      network,
      key_shares[&network]
    ));
    assert_eq!(Coins::balance(participant, Coin::Serai).0, 0);

    // make a pool so that we have security oracle value for the coin
    let liq_acc = insecure_pair_from_name("liq-acc").public();
    let coin = Coin::Monero;
    let balance = Balance { coin, amount: Amount(2 * key_shares[&network].0) };
    Coins::mint(liq_acc, balance).unwrap();
    Coins::mint(liq_acc, Balance { coin: Coin::Serai, amount: balance.amount }).unwrap();
    Dex::add_liquidity(
      RawOrigin::Signed(liq_acc).into(),
      coin,
      balance.amount.0 / 2,
      balance.amount.0 / 2,
      1,
      1,
      liq_acc,
    )
    .unwrap();
    Dex::on_finalize(1);
    assert!(Dex::security_oracle_value(coin).unwrap().0 > 0);

    // we can't deallocate if it would break economic security
    // The reason we don't have economic security for the network now is that we just set
    // the value for coin/SRI to 1:1 when making the pool and we minted 2 * key_share amount
    // of coin but we only allocated 1 key_share of SRI for the network although we need more than
    // 3 for the same amount of coin.
    assert_noop!(
      ValidatorSets::deallocate(
        RawOrigin::Signed(participant).into(),
        network,
        key_shares[&network]
      ),
      validator_sets::Error::<Test>::DeallocationWouldRemoveEconomicSecurity
    );
  })
}

#[test]
fn set_keys_no_serai_network() {
  new_test_ext().execute_with(|| {
    let call = validator_sets::Call::<Test>::set_keys {
      network: NetworkId::Serai,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair: KeyPair(insecure_pair_from_name("name").public(), Vec::new().try_into().unwrap()),
      signature: Signature([0u8; 64]),
    };

    assert_eq!(
      ValidatorSets::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Custom(0).into()
    );
  })
}

#[test]
fn set_keys_keys_exist() {
  new_test_ext().execute_with(|| {
    let network = NetworkId::Monero;

    // set the keys first
    ValidatorSets::set_keys(
      RawOrigin::None.into(),
      network,
      Vec::new().try_into().unwrap(),
      KeyPair(insecure_pair_from_name("name").public(), Vec::new().try_into().unwrap()),
      Signature([0u8; 64]),
    )
    .unwrap();

    let call = validator_sets::Call::<Test>::set_keys {
      network,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair: KeyPair(insecure_pair_from_name("name").public(), Vec::new().try_into().unwrap()),
      signature: Signature([0u8; 64]),
    };

    assert_eq!(
      ValidatorSets::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Stale.into()
    );
  })
}

#[test]
fn set_keys_invalid_signature() {
  new_test_ext().execute_with(|| {
    let network = NetworkId::Ethereum;
    let mut participants = get_ordered_keys(network, &genesis_participants());

    // we can't have invalid set
    let mut set = ValidatorSet { network, session: Session(1) };
    let key_pair =
      KeyPair(insecure_pair_from_name("name").public(), Vec::new().try_into().unwrap());
    let signature = set_keys_signature(&set, &key_pair, &participants);

    let call = validator_sets::Call::<Test>::set_keys {
      network,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair: key_pair.clone(),
      signature,
    };
    assert_eq!(
      ValidatorSets::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::BadProof.into()
    );

    // fix the set
    set.session = Session(0);

    // participants should match
    participants.push(insecure_pair_from_name("random1"));
    let signature = set_keys_signature(&set, &key_pair, &participants);

    let call = validator_sets::Call::<Test>::set_keys {
      network,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair: key_pair.clone(),
      signature,
    };
    assert_eq!(
      ValidatorSets::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::BadProof.into()
    );

    // fix the participants
    participants.pop();

    // msg key pair and the key pair to set should match
    let key_pair2 =
      KeyPair(insecure_pair_from_name("name2").public(), Vec::new().try_into().unwrap());
    let signature = set_keys_signature(&set, &key_pair2, &participants);

    let call = validator_sets::Call::<Test>::set_keys {
      network,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair: key_pair.clone(),
      signature,
    };
    assert_eq!(
      ValidatorSets::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::BadProof.into()
    );

    // use the same key pair
    let signature = set_keys_signature(&set, &key_pair, &participants);
    let call = validator_sets::Call::<Test>::set_keys {
      network,
      removed_participants: Vec::new().try_into().unwrap(),
      key_pair,
      signature,
    };
    ValidatorSets::validate_unsigned(TransactionSource::External, &call).unwrap();

    // TODO: removed_participants parameter isn't tested since it will be removed in upcoming
    // commits?
  })
}

// TODO: add report_slashes tests when the feature is complete.
