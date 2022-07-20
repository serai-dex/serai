#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

use serai_extension::{Curve, GlobalValidatorSetId, ValidatorSetIndex, Key};

type KeysHash = [u8; 32];

#[ink::contract(env = serai_extension::SeraiEnvironment)]
mod multisig {
  use scale::Encode;

  use ink_storage::{traits::SpreadAllocate, Mapping};
  use ink_env::{hash::Blake2x256, hash_encoded};

  use super::*;

  /// A contract which tracks the current multisig keys.
  /// Mapping of each validator set to their multisigs.
  #[ink(storage)]
  #[derive(SpreadAllocate)]
  pub struct Multisig {
    /// Global validator set ID under which this multisig was updated.
    /// Used to track if the multisig has been updated to the latest instantiation of a validator
    /// set or not.
    /// May be behind, and still healthy, if a validator set didn't change despite the global
    /// validator set doing so.
    updated_at: Mapping<ValidatorSetIndex, GlobalValidatorSetId>,
    /// Mapping from a curve's index to the multisig's current public key for it, if it has one.
    // This is a mapping due to ink's eager loading. Considering we're right now only considering
    // Secp256k1 and Ed25519, it may be notably more efficient to use a Vec here.
    // In practice, we're likely discussing up to 7 curves in total, so it may always be better to
    // simply use a Vec here, especially since it'd be Vec<Option<Key>>.
    keys: Mapping<(ValidatorSetIndex, Curve), Key>,
    /// Validator + Keys -> Voted already or not.
    /// Prevents voting multiple times on the same set of keys.
    voted: Mapping<(AccountId, KeysHash), ()>,
    /// Global Validator Set ID + Validator + Keys -> Vote Count.
    /// Including the GVSID locks it to a specific time period, preventing a validator from joining
    /// a set, voting on old keys, and then moving their bond to a new account to vote again.
    votes: Mapping<(GlobalValidatorSetId, ValidatorSetIndex, KeysHash), u16>,
  }

  /// Event emitted when a new set of multisig keys is voted on.
  #[ink(event)]
  pub struct Vote {
    /// Validator who issued the vote.
    #[ink(topic)]
    validator: AccountId,
    /// Global validator set ID under which keys are being generated.
    #[ink(topic)]
    global_validator_set: GlobalValidatorSetId,
    /// Validator set for which keys are being generated.
    #[ink(topic)]
    validator_set: ValidatorSetIndex,
    /// Hash of the keys voted on.
    #[ink(topic)]
    hash: KeysHash,
    /// Keys voted on. Only present in the first event for a given set of keys.
    keys: Option<Vec<Option<Key>>>,
  }

  /// Event emitted when the new keys are fully generated for a validator set, having been fully
  /// voted on.
  #[ink(event)]
  pub struct KeyGen {
    #[ink(topic)]
    global_validator_set: GlobalValidatorSetId,
    #[ink(topic)]
    validator_set: ValidatorSetIndex,
    #[ink(topic)]
    hash: KeysHash,
  }

  /// The Multisig error types.
  #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub enum Error {
    /// Returned if a validator set hasn't had keys registered for it yet.
    NonExistentValidatorSet,
    /// Returned if a validator set and curve index doesn't have a key registered for it.
    NonExistentKey,
    /// Returned if a curve index doesn't exist.
    NonExistentCurve,
    /// Returned if a non-validator is voting.
    NotValidator,
    /// Returned if this validator set already generated keys.
    AlreadyGeneratedKeys,
    /// Returned if this validator has already voted for these keys.
    AlreadyVoted,
  }

  /// The Multisig result type.
  pub type Result<T> = core::result::Result<T, Error>;

  impl Multisig {
    /// Deploys the Multisig contract.
    #[ink(constructor)]
    pub fn new() -> Self {
      ink_lang::utils::initialize_contract(|_| {})
    }

    /// Global validator set ID under which a validator set updated their multisig.
    #[ink(message)]
    pub fn updated_at(&self, validator_set: ValidatorSetIndex) -> Result<GlobalValidatorSetId> {
      self.updated_at.get(validator_set).ok_or(Error::NonExistentValidatorSet)
    }

    /// Returns the key currently in-use for a given validator set and curve.
    /// This is then bound to a given chain by applying a network-specific additive offset, as done
    /// by the processor. Each chain then has its own way of receiving funds to these keys, leaving
    /// this not for usage by wallets, nor the processor which is expected to track events for this
    /// information. This is really solely for debugging purposes.
    #[ink(message)]
    pub fn key(&self, validator_set: ValidatorSetIndex, curve: Curve) -> Result<Key> {
      self.keys.get((validator_set, curve)).ok_or(Error::NonExistentKey)
    }

    // TODO: voted
    // TODO: votes

    fn hash<T: Encode>(value: &T) -> KeysHash {
      let mut output = KeysHash::default();
      hash_encoded::<Blake2x256, _>(value, &mut output);
      output
    }

    /// Vote for a given set of keys.
    #[ink(message)]
    pub fn vote(&mut self, keys: Vec<Option<Key>>) -> Result<()> {
      if keys.len() > 256 {
        Err(Error::NonExistentCurve)?;
      }

      // Make sure they're a valid validator.
      let validator = self.env().caller();
      let active_validator = self.env().extension().active_validator(&validator);
      if active_validator.is_none() {
        Err(Error::NotValidator)?;
      }
      let (validator_set, shares) = active_validator.unwrap();

      // Prevent a validator set from generating keys multiple times. Only the first-voted-in keys
      // should be acknowledged.
      let global_validator_set = self.env().extension().global_validator_set_id();
      if self.updated_at.get(validator_set) == Some(global_validator_set) {
        Err(Error::AlreadyGeneratedKeys)?;
      }

      // Prevent a validator from voting on keys multiple times.
      let keys_hash = Self::hash(&keys);
      if self.voted.get((validator, keys_hash)).is_some() {
        Err(Error::AlreadyVoted)?;
      }
      self.voted.insert((validator, keys_hash), &());

      let votes = if let Some(votes) = self.votes.get((global_validator_set, validator_set, keys_hash)) {
        self.env().emit_event(Vote { validator, global_validator_set, validator_set, hash: keys_hash, keys: None });
        votes + shares
      } else {
        self.env().emit_event(Vote {
          validator,
          global_validator_set,
          validator_set,
          hash: keys_hash,
          keys: Some(keys.clone()),
        });
        shares
      };
      // We could skip writing this if we've reached consensus, yet best to keep our ducks in a row
      self.votes.insert((global_validator_set, validator_set, keys_hash), &votes);

      // If we've reached consensus, action this.
      if votes == self.env().extension().validator_set_shares(validator_set) {
        self.updated_at.insert(validator_set, &global_validator_set);
        for (k, key) in keys.iter().enumerate() {
          if let Some(key) = key {
            self.keys.insert((validator_set, Curve::try_from(k).unwrap()), key);
          }
        }
        self.env().emit_event(KeyGen { global_validator_set, validator_set, hash: keys_hash });
      }

      Ok(())
    }
  }

  #[cfg(test)]
  mod tests {
    use lazy_static::lazy_static;

    use ink_env::{
      hash::{CryptoHash, Blake2x256},
      AccountId,
      topics::PrefixedValue,
    };
    use ink_lang as ink;

    use serai_extension::{test_validators, test_register};

    use super::*;

    type Event = <Multisig as ::ink_lang::reflect::ContractEventBase>::Type;

    lazy_static! {
      static ref EXPECTED_GLOBAL_VALIDATOR_SET: GlobalValidatorSetId = 1;
      static ref EXPECTED_VALIDATOR_SET: ValidatorSetIndex = 0;
      static ref KEYS: Vec<Option<Key>> = vec![Some(vec![0, 1]), Some(vec![2, 3])];
      static ref EXPECTED_HASH: KeysHash = {
        let mut hash = KeysHash::default();
        ink_env::hash_encoded::<Blake2x256, _>(&*KEYS, &mut hash);
        hash
      };
    }

    fn hash_prefixed<T: scale::Encode>(prefixed: PrefixedValue<T>) -> [u8; 32] {
      let encoded = prefixed.encode();
      let mut hash = KeysHash::default();
      if encoded.len() < 32 {
        hash[.. encoded.len()].copy_from_slice(&encoded);
      } else {
        Blake2x256::hash(&encoded, &mut hash);
      }
      hash
    }

    fn assert_vote(
      event: &ink_env::test::EmittedEvent,
      expected_validator: AccountId,
      expected_keys: Option<()>,
    ) {
      let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
        .expect("encountered invalid contract event data buffer");

      if let Event::Vote(Vote { validator, global_validator_set, validator_set, hash, keys: actual_keys }) = decoded_event
      {
        assert_eq!(validator, expected_validator);
        assert_eq!(global_validator_set, *EXPECTED_GLOBAL_VALIDATOR_SET);
        assert_eq!(validator_set, *EXPECTED_VALIDATOR_SET);
        assert_eq!(hash, *EXPECTED_HASH);
        assert_eq!(actual_keys.as_ref(), expected_keys.map(|_| &*KEYS));
      } else {
        panic!("invalid Vote event")
      }

      let expected_topics = vec![
        hash_prefixed(PrefixedValue { prefix: b"", value: b"Multisig::Vote" }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::Vote::validator",
          value: &expected_validator,
        }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::Vote::global_validator_set",
          value: &*EXPECTED_GLOBAL_VALIDATOR_SET,
        }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::Vote::validator_set",
          value: &*EXPECTED_VALIDATOR_SET,
        }),
        hash_prefixed(PrefixedValue { prefix: b"Multisig::Vote::hash", value: &*EXPECTED_HASH }),
      ];

      for (n, (actual_topic, expected_topic)) in
        event.topics.iter().zip(expected_topics).enumerate()
      {
        assert_eq!(actual_topic, &expected_topic, "encountered invalid topic at {}", n);
      }
    }

    fn assert_key_gen(event: &ink_env::test::EmittedEvent) {
      let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
        .expect("encountered invalid contract event data buffer");

      if let Event::KeyGen(KeyGen { global_validator_set, validator_set, hash }) = decoded_event {
        assert_eq!(global_validator_set, *EXPECTED_GLOBAL_VALIDATOR_SET);
        assert_eq!(validator_set, *EXPECTED_VALIDATOR_SET);
        assert_eq!(hash, *EXPECTED_HASH);
      } else {
        panic!("invalid KeyGen event")
      }

      let expected_topics = vec![
        hash_prefixed(PrefixedValue { prefix: b"", value: b"Multisig::KeyGen" }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::KeyGen::global_validator_set",
          value: &*EXPECTED_GLOBAL_VALIDATOR_SET,
        }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::KeyGen::validator_set",
          value: &*EXPECTED_VALIDATOR_SET,
        }),
        hash_prefixed(PrefixedValue { prefix: b"Multisig::KeyGen::hash", value: &*EXPECTED_HASH }),
      ];

      for (n, (actual_topic, expected_topic)) in
        event.topics.iter().zip(expected_topics).enumerate()
      {
        assert_eq!(actual_topic, &expected_topic, "encountered invalid topic at {}", n);
      }
    }

    /// The default constructor does its job.
    #[ink::test]
    fn new() {
      let multisig = Multisig::new();
      assert_eq!(multisig.updated_at(0), Err(Error::NonExistentValidatorSet));
    }

    /// Non-existent keys error accordingly.
    #[ink::test]
    fn non_existent_key() {
      assert_eq!(Multisig::new().key(0, 0), Err(Error::NonExistentKey));
    }

    #[ink::test]
    fn success() {
      test_register();
      let mut multisig = Multisig::new();

      // Test voting on keys works without issue, emitting the keys for the first vote
      let mut emitted_events = vec![];
      for (i, validator) in test_validators().iter().enumerate() {
        ink_env::test::set_caller::<ink_env::DefaultEnvironment>(*validator);
        multisig.vote(KEYS.clone()).unwrap();

        emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
        // If this is the last validator, it should also trigger a keygen event, hence the + 1
        assert_eq!(emitted_events.len(), (i + 1) + (i / (test_validators().len() - 1)));
        assert_vote(
          &emitted_events[i],
          *validator,
          // Only the first event for this hash should have the keys
          Some(()).filter(|_| i == 0),
        );
      }

      // Since this should have key gen'd, verify that
      assert_eq!(multisig.updated_at(0).unwrap(), *EXPECTED_GLOBAL_VALIDATOR_SET);
      assert_key_gen(&emitted_events[test_validators().len()]);
    }
  }
}
