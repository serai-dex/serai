#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract(env = serai_extension::SeraiEnvironment)]
mod multisig {
  use scale::Encode;

  use ink_storage::{traits::SpreadAllocate, Mapping};
  use ink_env::{hash::Blake2x256, hash_encoded};

  /// A contract which tracks the current multisig keys.
  #[ink(storage)]
  #[derive(SpreadAllocate)]
  pub struct Multisig {
    /// Validator set currently holding the multisig.
    validator_set: [u8; 32],
    /// Mapping from a curve's index to the multisig's current public key for it.
    // This is a mapping due to ink's eager loading. Considering we're right now only considering
    // secp256k1 and Ed25519, it may be notably more efficient to use a Vec here.
    keys: Mapping<u8, Vec<u8>>,
    /// Voter + Keys -> Voted already or not
    voted: Mapping<(AccountId, [u8; 32]), ()>,
    /// Validator Set + Keys -> Vote Count
    votes: Mapping<([u8; 32], [u8; 32]), u16>,
  }

  /// Event emitted when a new set of multisig keys is voted on. Only for the first vote on a set
  // of keys will they be present in this event.
  #[ink(event)]
  pub struct Vote {
    /// Validator who issued the vote.
    #[ink(topic)]
    validator: AccountId,
    /// Validator set for which keys are being generated.
    #[ink(topic)]
    validator_set: [u8; 32],
    /// Hash of the keys voted on.
    #[ink(topic)]
    hash: [u8; 32],
    /// Keys voted on.
    keys: Option<Vec<Vec<u8>>>,
  }

  /// Event emitted when the new keys are fully generated for all curves, having been fully voted
  /// on.
  #[ink(event)]
  pub struct KeyGen {
    #[ink(topic)]
    validator_set: [u8; 32],
    #[ink(topic)]
    hash: [u8; 32],
  }

  /// The Multisig error types.
  #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub enum Error {
    /// Returned if a curve index doesn't have a key registered for it.
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

    /// Validator set currently holding the multisig.
    #[ink(message)]
    pub fn validator_set(&self) -> [u8; 32] {
      self.validator_set
    }

    /// Returns the key currently in-use for a given curve ID. This is then bound to a given chain
    /// by applying a personalized additive offset, as done by the processor. Each chain then has
    /// its own way of receiving funds to these keys, leaving this not for usage by wallets, nor
    /// the processor which is expected to track events for this information. This is really solely
    /// for debugging purposes.
    #[ink(message)]
    pub fn key(&self, curve: u8) -> Result<Vec<u8>> {
      self.keys.get(curve).ok_or(Error::NonExistentCurve)
    }

    // TODO: voted
    // TODO: votes

    fn hash<T: Encode>(value: &T) -> [u8; 32] {
      let mut output = [0; 32];
      hash_encoded::<Blake2x256, _>(value, &mut output);
      output
    }

    /// Vote for a given set of keys.
    #[ink(message)]
    pub fn vote(&mut self, keys: Vec<Vec<u8>>) -> Result<()> {
      if keys.len() > 256 {
        Err(Error::NonExistentCurve)?;
      }

      let validator = self.env().caller();
      if !self.env().extension().is_active_validator(&validator) {
        Err(Error::NotValidator)?;
      }

      let validator_set = self.env().extension().validator_set_id();
      if self.validator_set == validator_set {
        Err(Error::AlreadyGeneratedKeys)?;
      }

      let keys_hash = Self::hash(&keys);
      if self.voted.get((validator, keys_hash)).is_some() {
        Err(Error::AlreadyVoted)?;
      }
      self.voted.insert((validator, keys_hash), &());

      let votes = if let Some(votes) = self.votes.get((validator_set, keys_hash)) {
        self.env().emit_event(Vote { validator, validator_set, hash: keys_hash, keys: None });
        votes + 1
      } else {
        self.env().emit_event(Vote {
          validator,
          validator_set,
          hash: keys_hash,
          keys: Some(keys.clone()),
        });
        1
      };
      // We could skip writing this if we've reached consensus, yet best to keep our ducks in a row
      self.votes.insert((validator_set, keys_hash), &votes);

      // If we've reached consensus, action this.
      if votes == self.env().extension().active_validators_len() {
        self.validator_set = validator_set;
        for (k, key) in keys.iter().enumerate() {
          self.keys.insert(u8::try_from(k).unwrap(), key);
        }
        self.env().emit_event(KeyGen { validator_set, hash: keys_hash });
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
      static ref EXPECTED_VALIDATOR_SET: [u8; 32] = [0xff; 32];

      static ref KEYS: Vec<Vec<u8>> = vec![vec![0, 1], vec![2, 3]];
      static ref EXPECTED_HASH: [u8; 32] = {
        let mut hash = [0; 32];
        ink_env::hash_encoded::<Blake2x256, _>(&*KEYS, &mut hash);
        hash
      };
    }

    fn hash_prefixed<T: scale::Encode>(prefixed: PrefixedValue<T>) -> [u8; 32] {
      let encoded = prefixed.encode();
      let mut hash = [0; 32];
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

      if let Event::Vote(Vote { validator, validator_set, hash, keys: actual_keys }) = decoded_event
      {
        assert_eq!(validator, expected_validator);
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

      if let Event::KeyGen(KeyGen { validator_set, hash }) = decoded_event
      {
        assert_eq!(validator_set, *EXPECTED_VALIDATOR_SET);
        assert_eq!(hash, *EXPECTED_HASH);
      } else {
        panic!("invalid KeyGen event")
      }

      let expected_topics = vec![
        hash_prefixed(PrefixedValue { prefix: b"", value: b"Multisig::KeyGen" }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::KeyGen::validator_set",
          value: &*EXPECTED_VALIDATOR_SET,
        }),
        hash_prefixed(PrefixedValue {
          prefix: b"Multisig::KeyGen::hash",
          value: &*EXPECTED_HASH,
        })
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
      assert_eq!(multisig.validator_set(), [0; 32]);
    }

    /// Non-existent curves error accordingly.
    #[ink::test]
    fn non_existent_curve() {
      assert_eq!(Multisig::new().key(0), Err(Error::NonExistentCurve));
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
      assert_eq!(multisig.validator_set(), *EXPECTED_VALIDATOR_SET);
      assert_key_gen(&emitted_events[test_validators().len()]);
    }
  }
}
