#![cfg_attr(not(feature = "std"), no_std)]

#[allow(deprecated, clippy::let_unit_value)] // TODO
#[frame_support::pallet]
pub mod pallet {
  use scale_info::TypeInfo;

  use sp_core::sr25519::{Public, Signature};
  use sp_std::{vec, vec::Vec};
  use sp_application_crypto::RuntimePublic;

  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, StoragePrefixedMap};

  use serai_primitives::*;
  pub use validator_sets_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = Public> + pallet_session::Config + TypeInfo
  {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Stake requirement to join the initial validator sets.
    ///
    /// Every participant at genesis will automatically be assumed to have this much stake.
    /// This stake cannot be withdrawn however as there's no actual stake behind it.
    // TODO: Localize stake to network?
    pub stake: Amount,
    /// Networks to spawn Serai with.
    pub networks: Vec<NetworkId>,
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<T::AccountId>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig {
        stake: Amount(1),
        networks: Default::default(),
        participants: Default::default(),
      }
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The current session for a network.
  ///
  /// This does not store the current session for Serai. pallet_session handles that.
  // Uses Identity for the lookup to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  pub type CurrentSession<T: Config> = StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  impl<T: Config> Pallet<T> {
    fn session(network: NetworkId) -> Session {
      if network == NetworkId::Serai {
        Session(pallet_session::Pallet::<T>::current_index())
      } else {
        CurrentSession::<T>::get(network).unwrap()
      }
    }
  }

  /// The minimum allocation required to join a validator set.
  // Uses Identity for the lookup to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  #[pallet::getter(fn minimum_allocation)]
  pub type MinimumAllocation<T: Config> = StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  /// The validators selected to be in-set.
  #[pallet::storage]
  #[pallet::getter(fn participants)]
  pub type Participants<T: Config> = StorageMap<
    _,
    Identity,
    NetworkId,
    BoundedVec<Public, ConstU32<{ MAX_VALIDATORS_PER_SET }>>,
    ValueQuery,
  >;
  /// The validators selected to be in-set, yet with the ability to perform a check for presence.
  #[pallet::storage]
  pub type InSet<T: Config> = StorageMap<_, Blake2_128Concat, (NetworkId, Public), (), OptionQuery>;

  /// The current amount allocated to a validator set by a validator.
  #[pallet::storage]
  #[pallet::getter(fn allocation)]
  pub type Allocations<T: Config> =
    StorageMap<_, Blake2_128Concat, (NetworkId, Public), Amount, OptionQuery>;
  /// A sorted view of the current allocations premised on the underlying DB itself being sorted.
  // Uses Identity so we can iterate over the key space from highest-to-lowest allocated.
  // While this does enable attacks the hash is meant to prevent, the minimum stake should resolve
  // these.
  #[pallet::storage]
  type SortedAllocations<T: Config> =
    StorageMap<_, Identity, (NetworkId, [u8; 8], Public), (), OptionQuery>;
  impl<T: Config> Pallet<T> {
    /// A function which takes an amount and generates a byte array with a lexicographic order from
    /// high amount to low amount.
    #[inline]
    fn lexicographic_amount(amount: Amount) -> [u8; 8] {
      let mut bytes = amount.0.to_be_bytes();
      for byte in &mut bytes {
        *byte = !*byte;
      }
      bytes
    }
    fn set_allocation(network: NetworkId, key: Public, amount: Amount) {
      let prior = Allocations::<T>::take((network, key));
      if prior.is_some() {
        SortedAllocations::<T>::remove((network, Self::lexicographic_amount(amount), key));
      }
      if amount.0 != 0 {
        Allocations::<T>::set((network, key), Some(amount));
        SortedAllocations::<T>::set((network, Self::lexicographic_amount(amount), key), Some(()));
      }
    }
  }

  /// The MuSig key for a validator set.
  #[pallet::storage]
  #[pallet::getter(fn musig_key)]
  pub type MuSigKeys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, Public, OptionQuery>;

  /// The generated key pair for a given validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn keys)]
  pub type Keys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, KeyPair, OptionQuery>;

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    NewSet { set: ValidatorSet },
    KeyGen { set: ValidatorSet, key_pair: KeyPair },
  }

  impl<T: Config> Pallet<T> {
    fn new_set(network: NetworkId) {
      // Update CurrentSession
      let session = if network != NetworkId::Serai {
        CurrentSession::<T>::mutate(network, |session| {
          Some(session.map(|session| Session(session.0 + 1)).unwrap_or(Session(0)))
        })
        .unwrap()
      } else {
        Self::session(network)
      };

      // Clear the current InSet
      {
        let mut in_set_key = InSet::<T>::final_prefix().to_vec();
        in_set_key.extend(network.encode());
        assert!(matches!(
          sp_io::storage::clear_prefix(&in_set_key, Some(MAX_VALIDATORS_PER_SET)),
          sp_io::KillStorageResult::AllRemoved(_)
        ));
      }

      let mut prefix = SortedAllocations::<T>::final_prefix().to_vec();
      prefix.extend(&network.encode());
      let prefix = prefix;

      let mut last = prefix.clone();

      let mut participants = vec![];
      for _ in 0 .. MAX_VALIDATORS_PER_SET {
        let Some(next) = sp_io::storage::next_key(&last) else { break };
        if !next.starts_with(&prefix) {
          break;
        }
        assert_eq!(next.len(), (32 + 1 + 8 + 32));
        let key = Public(next[(next.len() - 32) .. next.len()].try_into().unwrap());

        InSet::<T>::set((network, key), Some(()));
        participants.push(key);

        last = next;
      }
      assert!(!participants.is_empty());

      let set = ValidatorSet { network, session };
      Pallet::<T>::deposit_event(Event::NewSet { set });
      if network != NetworkId::Serai {
        // Remove the keys for the set prior to the one now rotating out
        if session.0 >= 2 {
          let prior_to_now_rotating = ValidatorSet { network, session: Session(session.0 - 2) };
          MuSigKeys::<T>::remove(prior_to_now_rotating);
          Keys::<T>::remove(prior_to_now_rotating);
        }
        MuSigKeys::<T>::set(set, Some(musig_key(set, &participants)));
      }
      Participants::<T>::set(network, participants.try_into().unwrap());
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Validator Set doesn't exist.
    NonExistentValidatorSet,
    /// Not enough stake to participate in a set.
    InsufficientStake,
    /// Trying to deallocate more than allocated.
    InsufficientAllocation,
    /// Deallocation would remove the participant from the set, despite the validator not
    /// specifying so.
    DeallocationWouldRemoveParticipant,
    /// Validator Set already generated keys.
    AlreadyGeneratedKeys,
    /// An invalid MuSig signature was provided.
    BadSignature,
    /// Validator wasn't registered or active.
    NonExistentValidator,
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      {
        let hash_set =
          self.participants.iter().map(|key| key.0).collect::<hashbrown::HashSet<[u8; 32]>>();
        if hash_set.len() != self.participants.len() {
          panic!("participants contained duplicates");
        }
      }

      for id in self.networks.clone() {
        MinimumAllocation::<T>::set(id, Some(self.stake));
        for participant in self.participants.clone() {
          Pallet::<T>::set_allocation(id, participant, self.stake);
        }
        Pallet::<T>::new_set(id);
      }
    }
  }

  impl<T: Config> Pallet<T> {
    fn verify_signature(
      set: ValidatorSet,
      key_pair: &KeyPair,
      signature: &Signature,
    ) -> Result<(), Error<T>> {
      // Confirm a key hasn't been set for this set instance
      if Keys::<T>::get(set).is_some() {
        Err(Error::AlreadyGeneratedKeys)?
      }

      let Some(musig_key) = MuSigKeys::<T>::get(set) else { Err(Error::NonExistentValidatorSet)? };
      if !musig_key.verify(&set_keys_message(&set, key_pair), signature) {
        Err(Error::BadSignature)?;
      }

      Ok(())
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(0)] // TODO
    pub fn set_keys(
      origin: OriginFor<T>,
      network: NetworkId,
      key_pair: KeyPair,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      let session = Session(pallet_session::Pallet::<T>::current_index());

      let set = ValidatorSet { session, network };
      // TODO: Is this needed? validate_unsigned should be called before this and ensure it's Ok
      Self::verify_signature(set, &key_pair, &signature)?;

      Keys::<T>::set(set, Some(key_pair.clone()));
      Self::deposit_event(Event::KeyGen { set, key_pair });

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      let (network, key_pair, signature) = match call {
        Call::set_keys { network, ref key_pair, ref signature } => (network, key_pair, signature),
        Call::__Ignore(_, _) => unreachable!(),
      };

      let session = Session(pallet_session::Pallet::<T>::current_index());

      let set = ValidatorSet { session, network: *network };
      match Self::verify_signature(set, key_pair, signature) {
        Err(Error::AlreadyGeneratedKeys) => Err(InvalidTransaction::Stale)?,
        Err(Error::NonExistentValidatorSet) |
        Err(Error::InsufficientStake) |
        Err(Error::InsufficientAllocation) |
        Err(Error::DeallocationWouldRemoveParticipant) |
        Err(Error::NonExistentValidator) |
        Err(Error::BadSignature) => Err(InvalidTransaction::BadProof)?,
        Err(Error::__Ignore(_, _)) => unreachable!(),
        Ok(()) => (),
      }

      ValidTransaction::with_tag_prefix("validator-sets")
        .and_provides(set)
        // Set a 10 block longevity, though this should be included in the next block
        .longevity(10)
        .propagate(true)
        .build()
    }
  }

  impl<T: Config> Pallet<T> {
    pub fn increase_allocation(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> DispatchResult {
      let new_allocation = Self::allocation((network, account)).unwrap_or(Amount(0)).0 + amount.0;
      if new_allocation < Self::minimum_allocation(network).unwrap().0 {
        Err(Error::<T>::InsufficientStake)?;
      }
      Self::set_allocation(network, account, Amount(new_allocation));
      Ok(())
    }

    /// Decreases a validator's allocation to a set.
    ///
    /// Errors if the capacity provided by this allocation is in use.
    ///
    /// Errors if a partial decrease of allocation which puts the allocation below the minimum.
    ///
    /// The capacity prior provided by the allocation is immediately removed, in order to ensure it
    /// doesn't become used (preventing deallocation).
    pub fn decrease_allocation(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> DispatchResult {
      // TODO: Check it's safe to decrease this set's stake by this amount

      let new_allocation = Self::allocation((network, account))
        .ok_or(Error::<T>::NonExistentValidator)?
        .0
        .checked_sub(amount.0)
        .ok_or(Error::<T>::InsufficientAllocation)?;
      // If we're not removing the entire allocation, yet the allocation is no longer at or above
      // the minimum stake, error
      if (new_allocation != 0) &&
        (new_allocation < Self::minimum_allocation(network).unwrap_or(Amount(0)).0)
      {
        Err(Error::<T>::DeallocationWouldRemoveParticipant)?;
      }
      // TODO: Error if we're about to be removed, and the remaining set size would be <4

      // Decrease the allocation now
      Self::set_allocation(network, account, Amount(new_allocation));

      // Set it to PendingDeallocation, letting the staking pallet release it AFTER this session
      // TODO
      // TODO: We can immediately free it if it doesn't cross a key share threshold

      Ok(())
    }

    pub fn new_session() {
      // TODO: Define an array of all networks in primitives
      let networks = [NetworkId::Serai, NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero];
      for network in networks {
        // Handover is automatically complete for Serai as it doesn't have a handover protocol
        // TODO: Update how handover completed is determined. It's not on set keys. It's on new
        // set accepting responsibility
        let handover_completed = (network == NetworkId::Serai) ||
          Keys::<T>::contains_key(ValidatorSet { network, session: Self::session(network) });
        // Only spawn a NewSet if the current set was actually established with a completed
        // handover protocol
        if handover_completed {
          Pallet::<T>::new_set(network);
        }
      }
    }

    pub fn validators(network: NetworkId) -> Vec<Public> {
      Self::participants(network).into()
    }
  }
}

pub use pallet::*;
