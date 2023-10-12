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
    pub fn session(network: NetworkId) -> Session {
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
  // Uses Identity so we can call clear_prefix over network, manually inserting a Blake2 hash
  // before the spammable key.
  // TODO: Review child trees?
  #[pallet::storage]
  pub type InSet<T: Config> =
    StorageMap<_, Identity, (NetworkId, [u8; 16], Public), (), OptionQuery>;

  /// The current amount allocated to a validator set by a validator.
  #[pallet::storage]
  #[pallet::getter(fn allocation)]
  pub type Allocations<T: Config> =
    StorageMap<_, Blake2_128Concat, (NetworkId, Public), Amount, OptionQuery>;
  /// A sorted view of the current allocations premised on the underlying DB itself being sorted.
  /*
    This uses Identity so we can take advantage of the DB's lexicographic ordering to iterate over
    the key space from highest-to-lowest allocated.

    This does remove the protection using a hash algorithm here offers against spam attacks (by
    flooding the DB with layers, increasing lookup time and merkle proof sizes, not that we use
    merkle proofs as Polkadot does).

    Since amounts are represented with just 8 bytes, only 16 nibbles are presents. This caps the
    potential depth caused by spam at 16 layers (as the underlying DB operates on nibbles).

    While there is an entire 32-byte public key after this, a Blake hash of the key is inserted
    after the amount to prevent the key from also being used to cause layer spam.

    There's also a minimum stake requirement, which further reduces the potential for spam.
  */
  #[pallet::storage]
  type SortedAllocations<T: Config> =
    StorageMap<_, Identity, (NetworkId, [u8; 8], [u8; 16], Public), (), OptionQuery>;
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
    #[inline]
    fn sorted_allocation_key(
      network: NetworkId,
      key: Public,
      amount: Amount,
    ) -> (NetworkId, [u8; 8], [u8; 16], Public) {
      let amount = Self::lexicographic_amount(amount);
      let hash = sp_io::hashing::blake2_128(&(network, amount, key).encode());
      (network, amount, hash, key)
    }
    fn set_allocation(network: NetworkId, key: Public, amount: Amount) {
      let prior = Allocations::<T>::take((network, key));
      if let Some(amount) = prior {
        SortedAllocations::<T>::remove(Self::sorted_allocation_key(network, key, amount));
      }
      if amount.0 != 0 {
        Allocations::<T>::set((network, key), Some(amount));
        SortedAllocations::<T>::set(Self::sorted_allocation_key(network, key, amount), Some(()));
      }
    }
  }

  /// Pending deallocations, keyed by the Session they become unlocked on.
  #[pallet::storage]
  type PendingDeallocations<T: Config> =
    StorageMap<_, Blake2_128Concat, (NetworkId, Session, Public), Amount, OptionQuery>;

  /// The MuSig key for a validator set.
  #[pallet::storage]
  #[pallet::getter(fn musig_key)]
  pub type MuSigKeys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, Public, OptionQuery>;

  /// The generated key pair for a given validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn keys)]
  pub type Keys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, KeyPair, OptionQuery>;

  // TODO: Expand
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
        let new_session = CurrentSession::<T>::get(network)
          .map(|session| Session(session.0 + 1))
          .unwrap_or(Session(0));
        CurrentSession::<T>::set(network, Some(new_session));
        new_session
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
        let key = Public(next[(next.len() - 32) .. next.len()].try_into().unwrap());

        InSet::<T>::set(
          (network, sp_io::hashing::blake2_128(&(network, key).encode()), key),
          Some(()),
        );
        participants.push(key);

        last = next;
      }

      let set = ValidatorSet { network, session };
      Pallet::<T>::deposit_event(Event::NewSet { set });
      if network != NetworkId::Serai {
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

      // Set it to PendingDeallocations, letting the staking pallet release it on a future session
      // TODO: We can immediately deallocate if not active
      let mut to_unlock_on = Self::session(network);
      if network == NetworkId::Serai {
        // Since the next Serai set will already have been decided, we can only deallocate once the
        // next set ends
        to_unlock_on.0 += 2;
      } else {
        // TODO: We can immediately free it if the deallocation doesn't cross a key share threshold
        to_unlock_on.0 += 1;
      }
      // Increase the session by one, creating a cooldown period
      to_unlock_on.0 += 1;
      let existing =
        PendingDeallocations::<T>::get((network, to_unlock_on, account)).unwrap_or(Amount(0));
      PendingDeallocations::<T>::set(
        (network, to_unlock_on, account),
        Some(Amount(existing.0 + amount.0)),
      );

      Ok(())
    }

    // Checks if this session has completed the handover from the prior session.
    fn handover_completed(network: NetworkId, session: Session) -> bool {
      let current_session = Self::session(network);
      // No handover occurs on genesis
      if current_session.0 == 0 {
        return true;
      }
      // If the session we've been queried about has yet to start, it can't have completed its
      // handover
      if current_session.0 < session.0 {
        return false;
      }
      if current_session.0 == session.0 {
        // Handover is automatically complete for Serai as it doesn't have a handover protocol
        // If not Serai, check the prior session had its keys cleared, which happens once its
        // retired
        return (network == NetworkId::Serai) ||
          (!Keys::<T>::contains_key(ValidatorSet {
            network,
            session: Session(current_session.0 - 1),
          }));
      }
      // We're currently in a future session, meaning this session definitely performed itself
      // handover
      true
    }

    pub fn new_session() {
      // TODO: Define an array of all networks in primitives
      let networks = [NetworkId::Serai, NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero];
      for network in networks {
        let current_session = Self::session(network);
        // Only spawn a NewSet if the current set was actually established with a completed
        // handover protocol
        if Self::handover_completed(network, current_session) {
          Pallet::<T>::new_set(network);
        }
      }
    }

    pub fn select_validators(network: NetworkId) -> Vec<Public> {
      Self::participants(network).into()
    }

    pub fn retire_session(network: NetworkId, session: Session) {
      let set = ValidatorSet { network, session };
      MuSigKeys::<T>::remove(set);
      Keys::<T>::remove(set);
    }

    /// Take the amount deallocatable.
    ///
    /// `session` refers to the Session the stake becomes deallocatable on.
    pub fn take_deallocatable_amount(
      network: NetworkId,
      session: Session,
      key: Public,
    ) -> Option<Amount> {
      // Check this Session has properly started, completing the handover from the prior session.
      if !Self::handover_completed(network, session) {
        return None;
      }
      PendingDeallocations::<T>::take((network, session, key))
    }
  }
}

pub use pallet::*;
