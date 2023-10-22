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
    frame_system::Config<AccountId = Public>
    + pallet_session::Config<ValidatorId = Public>
    + TypeInfo
  {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Stake requirement to join the initial validator sets.

    /// Networks to spawn Serai with, and the stake requirement per key share.
    ///
    /// Every participant at genesis will automatically be assumed to have this much stake.
    /// This stake cannot be withdrawn however as there's no actual stake behind it.
    pub networks: Vec<(NetworkId, Amount)>,
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<T::AccountId>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { networks: Default::default(), participants: Default::default() }
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
    pub fn session(network: NetworkId) -> Option<Session> {
      if network == NetworkId::Serai {
        Some(Session(pallet_session::Pallet::<T>::current_index()))
      } else {
        CurrentSession::<T>::get(network)
      }
    }

    pub fn latest_decided_session(network: NetworkId) -> Option<Session> {
      CurrentSession::<T>::get(network)
    }
  }

  /// The allocation required per key share.
  // Uses Identity for the lookup to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  #[pallet::getter(fn allocation_per_key_share)]
  pub type AllocationPerKeyShare<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  /// The validators selected to be in-set.
  #[pallet::storage]
  #[pallet::getter(fn participants)]
  pub type Participants<T: Config> = StorageMap<
    _,
    Identity,
    NetworkId,
    BoundedVec<Public, ConstU32<{ MAX_KEY_SHARES_PER_SET }>>,
    ValueQuery,
  >;
  /// The validators selected to be in-set, yet with the ability to perform a check for presence.
  // Uses Identity so we can call clear_prefix over network, manually inserting a Blake2 hash
  // before the spammable key.
  #[pallet::storage]
  pub type InSet<T: Config> =
    StorageMap<_, Identity, (NetworkId, [u8; 16], Public), (), OptionQuery>;
  impl<T: Config> Pallet<T> {
    fn in_set_key(
      network: NetworkId,
      account: T::AccountId,
    ) -> (NetworkId, [u8; 16], T::AccountId) {
      (network, sp_io::hashing::blake2_128(&(network, account).encode()), account)
    }

    // This exists as InSet, for Serai, is the validators set for the next session, *not* the
    // current set's validators
    #[inline]
    fn in_active_serai_set(account: Public) -> bool {
      // TODO: This is bounded O(n). Can we get O(1) via a storage lookup, like we do with InSet?
      for validator in pallet_session::Pallet::<T>::validators() {
        if validator == account {
          return true;
        }
      }
      false
    }

    /// Returns true if the account is included in an active set.
    pub fn in_active_set(network: NetworkId, account: Public) -> bool {
      if network == NetworkId::Serai {
        Self::in_active_serai_set(account)
      } else {
        InSet::<T>::contains_key(Self::in_set_key(network, account))
      }
    }

    /// Returns true if the account has been definitively included in an active or upcoming set.
    pub fn in_set(network: NetworkId, account: Public) -> bool {
      if InSet::<T>::contains_key(Self::in_set_key(network, account)) {
        return true;
      }

      if network == NetworkId::Serai {
        return Self::in_active_serai_set(account);
      }

      false
    }

    /// Returns true if the account is present in the latest decided set.
    ///
    /// This is useful when working with `allocation` and `total_allocated_stake`, which return the
    /// latest information.
    pub fn in_latest_decided_set(network: NetworkId, account: Public) -> bool {
      InSet::<T>::contains_key(Self::in_set_key(network, account))
    }
  }

  /// The total stake allocated to this network by the active set of validators.
  #[pallet::storage]
  #[pallet::getter(fn total_allocated_stake)]
  pub type TotalAllocatedStake<T: Config> = StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;

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
    fn recover_amount_from_sorted_allocation_key(key: &[u8]) -> Amount {
      let distance_from_end = 8 + 16 + 32;
      let start_pos = key.len() - distance_from_end;
      let mut raw: [u8; 8] = key[start_pos .. (start_pos + 8)].try_into().unwrap();
      for byte in &mut raw {
        *byte = !*byte;
      }
      Amount(u64::from_be_bytes(raw))
    }
    fn recover_key_from_sorted_allocation_key(key: &[u8]) -> Public {
      Public(key[(key.len() - 32) ..].try_into().unwrap())
    }
    // Returns if this validator already had an allocation set.
    fn set_allocation(network: NetworkId, key: Public, amount: Amount) -> bool {
      let prior = Allocations::<T>::take((network, key));
      if let Some(amount) = prior {
        SortedAllocations::<T>::remove(Self::sorted_allocation_key(network, key, amount));
      }
      if amount.0 != 0 {
        Allocations::<T>::set((network, key), Some(amount));
        SortedAllocations::<T>::set(Self::sorted_allocation_key(network, key, amount), Some(()));
      }
      prior.is_some()
    }
  }

  struct SortedAllocationsIter<T: Config> {
    _t: PhantomData<T>,
    prefix: Vec<u8>,
    last: Vec<u8>,
  }
  impl<T: Config> SortedAllocationsIter<T> {
    fn new(network: NetworkId) -> Self {
      let mut prefix = SortedAllocations::<T>::final_prefix().to_vec();
      prefix.extend(&network.encode());
      Self { _t: PhantomData, prefix: prefix.clone(), last: prefix }
    }
  }
  impl<T: Config> Iterator for SortedAllocationsIter<T> {
    type Item = (Public, Amount);
    fn next(&mut self) -> Option<Self::Item> {
      let next = sp_io::storage::next_key(&self.last)?;
      if !next.starts_with(&self.prefix) {
        return None;
      }
      let key = Pallet::<T>::recover_key_from_sorted_allocation_key(&next);
      let amount = Pallet::<T>::recover_amount_from_sorted_allocation_key(&next);
      self.last = next;
      Some((key, amount))
    }
  }

  impl<T: Config> Pallet<T> {
    fn is_bft(network: NetworkId) -> bool {
      let allocation_per_key_share = AllocationPerKeyShare::<T>::get(network).unwrap().0;

      let mut validators_len = 0;
      let mut top = None;
      let mut key_shares = 0;
      for (_, amount) in SortedAllocationsIter::<T>::new(network) {
        validators_len += 1;

        key_shares += amount.0 / allocation_per_key_share;
        if top.is_none() {
          top = Some(key_shares);
        }

        if key_shares > u64::from(MAX_KEY_SHARES_PER_SET) {
          break;
        }
      }

      let Some(top) = top else { return false };

      // key_shares may be over MAX_KEY_SHARES_PER_SET, which will cause an off-chain reduction of
      // each validator's key shares until their sum is MAX_KEY_SHARES_PER_SET
      // post_amortization_key_shares_for_top_validator yields what the top validator's key shares
      // would be after such a reduction, letting us evaluate this correctly
      let top = post_amortization_key_shares_for_top_validator(validators_len, top, key_shares);
      (top * 3) < key_shares.min(MAX_KEY_SHARES_PER_SET.into())
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

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    NewSet {
      set: ValidatorSet,
    },
    KeyGen {
      set: ValidatorSet,
      key_pair: KeyPair,
    },
    AllocationIncreased {
      validator: T::AccountId,
      network: NetworkId,
      amount: Amount,
    },
    AllocationDecreased {
      validator: T::AccountId,
      network: NetworkId,
      amount: Amount,
      delayed_until: Option<Session>,
    },
    SetRetired {
      set: ValidatorSet,
    },
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
        Self::session(network).unwrap_or(Session(0))
      };

      // Clear the current InSet
      {
        let mut in_set_key = InSet::<T>::final_prefix().to_vec();
        in_set_key.extend(network.encode());
        assert!(matches!(
          sp_io::storage::clear_prefix(&in_set_key, Some(MAX_KEY_SHARES_PER_SET)),
          sp_io::KillStorageResult::AllRemoved(_)
        ));
      }

      let allocation_per_key_share = Self::allocation_per_key_share(network).unwrap().0;

      let mut iter = SortedAllocationsIter::<T>::new(network);
      let mut participants = vec![];
      let mut key_shares = 0;
      let mut total_stake = 0;
      while key_shares < u64::from(MAX_KEY_SHARES_PER_SET) {
        let Some((key, amount)) = iter.next() else { break };

        InSet::<T>::set(Self::in_set_key(network, key), Some(()));
        participants.push(key);

        // This can technically set key_shares to a value exceeding MAX_KEY_SHARES_PER_SET
        // Off-chain, the key shares per validator will be accordingly adjusted
        key_shares += amount.0 / allocation_per_key_share;
        total_stake += amount.0;
      }
      TotalAllocatedStake::<T>::set(network, Some(Amount(total_stake)));

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
    /// Not enough allocation to obtain a key share in the set.
    InsufficientAllocation,
    /// Trying to deallocate more than allocated.
    NotEnoughAllocated,
    /// Allocation would cause the validator set to no longer achieve fault tolerance.
    AllocationWouldRemoveFaultTolerance,
    /// Deallocation would remove the participant from the set, despite the validator not
    /// specifying so.
    DeallocationWouldRemoveParticipant,
    /// Deallocation would cause the validator set to no longer achieve fault tolerance.
    DeallocationWouldRemoveFaultTolerance,
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
      for (id, stake) in self.networks.clone() {
        AllocationPerKeyShare::<T>::set(id, Some(stake));
        for participant in self.participants.clone() {
          if Pallet::<T>::set_allocation(id, participant, stake) {
            panic!("participants contained duplicates");
          }
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

      // signature isn't checked as this is an unsigned transaction, and validate_unsigned
      // (called by pre_dispatch) checks it
      let _ = signature;

      let session = Session(pallet_session::Pallet::<T>::current_index());

      let set = ValidatorSet { session, network };

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
        Err(Error::InsufficientAllocation) |
        Err(Error::NotEnoughAllocated) |
        Err(Error::AllocationWouldRemoveFaultTolerance) |
        Err(Error::DeallocationWouldRemoveParticipant) |
        Err(Error::DeallocationWouldRemoveFaultTolerance) |
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

    // Explicitly provide a pre-dispatch which calls validate_unsigned
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ()).map_err(Into::into)
    }
  }

  impl<T: Config> Pallet<T> {
    #[frame_support::transactional]
    pub fn increase_allocation(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> DispatchResult {
      let old_allocation = Self::allocation((network, account)).unwrap_or(Amount(0)).0;
      let new_allocation = old_allocation + amount.0;
      let allocation_per_key_share = Self::allocation_per_key_share(network).unwrap().0;
      if new_allocation < allocation_per_key_share {
        Err(Error::<T>::InsufficientAllocation)?;
      }

      let increased_key_shares =
        (old_allocation / allocation_per_key_share) < (new_allocation / allocation_per_key_share);

      let mut was_bft = None;
      if increased_key_shares {
        was_bft = Some(Self::is_bft(network));
      }

      // Increase the allocation now
      Self::set_allocation(network, account, Amount(new_allocation));
      Self::deposit_event(Event::AllocationIncreased { validator: account, network, amount });

      if let Some(was_bft) = was_bft {
        if was_bft && (!Self::is_bft(network)) {
          Err(Error::<T>::AllocationWouldRemoveFaultTolerance)?;
        }
      }

      if InSet::<T>::contains_key(Self::in_set_key(network, account)) {
        TotalAllocatedStake::<T>::set(
          network,
          Some(Amount(TotalAllocatedStake::<T>::get(network).unwrap_or(Amount(0)).0 + amount.0)),
        );
      }

      Ok(())
    }

    /// Decreases a validator's allocation to a set.
    ///
    /// Errors if the capacity provided by this allocation is in use.
    ///
    /// Errors if a partial decrease of allocation which puts the remaining allocation below the
    /// minimum requirement.
    ///
    /// The capacity prior provided by the allocation is immediately removed, in order to ensure it
    /// doesn't become used (preventing deallocation).
    ///
    /// Returns if the amount is immediately eligible for deallocation.
    #[frame_support::transactional]
    pub fn decrease_allocation(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> Result<bool, DispatchError> {
      // TODO: Check it's safe to decrease this set's stake by this amount

      let old_allocation =
        Self::allocation((network, account)).ok_or(Error::<T>::NonExistentValidator)?.0;
      let new_allocation =
        old_allocation.checked_sub(amount.0).ok_or(Error::<T>::NotEnoughAllocated)?;

      // If we're not removing the entire allocation, yet the allocation is no longer at or above
      // the threshold for a key share, error
      let allocation_per_key_share = Self::allocation_per_key_share(network).unwrap().0;
      if (new_allocation != 0) && (new_allocation < allocation_per_key_share) {
        Err(Error::<T>::DeallocationWouldRemoveParticipant)?;
      }

      let decreased_key_shares =
        (old_allocation / allocation_per_key_share) > (new_allocation / allocation_per_key_share);

      // If this decreases the validator's key shares, error if the new set is unable to handle
      // byzantine faults
      let mut was_bft = None;
      if decreased_key_shares {
        was_bft = Some(Self::is_bft(network));
      }

      // Decrease the allocation now
      // Since we don't also update TotalAllocatedStake here, TotalAllocatedStake may be greater
      // than the sum of all allocations, according to the Allocations StorageMap
      // This is intentional as this allocation has only been queued for deallocation at this time
      Self::set_allocation(network, account, Amount(new_allocation));

      if let Some(was_bft) = was_bft {
        if was_bft && (!Self::is_bft(network)) {
          Err(Error::<T>::DeallocationWouldRemoveFaultTolerance)?;
        }
      }

      // If we're not in-set, or this doesn't decrease our key shares, allow immediate deallocation
      let active = Self::in_set(network, account);
      if (!active) || (!decreased_key_shares) {
        if active {
          // Since it's being immediately deallocated, decrease TotalAllocatedStake
          TotalAllocatedStake::<T>::set(
            network,
            Some(Amount(TotalAllocatedStake::<T>::get(network).unwrap_or(Amount(0)).0 - amount.0)),
          );
        }
        Self::deposit_event(Event::AllocationDecreased {
          validator: account,
          network,
          amount,
          delayed_until: None,
        });
        return Ok(true);
      }

      // Set it to PendingDeallocations, letting the staking pallet release it on a future session
      // This unwrap should be fine as this account is active, meaning a session has occurred
      let mut to_unlock_on = Self::session(network).unwrap();
      if network == NetworkId::Serai {
        // Since the next Serai set will already have been decided, we can only deallocate once the
        // next set ends
        to_unlock_on.0 += 2;
      } else {
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

      Self::deposit_event(Event::AllocationDecreased {
        validator: account,
        network,
        amount,
        delayed_until: Some(to_unlock_on),
      });

      Ok(false)
    }

    // Checks if this session has completed the handover from the prior session.
    fn handover_completed(network: NetworkId, session: Session) -> bool {
      let Some(current_session) = Self::session(network) else { return false };
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
      for network in serai_primitives::NETWORKS {
        // If this network hasn't started sessions yet, don't start one now
        let Some(current_session) = Self::session(network) else { continue };
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

    pub fn retire_set(set: ValidatorSet) {
      MuSigKeys::<T>::remove(set);
      Keys::<T>::remove(set);
      Pallet::<T>::deposit_event(Event::SetRetired { set });
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
