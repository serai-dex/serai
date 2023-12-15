#![cfg_attr(not(feature = "std"), no_std)]

#[allow(deprecated, clippy::let_unit_value)] // TODO
#[frame_support::pallet]
pub mod pallet {
  use super::*;

  use scale_info::TypeInfo;

  use sp_core::sr25519::{Public, Signature};
  use sp_std::{vec, vec::Vec};
  use sp_application_crypto::RuntimePublic;
  use sp_session::ShouldEndSession;
  use sp_runtime::traits::IsMember;

  use frame_system::pallet_prelude::*;
  use frame_support::{
    pallet_prelude::*, traits::DisabledValidators, BoundedVec, WeakBoundedVec, StoragePrefixedMap,
  };

  use serai_primitives::*;
  pub use validator_sets_primitives as primitives;
  use primitives::*;

  use coins_pallet::{Pallet as Coins, AllowMint};
  use dex_pallet::Pallet as Dex;

  use pallet_babe::{Pallet as Babe, AuthorityId as BabeAuthorityId};
  use pallet_grandpa::{Pallet as Grandpa, AuthorityId as GrandpaAuthorityId};

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = Public>
    + coins_pallet::Config
    + dex_pallet::Config
    + pallet_babe::Config
    + pallet_grandpa::Config
    + TypeInfo
  {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;

    type ShouldEndSession: ShouldEndSession<BlockNumberFor<Self>>;
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
  // Uses Identity for the lookup to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  #[pallet::getter(fn session)]
  pub type CurrentSession<T: Config> = StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  impl<T: Config> Pallet<T> {
    pub fn latest_decided_session(network: NetworkId) -> Option<Session> {
      let session = Self::session(network);
      // we already decided about the next session for serai.
      if network == NetworkId::Serai {
        return session.map(|s| Session(s.0 + 1));
      }
      session
    }
  }

  /// The allocation required per key share.
  // Uses Identity for the lookup to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  #[pallet::getter(fn allocation_per_key_share)]
  pub type AllocationPerKeyShare<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  /// The validators selected to be in-set who haven't been removed.
  #[pallet::storage]
  pub(crate) type Participants<T: Config> = StorageMap<
    _,
    Identity,
    NetworkId,
    BoundedVec<(Public, u64), ConstU32<{ MAX_KEY_SHARES_PER_SET }>>,
    OptionQuery,
  >;
  /// The validators selected to be in-set, regardless of if removed, with the ability to perform a
  /// check for presence.
  // Uses Identity for NetworkId to avoid a hash of a severely limited fixed key-space.
  #[pallet::storage]
  pub(crate) type InSet<T: Config> =
    StorageDoubleMap<_, Identity, NetworkId, Blake2_128Concat, Public, u64, OptionQuery>;

  impl<T: Config> Pallet<T> {
    // This exists as InSet, for Serai, is the validators set for the next session, *not* the
    // current set's validators
    #[inline]
    fn in_active_serai_set(account: Public) -> bool {
      // TODO: is_member is internally O(n). Update Babe to use an O(1) storage lookup?
      Babe::<T>::is_member(&BabeAuthorityId::from(account))
    }

    /// Returns true if the account is included in an active set.
    ///
    /// This will still include participants which were removed from the DKG.
    pub fn in_active_set(network: NetworkId, account: Public) -> bool {
      if network == NetworkId::Serai {
        Self::in_active_serai_set(account)
      } else {
        InSet::<T>::contains_key(network, account)
      }
    }

    /// Returns true if the account has been definitively included in an active or upcoming set.
    ///
    /// This will still include participants which were removed from the DKG.
    pub fn in_set(network: NetworkId, account: Public) -> bool {
      if InSet::<T>::contains_key(network, account) {
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
      InSet::<T>::contains_key(network, account)
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

  // Doesn't use PrefixIterator as we need to yield the keys *and* values
  // PrefixIterator only yields the values
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

  /// Pending deallocations, keyed by the Session they become unlocked on.
  #[pallet::storage]
  type PendingDeallocations<T: Config> =
    StorageMap<_, Blake2_128Concat, (NetworkId, Session, Public), Amount, OptionQuery>;

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
    ParticipantRemoved {
      set: ValidatorSet,
      removed: T::AccountId,
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
    DeallocationClaimed {
      validator: T::AccountId,
      network: NetworkId,
      session: Session,
    },
    SetRetired {
      set: ValidatorSet,
    },
  }

  impl<T: Config> Pallet<T> {
    fn new_set(network: NetworkId) {
      // TODO: prevent new set if it doesn't have enough stake for economic security.

      // Update CurrentSession
      let session = {
        let new_session = CurrentSession::<T>::get(network)
          .map(|session| Session(session.0 + 1))
          .unwrap_or(Session(0));
        CurrentSession::<T>::set(network, Some(new_session));
        new_session
      };

      // Clear the current InSet
      assert_eq!(
        InSet::<T>::clear_prefix(network, MAX_KEY_SHARES_PER_SET, None).maybe_cursor,
        None
      );

      let allocation_per_key_share = Self::allocation_per_key_share(network).unwrap().0;

      let mut iter = SortedAllocationsIter::<T>::new(network);
      let mut participants = vec![];
      let mut key_shares = 0;
      let mut total_stake = 0;
      while key_shares < u64::from(MAX_KEY_SHARES_PER_SET) {
        let Some((key, amount)) = iter.next() else { break };

        let these_key_shares = amount.0 / allocation_per_key_share;
        InSet::<T>::set(network, key, Some(these_key_shares));
        participants.push((key, these_key_shares));

        // This can technically set key_shares to a value exceeding MAX_KEY_SHARES_PER_SET
        // Off-chain, the key shares per validator will be accordingly adjusted
        key_shares += these_key_shares;
        total_stake += amount.0;
      }
      TotalAllocatedStake::<T>::set(network, Some(Amount(total_stake)));

      let set = ValidatorSet { network, session };
      Pallet::<T>::deposit_event(Event::NewSet { set });

      Participants::<T>::set(network, Some(participants.try_into().unwrap()));
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
    /// Allocation would cause the validator set to never be able to achieve fault tolerance.
    AllocationWouldPreventFaultTolerance,
    /// Deallocation would remove the participant from the set, despite the validator not
    /// specifying so.
    DeallocationWouldRemoveParticipant,
    /// Deallocation would cause the validator set to no longer achieve fault tolerance.
    DeallocationWouldRemoveFaultTolerance,
    /// Deallocation to be claimed doesn't exist.
    NonExistentDeallocation,
    /// Validator Set already generated keys.
    AlreadyGeneratedKeys,
    /// An invalid MuSig signature was provided.
    BadSignature,
    /// Validator wasn't registered or active.
    NonExistentValidator,
    /// Deallocation would take the stake below what is required.
    DeallocationWouldRemoveEconomicSecurity,
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      if T::ShouldEndSession::should_end_session(n) {
        Self::rotate_session();
        // TODO: set the proper weights
        T::BlockWeights::get().max_block
      } else {
        Weight::zero()
      }
    }
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
    fn account() -> T::AccountId {
      system_address(b"ValidatorSets").into()
    }

    // is_bft returns if the network is able to survive any single node becoming byzantine.
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

    fn increase_allocation(
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

      // Check if the net exhibited the ability to handle any single node becoming byzantine
      let mut was_bft = None;
      if increased_key_shares {
        was_bft = Some(Self::is_bft(network));
      }

      // Increase the allocation now
      Self::set_allocation(network, account, Amount(new_allocation));
      Self::deposit_event(Event::AllocationIncreased { validator: account, network, amount });

      // Error if the net no longer can handle any single node becoming byzantine
      if let Some(was_bft) = was_bft {
        if was_bft && (!Self::is_bft(network)) {
          Err(Error::<T>::AllocationWouldRemoveFaultTolerance)?;
        }
      }

      // The above is_bft calls are only used to check a BFT net doesn't become non-BFT
      // Check here if this call would prevent a non-BFT net from *ever* becoming BFT
      if (new_allocation / allocation_per_key_share) >= (MAX_KEY_SHARES_PER_SET / 3).into() {
        Err(Error::<T>::AllocationWouldPreventFaultTolerance)?;
      }

      if InSet::<T>::contains_key(network, account) {
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
    fn decrease_allocation(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> Result<bool, DispatchError> {
      // Check it's safe to decrease this set's stake by this amount
      let new_total_staked = Self::total_allocated_stake(network)
        .unwrap()
        .0
        .checked_sub(amount.0)
        .ok_or(Error::<T>::NotEnoughAllocated)?;
      let required_stake = Self::required_stake_for_network(network);
      if new_total_staked < required_stake {
        Err(Error::<T>::DeallocationWouldRemoveEconomicSecurity)?;
      }

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

      // If we're not in-set, allow immediate deallocation
      if !Self::in_set(network, account) {
        Self::deposit_event(Event::AllocationDecreased {
          validator: account,
          network,
          amount,
          delayed_until: None,
        });
        return Ok(true);
      }

      // Set it to PendingDeallocations, letting it be released upon a future session
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

    fn new_session() {
      for network in serai_primitives::NETWORKS {
        // If this network hasn't started sessions yet, don't start one now
        let Some(current_session) = Self::session(network) else { continue };
        // Only spawn a new set if:
        // - This is Serai, as we need to rotate Serai upon a new session (per Babe)
        // - The current set was actually established with a completed handover protocol
        if (network == NetworkId::Serai) || Self::handover_completed(network, current_session) {
          Pallet::<T>::new_set(network);
          // let the Dex know session is rotated.
          Dex::<T>::on_new_session(network);
        }
      }
    }

    pub fn retire_set(set: ValidatorSet) {
      Keys::<T>::remove(set);
      Pallet::<T>::deposit_event(Event::SetRetired { set });
    }

    /// Take the amount deallocatable.
    ///
    /// `session` refers to the Session the stake becomes deallocatable on.
    fn take_deallocatable_amount(
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

    fn rotate_session() {
      let prior_serai_participants = Participants::<T>::get(NetworkId::Serai)
        .expect("no Serai participants upon rotate_session");
      let prior_serai_session = Self::session(NetworkId::Serai).unwrap();

      // TODO: T::SessionHandler::on_before_session_ending() was here.
      // end the current serai session.
      Self::retire_set(ValidatorSet { network: NetworkId::Serai, session: prior_serai_session });

      // make a new session and get the next validator set.
      Self::new_session();

      // Update Babe and Grandpa
      let session = prior_serai_session.0 + 1;
      let validators = prior_serai_participants;
      let next_validators =
        Participants::<T>::get(NetworkId::Serai).expect("no Serai participants after new_session");
      Babe::<T>::enact_epoch_change(
        WeakBoundedVec::force_from(
          validators.iter().copied().map(|(id, w)| (BabeAuthorityId::from(id), w)).collect(),
          None,
        ),
        WeakBoundedVec::force_from(
          next_validators.into_iter().map(|(id, w)| (BabeAuthorityId::from(id), w)).collect(),
          None,
        ),
        Some(session),
      );
      Grandpa::<T>::new_session(
        true,
        session,
        validators.into_iter().map(|(id, w)| (GrandpaAuthorityId::from(id), w)).collect(),
      );
    }

    /// Returns the required stake in terms SRI for a given `Balance`.
    pub fn required_stake(balance: &Balance) -> SubstrateAmount {
      use dex_pallet::HigherPrecisionBalance;

      // This is inclusive to an increase in accuracy
      let sri_per_coin = Dex::<T>::oracle_value(balance.coin).unwrap_or(Amount(0));

      // See dex-pallet for the reasoning on these
      let coin_decimals = balance.coin.decimals().max(5);
      let accuracy_increase = HigherPrecisionBalance::from(SubstrateAmount::pow(10, coin_decimals));

      let total_coin_value = u64::try_from(
        HigherPrecisionBalance::from(balance.amount.0) *
          HigherPrecisionBalance::from(sri_per_coin.0) /
          accuracy_increase,
      )
      .unwrap_or(u64::MAX);

      // required stake formula (COIN_VALUE * 1.5) + margin(20%)
      let required_stake = total_coin_value.saturating_mul(3).saturating_div(2);
      required_stake.saturating_add(total_coin_value.saturating_div(5))
    }

    /// Returns the current total required stake for a given `network`.
    pub fn required_stake_for_network(network: NetworkId) -> SubstrateAmount {
      let mut total_required = 0;
      for coin in network.coins() {
        let supply = Coins::<T>::supply(coin);
        total_required += Self::required_stake(&Balance { coin: *coin, amount: Amount(supply) });
      }
      total_required
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(0)] // TODO
    pub fn set_keys(
      origin: OriginFor<T>,
      network: NetworkId,
      removed_participants: Vec<Public>,
      key_pair: KeyPair,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // signature isn't checked as this is an unsigned transaction, and validate_unsigned
      // (called by pre_dispatch) checks it
      let _ = signature;

      let session = Self::session(network).unwrap();
      let set = ValidatorSet { network, session };

      Keys::<T>::set(set, Some(key_pair.clone()));

      // This does not remove from TotalAllocatedStake or InSet in order to:
      // 1) Not decrease the stake present in this set. This means removed participants are
      //    still liable for the economic security of the external network. This prevents
      //    a decided set, which is economically secure, from falling below the threshold.
      // 2) Not allow parties removed to immediately deallocate, per commentary on deallocation
      //    scheduling (https://github.com/serai-dex/serai/issues/394).
      for removed in removed_participants {
        Self::deposit_event(Event::ParticipantRemoved { set, removed });
      }
      Self::deposit_event(Event::KeyGen { set, key_pair });

      Ok(())
    }

    #[pallet::call_index(2)]
    #[pallet::weight(0)] // TODO
    pub fn allocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      Coins::<T>::transfer_internal(
        validator,
        Self::account(),
        Balance { coin: Coin::Serai, amount },
      )?;
      Self::increase_allocation(network, validator, amount)
    }

    #[pallet::call_index(3)]
    #[pallet::weight(0)] // TODO
    pub fn deallocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let account = ensure_signed(origin)?;

      let can_immediately_deallocate = Self::decrease_allocation(network, account, amount)?;
      if can_immediately_deallocate {
        Coins::<T>::transfer_internal(
          Self::account(),
          account,
          Balance { coin: Coin::Serai, amount },
        )?;
      }

      Ok(())
    }

    #[pallet::call_index(4)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn claim_deallocation(
      origin: OriginFor<T>,
      network: NetworkId,
      session: Session,
    ) -> DispatchResult {
      let account = ensure_signed(origin)?;
      let Some(amount) = Self::take_deallocatable_amount(network, session, account) else {
        Err(Error::<T>::NonExistentDeallocation)?
      };
      Coins::<T>::transfer_internal(
        Self::account(),
        account,
        Balance { coin: Coin::Serai, amount },
      )?;
      Self::deposit_event(Event::DeallocationClaimed { validator: account, network, session });
      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      match call {
        Call::set_keys { network, ref removed_participants, ref key_pair, ref signature } => {
          let network = *network;

          // Don't allow the Serai set to set_keys, as they have no reason to do so
          if network == NetworkId::Serai {
            Err(InvalidTransaction::Custom(0))?;
          }

          // Confirm this set has a session
          let Some(current_session) = Self::session(network) else {
            Err(InvalidTransaction::Custom(1))?
          };

          let set = ValidatorSet { network, session: current_session };

          // Confirm it has yet to set keys
          if Keys::<T>::get(set).is_some() {
            Err(InvalidTransaction::Stale)?;
          }

          // This is a needed precondition as this uses storage variables for the latest decided
          // session on this assumption
          assert_eq!(Pallet::<T>::latest_decided_session(network), Some(current_session));

          // This does not slash the removed participants as that'll be done at the end of the
          // set's lifetime
          let mut removed = hashbrown::HashSet::new();
          for participant in removed_participants {
            // Confirm this wasn't duplicated
            if removed.contains(&participant.0) {
              Err(InvalidTransaction::Custom(2))?;
            }
            removed.insert(participant.0);
          }

          let participants =
            Participants::<T>::get(network).expect("session existed without participants");

          let mut all_key_shares = 0;
          let mut signers = vec![];
          let mut signing_key_shares = 0;
          for participant in participants {
            let participant = participant.0;
            let shares = InSet::<T>::get(network, participant)
              .expect("participant from Participants wasn't InSet");
            all_key_shares += shares;

            if removed.contains(&participant.0) {
              continue;
            }

            signers.push(participant);
            signing_key_shares += shares;
          }

          {
            let f = all_key_shares - signing_key_shares;
            if signing_key_shares < ((2 * f) + 1) {
              Err(InvalidTransaction::Custom(3))?;
            }
          }

          // Verify the signature with the MuSig key of the signers
          // We theoretically don't need set_keys_message to bind to removed_participants, as the
          // key we're signing with effectively already does so, yet there's no reason not to
          if !musig_key(set, &signers)
            .verify(&set_keys_message(&set, removed_participants, key_pair), signature)
          {
            Err(InvalidTransaction::BadProof)?;
          }

          ValidTransaction::with_tag_prefix("ValidatorSets")
            .and_provides(set)
            .longevity(u64::MAX)
            .propagate(true)
            .build()
        }
        Call::allocate { .. } | Call::deallocate { .. } | Call::claim_deallocation { .. } => {
          Err(InvalidTransaction::Call)?
        }
        Call::__Ignore(_, _) => unreachable!(),
      }
    }

    // Explicitly provide a pre-dispatch which calls validate_unsigned
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ()).map_err(Into::into)
    }
  }

  impl<T: Config> AllowMint for Pallet<T> {
    fn is_allowed(balance: &Balance) -> bool {
      // get the required stake
      let current_required = Self::required_stake_for_network(balance.coin.network());
      let new_required = current_required + Self::required_stake(balance);

      // get the total stake for the network & compare.
      let staked = Self::total_allocated_stake(balance.coin.network()).unwrap_or(Amount(0));
      staked.0 >= new_required
    }
  }

  impl<T: Config> DisabledValidators for Pallet<T> {
    fn is_disabled(_: u32) -> bool {
      // TODO
      false
    }
  }
}

pub use pallet::*;
