#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]

//! This pallet is likely the most complicated of all of Serai's pallets. In order to ensure it's
//! maintainable, the logic within it is broken into several sections which each intend to have
//! strongly defined API boundaries and be independently reviewable.
//!
//! Unfortunately, the `#[pallet::storage]` macro must be declared _in the pallet_ and we cannot
//! `include!` another file in that location (as the `include!` would be inside the pallet
//! definition and resolve _after_ the `pallet` attribute macro performs its
//! evaluation/transformation). This leaves us having this file contain
//! _every single storage definition_, before handing them out to each of the composed
//! functionalities.
//!
//! While some abstractions may be implemented and tested over arbitrary types, the abstractions
//! are allowed to be tightly bound to the pallet, and some are. Notably, for any storage value
//! which says it may be read from anywhere within the pallet, we tend to directly access the
//! pallet's definition of the storage value. This would mean the abstaction expected to write into
//! it must be defined over the pallet's storage value, and not for its own shim. This does
//! question why have the abstractions at all, instead of hooking `impl<T: Config> Pallet<T>`, and
//! the honest answer would be how they're an artifact from the development process. They do confer
//! the pleasant advantage of organizing, and documenting, storage within their own readable blocks
//! however (instead of within this monolithic file where the definitions must live). In some
//! cases, it does allow more granular testing however.
//!
//! Note the `EmbeddedEllipticCurveKeys` functionality is internally referred to as
//! `AuxiliaryKeys`. This is inconsistent with `EmbeddedEllipticCurveKeys` solely because the
//! object itself is pending a rename, while the functionality here is accurately named.
//!
//! As an invariant, this library assumes any selected validator has the auxiliary keys necessary
//! for the network they're validating. This is stated here to document how we rely on, and make
//! liberal use of, such an invariant, while also ensuring awareness as it's _critical_ a validator
//! is never selected to validate a network they didn't set the needed auxiliary keys for.
//! Currently, the invariant is enforced by not allowing validators who have yet to set the
//! auxiliary keys to allocate stake (preventing their candidacy for selection).

extern crate alloc;
use alloc::{vec, vec::Vec};

use sp_application_crypto::RuntimePublic as _;
use sp_core::sr25519::Public as SchnorrkelPublic;

use frame_system::pallet_prelude::*;
use frame_support::{
  sp_runtime::generic::DigestItem,
  pallet_prelude::*,
  traits::{OneSessionHandler as _, FindAuthor as _},
};

use pallet_session::ShouldEndSession;
use pallet_babe::Pallet as Babe;
use pallet_grandpa::Pallet as Grandpa;

use serai_abi::{
  primitives::{
    BitVec,
    crypto::{
      EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
      SignedEmbeddedEllipticCurveKeys as SignedAuxiliaryKeys, ExternalKey, KeyPair, Signature,
    },
    address::SeraiAddress,
    network_id::{ExternalNetworkId, NetworkId},
    coin::Coin,
    balance::{Amount, Balance},
    validator_sets::{
      Session, ExternalValidatorSet, ValidatorSet, KeyShares as KeySharesStruct, SlashReport,
      DeallocationTimeline,
    },
  },
  economic_security::EconomicSecurity,
  validator_sets::Event,
  SeraiPreExecutionDigest,
};

use serai_core_pallet::Pallet as Core;
type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;

mod auxiliary_keys;
use auxiliary_keys::{AuxiliaryKeysStorage, AuxiliaryKeys as _};

mod allocations;
use allocations::{
  AllocationError, DeallocationError, DelayedDeallocationError, AllocationsKey,
  SortedAllocationsKey, AllocationsStorage, DelayedDeallocationsStorage, DelayedDeallocations as _,
};

mod sessions;
use sessions::{
  *, GenesisValidators as GenesisValidatorsContainer, PendingSlashReport as PendingSlashReportValue,
};

mod keys;
use keys::{KeysStorage, Keys as _};

mod babe_grandpa;
#[doc(hidden)]
pub use babe_grandpa::*;

mod getters;
mod economic_security;
pub use economic_security::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;

/// An abstract view of `Coin::Serai`'s emissions.
pub trait Emissions {
  /// The `Coin::Serai` reward to issue to the block's author.
  fn block_reward() -> Amount;
  /// The `Coin::Serai` rewards to issue to `set`, which has just retired.
  ///
  /// This will only be called for a set which is no longer the latest-decided set. This will only
  /// be called once per set, hence the name being `take_set_reward`, noting that the implemetor
  /// MUST remove their storage for this.
  fn take_set_reward(set: ExternalValidatorSet) -> Amount;
}

#[frame_support::pallet]
mod pallet {
  use super::*;

  /// The weights for the pallet.
  pub trait Weights {
    /// The weight for the `set_keys` call.
    fn set_keys() -> Weight;
    /// The weight for the `slash_serai_validator` call.
    fn slash_serai_validator() -> Weight;
    /// The weight for the `report_slashes` call.
    fn report_slashes() -> Weight;
    /// The weight for the `set_auxiliary_keys` call.
    fn set_auxiliary_keys() -> Weight;
    /// The weight for the `allocate` call.
    fn allocate() -> Weight;
    /// The weight for the `deallocate` call.
    fn deallocate() -> Weight;
    /// The weight for the `claim_delayed_deallocation` call.
    fn claim_deallocation() -> Weight;
  }

  /// A shimmed set of weights, returning zero.
  ///
  /// This is NOT safe for usage in a production system and is provided only for testing purposes.
  impl Weights for () {
    fn set_keys() -> Weight {
      Weight::zero()
    }
    fn slash_serai_validator() -> Weight {
      Weight::zero()
    }
    fn report_slashes() -> Weight {
      Weight::zero()
    }
    fn set_auxiliary_keys() -> Weight {
      Weight::zero()
    }
    fn allocate() -> Weight {
      Weight::zero()
    }
    fn deallocate() -> Weight {
      Weight::zero()
    }
    fn claim_deallocation() -> Weight {
      Weight::zero()
    }
  }

  #[pallet::config]
  pub trait Config:
    frame_system::Config<RuntimeOrigin: From<Option<SeraiAddress>>>
    + pallet_session::Config
    + pallet_babe::Config
    + pallet_grandpa::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
  {
    type ShouldEndSession: ShouldEndSession<BlockNumberFor<Self>>;
    type EconomicSecurity: EconomicSecurity;
    type Emissions: Emissions;
    type Weights: Weights;
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /*
    The following storage values frequently use the `Identity` hasher for anything considered small
    and sufficiently constrained, such as `NetworkId` (statically-defined), `Session` (incremented
    per our scheduling), `ValidatorSet`, etc.
  */

  #[pallet::storage]
  pub(crate) type GenesisValidators<T: Config> =
    StorageValue<_, GenesisValidatorsContainer, OptionQuery>;
  #[pallet::storage]
  pub(crate) type AllocationPerKeyShare<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;

  /// The queued sessions to attempt.
  ///
  /// With each Serai session, an attempt at a new session for each external network is queued.
  /// These will be staggered such that they are actually attempted at block #`b + i`, where `b` is
  /// the block the Serai session began at and `i` is the index of the `ExternalNetworkId`.
  ///
  /// This would assume that within the session, there's at least `n` blocks, where `n` is the
  /// amount of external networks. To ensure, as an edge case, that all networks have a new session
  /// attempted _eventually_, the queue is preserved _across sessions of the Serai validator set_.
  /// This means if the a new Serai session occurs, and we only attempt a new session for
  /// `ExternalNetworkId::Bitcoin` before yet another Serai session occurs, the queue will become
  /// `ExternalNetworkId::all().skip(1).chain(ExternalNetworkId::all())`.
  ///
  /// To represent this in a finite amount of state, we solely track the session we're currently
  /// attempting sessions due to and the next network to attempt a session for. This also has the
  /// benefit of how _if_ we somehow ended up with a backlog, moving forward to the attempts for
  /// the next session will include _all_ currently-defined `ExternalNetworkId`s. If we used a
  /// literal `Vec<_>`, we would only use the `ExternalNetworkId`s defined _at time of queue_.
  ///
  /// Though again, this should be considered unneccessary as it's reasonable to assume each
  /// session will have more blocks than there are networks.
  #[pallet::storage]
  type QueuedAttempts<T: Config> = StorageValue<_, (Session, ExternalNetworkId), OptionQuery>;

  pub(crate) struct Abstractions<T: Config>(PhantomData<T>);

  // Satisfy the `AuxiliaryKeys` abstraction

  #[pallet::storage]
  pub(crate) type AuxiliaryKeys<T: Config> = StorageDoubleMap<
    _,
    Identity,
    NetworkId,
    Blake2_128Concat,
    SeraiAddress,
    AuxiliaryKeysStruct,
    OptionQuery,
  >;

  impl<T: Config> AuxiliaryKeysStorage for Abstractions<T> {
    type EmitEvent = serai_core_pallet::Pallet<T>;

    type AuxiliaryKeys = AuxiliaryKeys<T>;
  }

  // Satisfy the `Allocations` abstractions

  #[pallet::storage]
  pub(crate) type Allocations<T: Config> =
    StorageMap<_, Blake2_128Concat, AllocationsKey, Amount, OptionQuery>;
  // This has to use `Identity` per the documentation of `AllocationsStorage`
  #[pallet::storage]
  pub(crate) type SortedAllocations<T: Config> =
    StorageMap<_, Identity, SortedAllocationsKey, (), OptionQuery>;
  #[pallet::storage]
  pub(crate) type SumAllocations<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, ValueQuery>;

  #[pallet::storage]
  pub(crate) type DelayedDeallocations<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    SeraiAddress,
    Identity,
    ValidatorSet,
    Amount,
    OptionQuery,
  >;

  impl<T: Config> AllocationsStorage for Abstractions<T> {
    type EconomicSecurity = T::EconomicSecurity;
    type NetworkStakeRequirement = Pallet<T>;
    type AllocationPerKeyShare = AllocationPerKeyShare<T>;
    type Allocations = Allocations<T>;
    type SortedAllocations = SortedAllocations<T>;
    type SumAllocations = SumAllocations<T>;
  }

  impl<T: Config> DelayedDeallocationsStorage for Abstractions<T> {
    type Sessions = Self;
    type DelayedDeallocations = DelayedDeallocations<T>;
  }

  // Satisfy the `Keys` abstraction

  #[pallet::storage]
  pub(crate) type OraclizationKeys<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, SchnorrkelPublic, OptionQuery>;
  #[pallet::storage]
  pub(crate) type ExternalKeys<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, ExternalKey, OptionQuery>;

  impl<T: Config> KeysStorage for Abstractions<T> {
    type OraclizationKeys = OraclizationKeys<T>;
    type ExternalKeys = ExternalKeys<T>;
  }

  // Satisfy the `Sessions` abstractions

  #[pallet::storage]
  pub(crate) type CurrentSession<T: Config> =
    StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  #[pallet::storage]
  pub(crate) type LatestDecidedSession<T: Config> =
    StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  #[pallet::storage]
  pub(crate) type KeyShares<T: Config> =
    StorageMap<_, Identity, ValidatorSet, KeySharesStruct, OptionQuery>;
  #[pallet::storage]
  pub(crate) type SelectedValidators<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ValidatorSet,
    Blake2_128Concat,
    SeraiAddress,
    (SchnorrkelPublic, KeySharesStruct),
    OptionQuery,
  >;
  #[pallet::storage]
  pub(crate) type CurrentAllocatedStake<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  #[pallet::storage]
  pub(crate) type LatestDecidedAllocatedStake<T: Config> =
    StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  #[pallet::storage]
  pub(crate) type PendingSlashReport<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, PendingSlashReportValue, OptionQuery>;

  impl<T: Config> SessionsStorage for Abstractions<T> {
    type Config = T;

    type GenesisValidators = GenesisValidators<T>;
    type AllocationPerKeyShare = AllocationPerKeyShare<T>;
    type CurrentSession = CurrentSession<T>;
    type LatestDecidedSession = LatestDecidedSession<T>;
    type KeyShares = KeyShares<T>;
    type SelectedValidators = SelectedValidators<T>;
    type CurrentAllocatedStake = CurrentAllocatedStake<T>;
    type LatestDecidedAllocatedStake = LatestDecidedAllocatedStake<T>;
  }

  impl<T: Config> SlashReportsStorage for Abstractions<T> {
    type PendingSlashReport = PendingSlashReport<T>;
  }

  #[pallet::error]
  pub enum Error<T> {
    /// The auxiliary keys were invalid.
    InvalidAuxiliaryKeys,
    /// Allocation was erroneous.
    AllocationError(AllocationError),
    /// Deallocation was erroneous.
    DeallocationError(DeallocationError),
    /// Delayed deallocation was erroneous.
    DelayedDeallocationError(DelayedDeallocationError),
  }

  #[pallet::genesis_config]
  #[derive(Clone, Debug)]
  pub struct GenesisConfig<T: Config> {
    /// List of participants to place in the initial validator sets.
    ///
    /// Each genesis validator is expected to provide `SignedAuxiliaryKeys` for each network. They
    /// may not only validate _some_ networks. This is enforced by requiring the order of this
    /// `Vec<_>` equal the order yielded by [`NetworkId::all`], with matching lengths for the two
    /// lists.
    pub participants: Vec<(T::AccountId, Vec<SignedAuxiliaryKeys>)>,
  }
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      Self { participants: Default::default() }
    }
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      /*
        Substrate _always_ defines `test_genesis_config_builds` which checks if the default genesis
        config is accepted by `build` or not. Our issue is the default genesis config, which is
        without validators, is not valid and should not be considered valid.

        When testing, and for testing alone, we immediately return if given the default config so
        the test passes.
      */
      #[cfg(any(test, feature = "tests"))]
      if self.participants.is_empty() {
        return;
      }

      /*
        For a network with `n = 3f + 1`, where `n <= KeyShares::MAX_PER_SET`, we want to ensure
        the genesis validators are of quantity `<= f` and accordingly can become a minority unable
        to interrupt non-genesis validators.

        Further more, we want to assert a set of additional validators of size equal to the genesis
        validators is able to co-exist with the genesis validators before outright replacing them.
        This means we require `n >= 4g + 1`, where `g` is the amount of genesis validators.

        This isn't stricly ensuring, as even with so many validators, the capacity contributed from
        rewards distributed to genesis validators may still be needed, but it's a good sanity check
        on the amount of genesis validators.
      */
      assert!(((4 * self.participants.len()) + 1) <= usize::from(KeySharesStruct::MAX_PER_SET));

      GenesisValidators::<T>::set(Some(
        self
          .participants
          .iter()
          .map(|(participant, _keys)| *participant)
          .collect::<Vec<_>>()
          .try_into()
          .expect("amount of genesis validators exceeded the maximum allowed per set"),
      ));

      // Set their keys
      for (participant, keys) in &self.participants {
        let mut networks_iter = NetworkId::all();
        let mut keys_iter = keys.iter().cloned();
        for (network, keys) in (&mut networks_iter).zip(&mut keys_iter) {
          assert_eq!(network, keys.network());
          Abstractions::<T>::set_auxiliary_keys(*participant, keys)
            .expect("genesis auxiliary keys weren't valid");
        }
        assert!(networks_iter.next().is_none(), "less keys provided than networks");
        assert!(keys_iter.next().is_none(), "more keys provided than networks");
      }

      // Attempt sessions for all networks
      for network in NetworkId::all() {
        assert!(
          Abstractions::<T>::attempt_new_session(network, true),
          "failed to attempt a new session on genesis"
        );
      }

      // Immediately accept the handover for the genesis validators, for the Serai network
      Abstractions::<T>::accept_handover(NetworkId::Serai);
      // And decide the next session for the Serai network, as BABE requires selecting the next one
      // already
      assert!(
        Abstractions::<T>::attempt_new_session(NetworkId::Serai, true),
        "failed to attempt the next session for the Serai network on genesis"
      );

      // Spawn BABE's, GRANDPA's genesis session
      let genesis_serai_validators = SelectedValidators::<T>::iter_prefix(ValidatorSet {
        network: NetworkId::Serai,
        session: Session(0),
      })
      .collect::<Vec<_>>();
      Babe::<T>::on_genesis_session(validators_to_babe_validators(&genesis_serai_validators));
      Grandpa::<T>::on_genesis_session(validators_to_grandpa_validators(&genesis_serai_validators));
    }
  }

  impl<T: Config> Pallet<T> {
    /// Have the latest decided session become the current session.
    ///
    /// This is restricted to `ExternalNetworkId` as this process happens internally for
    /// `NetworkId::Serai`.
    ///
    /// This MUST be called as the corresponding function is documented in the `Sessions`
    /// abstraction.
    pub fn accept_handover(network: ExternalNetworkId) {
      Abstractions::<T>::accept_handover(network.into());
    }

    /// Set the allocation required per key share.
    ///
    /// The value is not sanity checked at all. The caller is liable to ensure it's a sane value.
    /// Setting the allocation per key share to `0` may produce undefined behavior.
    ///
    /// This is required in order for validators who have allocated stake to be selected.
    pub fn set_allocation_per_key_share(network: NetworkId, allocation_per_key_share: Amount) {
      AllocationPerKeyShare::<T>::set(network, Some(allocation_per_key_share));
    }
  }

  impl<T: Config> frame_support::traits::PreInherents for Pallet<T> {
    fn pre_inherents() {
      // Distribute the block reward
      if let Some(session) = CurrentSession::<T>::get(NetworkId::Serai) {
        let digest = frame_system::Pallet::<T>::digest();
        let author_index =
          Babe::<T>::find_author(digest.logs().iter().filter_map(DigestItem::as_pre_runtime))
            .expect("block without author");
        let author = Self::selected_validators(ValidatorSet { network: NetworkId::Serai, session })
          .nth(usize::try_from(author_index).unwrap())
          .expect("BABE index didn't identify a validator")
          .0;
        let SeraiPreExecutionDigest { proposer, unix_time_in_millis: _ } =
          SeraiPreExecutionDigest::find(&digest);
        // We want this block to be rejected if it doesn't accurately specify its author
        assert_eq!(author, proposer);

        let reward = T::Emissions::block_reward();
        if crate::Coins::<T>::mint(
          serai_abi::validator_sets::address(),
          Balance { coin: Coin::Serai, amount: reward },
        )
        .is_ok()
        {
          // This is a safe `unwrap` per the documented bounds on `increase_allocation`
          Abstractions::<T>::increase_allocation(NetworkId::Serai, author, reward, true).unwrap();
        }
      }

      {
        // If we should create a new Serai session, do so now (as mandatory)
        let block_number = frame_system::Pallet::<T>::block_number();
        if <T as Config>::ShouldEndSession::should_end_session(block_number) {
          Self::new_non_genesis_serai_session();

          // If there isn't an existing queue, queue attempts for new sessions for external networks
          if !QueuedAttempts::<T>::exists() {
            let session = CurrentSession::<T>::get(NetworkId::Serai)
              .expect("spawned new Serai session but no current session?");
            if let Some(first_network) = ExternalNetworkId::all().next() {
              QueuedAttempts::<T>::set(Some((session, first_network)));
            }
          }

          // We return now as to not overwhelm the amount of work which occurs within this block
          return;
        }
      }

      // If there's a queued attempt for an external network, handle it now
      let Some((queueing_session, attempting_network)) = QueuedAttempts::<T>::take() else {
        return;
      };

      Abstractions::<T>::attempt_new_session(
        attempting_network.into(),
        include_genesis_validators::<T, T::EconomicSecurity>(attempting_network),
      );

      // Queue the attempt for the next external network
      let mut networks = ExternalNetworkId::all();
      // Iterate through the networks and past the network we just attempted
      for network in &mut networks {
        if network == attempting_network {
          break;
        }
      }
      // If there's a network after it, queue its attempt
      if let Some(network_to_attempt_next) = networks.next() {
        QueuedAttempts::<T>::set(Some((queueing_session, network_to_attempt_next)));
      } else {
        /*
          If there isn't a network after it, check if we should already queue attempts for another
          session due to a new session having occurred _while working through the existing queue_.

          This means if a one-week-long session only had one block in it, and we only spawned a
          new session for a single network before the Serai session updated again, once we attempt
          new sessions for the rest of our networks, we'll immediately attempt a new session for
          the first network again. This will have the desired spacing.

          It will have 'undesired' spacing for the other networks though, as they may have multiple
          new sessions declared within a single Serai session. We bound this behavior by only
          queueing the attempted sessions for the current Serai session alone.

          Again, all of this should be overkill as we should be able to assume every Serai session
          to have more blocks than networks.
        */
        let current_session = CurrentSession::<T>::get(NetworkId::Serai)
          .expect("Serai doesn't have a current session?");
        if queueing_session < current_session {
          let first_network = ExternalNetworkId::all()
            .next()
            .expect("attempted a new session for an external network when there aren't any?");
          QueuedAttempts::<T>::set(Some((current_session, first_network)));
        }
      }
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((<T as Config>::Weights::set_keys(), DispatchClass::Operational))]
    pub fn set_keys(
      origin: OriginFor<T>,
      network: ExternalNetworkId,
      key_pair: KeyPair,
      signature_participants: BitVec<{ KeySharesStruct::MAX_PER_SET_U64 }>,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // `signature_participants`, `signature` are checked within `ValidateUnsigned`
      let _ = signature_participants;
      let _ = signature;

      let session = Self::current_session(NetworkId::from(network))
        .expect("validated `set_keys` for a non-existent session");
      let set = ExternalValidatorSet { network, session };
      Abstractions::<T>::set_keys(set, key_pair.clone());

      Core::<T>::emit_event(Event::SetKeys { set, key_pair });

      // If this is the first session of an external network, mark them current, not solely decided
      if session == Session(0) {
        Abstractions::<T>::accept_handover(network.into());
      }

      Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight((<T as Config>::Weights::slash_serai_validator(), DispatchClass::Operational))]
    pub fn slash_serai_validator(
      origin: OriginFor<T>,
      session: Session,
      validator: SeraiAddress,
    ) -> DispatchResult {
      ensure_none(origin)?;
      Abstractions::<T>::slash_serai_validator(session, validator);
      Ok(())
    }

    #[pallet::call_index(2)]
    #[pallet::weight((<T as Config>::Weights::report_slashes(), DispatchClass::Operational))]
    pub fn report_slashes(
      origin: OriginFor<T>,
      set: ExternalValidatorSet,
      slashes: SlashReport,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // `signature` is checked within `ValidateUnsigned`
      let _ = signature;

      Abstractions::<T>::handle_slash_report(set, slashes);

      Ok(())
    }

    #[pallet::call_index(3)]
    #[pallet::weight((<T as Config>::Weights::set_auxiliary_keys(), DispatchClass::Normal))]
    pub fn set_auxiliary_keys(origin: OriginFor<T>, keys: SignedAuxiliaryKeys) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      Abstractions::<T>::set_auxiliary_keys(validator, keys)
        .map_err(|()| Error::<T>::InvalidAuxiliaryKeys)?;
      Ok(())
    }

    #[pallet::call_index(4)]
    #[pallet::weight((<T as Config>::Weights::allocate(), DispatchClass::Normal))]
    pub fn allocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      Coins::<T>::transfer_fn(
        validator,
        serai_abi::validator_sets::address(),
        Balance { coin: Coin::Serai, amount },
      )?;

      Abstractions::<T>::increase_allocation(network, validator, amount, false)
        .map_err(Error::<T>::AllocationError)?;

      Ok(())
    }

    #[pallet::call_index(5)]
    #[pallet::weight((<T as Config>::Weights::deallocate(), DispatchClass::Normal))]
    pub fn deallocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      let timeline = Abstractions::<T>::decrease_allocation(network, validator, amount)
        .map_err(Error::<T>::DeallocationError)?;

      if matches!(timeline, DeallocationTimeline::Immediate) {
        Coins::<T>::transfer_fn(
          serai_abi::validator_sets::address(),
          validator,
          Balance { coin: Coin::Serai, amount },
        )?;
      }

      Ok(())
    }

    #[pallet::call_index(6)]
    #[pallet::weight((<T as Config>::Weights::claim_deallocation(), DispatchClass::Normal))]
    pub fn claim_deallocation(
      origin: OriginFor<T>,
      network: NetworkId,
      session: Session,
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      let amount = Abstractions::<T>::claim_delayed_deallocation(validator, network, session)
        .map_err(Error::<T>::DelayedDeallocationError)?;

      Core::<T>::emit_event(Event::DelayedDeallocationClaimed {
        validator,
        deallocation: ValidatorSet { network, session },
      });

      Coins::<T>::transfer_fn(
        serai_abi::validator_sets::address(),
        validator,
        Balance { coin: Coin::Serai, amount },
      )?;
      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      match call {
        Call::set_keys { network, ref key_pair, ref signature_participants, ref signature } => {
          let network = *network;

          // Confirm this network has a session decided
          let Some(latest_decided_session) = Self::latest_decided_session(network.into()) else {
            Err(InvalidTransaction::BadSigner)?
          };

          let set = ExternalValidatorSet { network, session: latest_decided_session };

          // Confirm this set has yet to set keys
          if !Abstractions::<T>::still_needs_to_set_keys(set) {
            Err(InvalidTransaction::Stale)?;
          }

          let participants = SelectedValidators::<T>::iter_prefix(set).collect::<Vec<_>>();
          assert!(
            !participants.is_empty(),
            "set which was decided had no selected participants stored"
          );
          // Check the bitvec is of the proper length
          if participants.len() != signature_participants.len() {
            Err(InvalidTransaction::BadProof)?;
          }

          // Find the participating, total key shares
          let mut all_key_shares = 0;
          let mut signers = vec![];
          let mut signing_key_shares = 0;
          for ((_participant, (aux_key, key_shares)), in_use) in
            participants.into_iter().zip(signature_participants)
          {
            all_key_shares += u16::from(key_shares);

            if !in_use {
              continue;
            }

            signers.push(aux_key);
            signing_key_shares += u16::from(key_shares);
          }

          // Check enough validators participated
          {
            let f = all_key_shares - signing_key_shares;
            if signing_key_shares < ((2 * f) + 1) {
              Err(InvalidTransaction::BadSigner)?;
            }
          }

          // Verify the signature with the MuSig key of the signers
          match signature {
            Signature::Ristretto(signature) => {
              if !ValidatorSet::from(set)
                .musig_key(&signers)
                .verify(&set.set_keys_message(key_pair), &signature.0.into())
              {
                Err(InvalidTransaction::BadProof)?;
              }
            }
          }

          ValidTransaction::with_tag_prefix("ValidatorSets")
            .and_provides((0, set))
            .longevity(u64::MAX)
            .propagate(true)
            .build()
        }
        Call::report_slashes { set, ref slashes, ref signature } => {
          let Some(key) = Abstractions::<T>::should_still_publish_slash_report(*set) else {
            Err(InvalidTransaction::Stale)?
          };

          if slashes.0.len() != SelectedValidators::<T>::iter_key_prefix(*set).count() {
            Err(InvalidTransaction::Custom(0))?
          }

          match signature {
            Signature::Ristretto(signature) => {
              if !key.verify(&slashes.report_slashes_message(), &signature.0.into()) {
                Err(InvalidTransaction::BadProof)?;
              }
            }
          }

          ValidTransaction::with_tag_prefix("ValidatorSets")
            .and_provides((1, key))
            .longevity(KeySharesStruct::MAX_PER_SET_U32.into())
            .propagate(true)
            .build()
        }
        Call::slash_serai_validator { session, validator } => {
          /*
            This is expected to be validated by the node, or at the very least, a higher level. The
            only validation performed here is that the transaction isn't stale as it doesn't make
            sense to dispatch this call if this is stale.
          */
          {
            let current_session =
              Pallet::<T>::current_session(NetworkId::Serai).unwrap_or(Session(0));
            let most_recent_session_with_still_pending_deallocations =
              current_session.0.saturating_sub(2);
            // We consider a slash stale if there's no stake to slash
            if <Abstractions<T> as allocations::Allocations>::allocation(
              NetworkId::Serai,
              *validator,
            )
            .is_none() &&
              (most_recent_session_with_still_pending_deallocations ..= current_session.0).all(
                |session| {
                  Abstractions::<T>::fetch_deallocations_delayed_from(
                    *validator,
                    NetworkId::Serai,
                    Session(session),
                  )
                  .is_none()
                },
              )
            {
              Err(InvalidTransaction::Stale)?;
            }
          }

          ValidTransaction::with_tag_prefix("ValidatorSets")
            .and_provides((2, session, validator))
            .longevity(KeySharesStruct::MAX_PER_SET_U32.into())
            .propagate(true)
            .build()
        }
        Call::set_auxiliary_keys { .. } |
        Call::allocate { .. } |
        Call::deallocate { .. } |
        Call::claim_deallocation { .. } => Err(InvalidTransaction::Call)?,
        Call::__Ignore(_, _) => unreachable!(),
      }
    }

    // Explicitly provide a pre-dispatch which calls `validate_unsigned`
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ())
    }
  }

  impl<T: Config> frame_support::traits::DisabledValidators for Pallet<T> {
    fn is_disabled(mut index: u32) -> bool {
      let session = Pallet::<T>::current_session(NetworkId::Serai).unwrap_or(Session(0));
      let mut iter =
        Pallet::<T>::selected_validators(ValidatorSet { network: NetworkId::Serai, session });
      while index != 0 {
        let _ = iter.next();
        index -= 1;
      }
      let Some((validator, _)) = iter.next() else {
        // If requesting information for an invalid index, claim it's disabled
        return true;
      };
      /*
        The validator is disabled if they aren't a genesis validator and have no stake associated
        with this session, meaning they have suffered a fatal slash.

        This does have the oddity that the allocation of any stake will then un-disable the
        validator, but the validator should no longer be able to propose blocks (preventing earning
        the block reward) and the traditional allocation flow would require allocating at least one
        key share (and not a trivial amount like one atomic unit). Accordingly, this is fine.
      */
      (!GenesisValidators::<T>::get()
        .expect("validators selected but never set genesis validators")
        .contains(&validator)) &&
        <Abstractions<T> as allocations::Allocations>::allocation(NetworkId::Serai, validator)
          .is_none() &&
        Abstractions::<T>::fetch_deallocations_delayed_from(validator, NetworkId::Serai, session)
          .is_none()
    }

    fn disabled_validators() -> Vec<u32> {
      let session = Pallet::<T>::current_session(NetworkId::Serai).unwrap_or(Session(0));
      let Some(genesis_validators) = GenesisValidators::<T>::get() else { return vec![] };

      let mut result = vec![];
      let mut index = 0u32;
      #[expect(clippy::explicit_counter_loop)] // `enumerate` would return a `usize`
      for (validator, _) in
        Pallet::<T>::selected_validators(ValidatorSet { network: NetworkId::Serai, session })
      {
        if (!genesis_validators.contains(&validator)) &&
          <Abstractions<T> as allocations::Allocations>::allocation(NetworkId::Serai, validator)
            .is_none() &&
          Abstractions::<T>::fetch_deallocations_delayed_from(
            validator,
            NetworkId::Serai,
            session,
          )
          .is_none()
        {
          result.push(index);
        }
        index += 1;
      }
      result
    }
  }
}

pub use pallet::{Config, Pallet, Call};
#[doc(hidden)]
pub use pallet::*;

sp_api::decl_runtime_apis! {
  #[api_version(1)]
  pub trait ValidatorSetsApi {
    /// Returns the current validators for a given network.
    fn validators(
      network_id: NetworkId,
    ) -> Vec<SeraiAddress>;

    /// Returns the external network key for a given external network.
    fn external_network_key(
      network: ExternalNetworkId,
    ) -> Option<ExternalKey>;
  }
}

/// A `*Storage` backend used when testing, without constructing a full runtime.
///
/// This is used for testing the simpler abstractions where it's feasible to define the relevant
/// subset and it's helpful for testing. For the abstractions which make use of it, they generally
/// define themselves and then proceed to implement their `trait Storage for MockStorage`.
#[cfg(test)]
struct MockStorage;
#[cfg(test)]
impl MockStorage {
  /// Set random random auxiliary keys for each network for a given validator.
  pub fn set_random_auxiliary_keys(validator: SeraiAddress) {
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    use ciphersuite::{group::ff::Field as _, WrappedGroup};
    use dalek_ff_group::Ristretto;
    use embedwards25519::Embedwards25519;
    use secq256k1::Secq256k1;

    let btc_keys = SignedAuxiliaryKeys::bitcoin(
      &mut OsRng,
      validator,
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
      &Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut OsRng)),
    );
    MockStorage::set_auxiliary_keys(validator, btc_keys).unwrap();

    let eth_keys = SignedAuxiliaryKeys::ethereum(
      &mut OsRng,
      validator,
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
      &Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut OsRng)),
    );
    MockStorage::set_auxiliary_keys(validator, eth_keys).unwrap();

    let xmr_keys = SignedAuxiliaryKeys::monero(
      &mut OsRng,
      validator,
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
    );
    MockStorage::set_auxiliary_keys(validator, xmr_keys).unwrap();

    let serai_keys = SignedAuxiliaryKeys::serai(
      &mut OsRng,
      validator,
      &Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng)),
    );
    MockStorage::set_auxiliary_keys(validator, serai_keys).unwrap();
  }
}
