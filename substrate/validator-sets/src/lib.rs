#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![expect(
  let_underscore_drop,
  clippy::as_conversions,
  clippy::cast_possible_truncation,
  clippy::semicolon_if_nothing_returned
)]

extern crate alloc;
use alloc::{vec, vec::Vec};

use sp_core::sr25519::Public as SchnorrkelPublic;
use serai_abi::primitives::address::SeraiAddress;

mod embedded_elliptic_curve_keys;
use embedded_elliptic_curve_keys::*;

mod allocations;
use allocations::*;

mod sessions;
use sessions::{*, GenesisValidators as GenesisValidatorsContainer};

mod keys;
use keys::{KeysStorage, Keys as _};

#[frame_support::pallet]
mod pallet {
  use sp_application_crypto::RuntimePublic as _;

  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, traits::OneSessionHandler as _};

  use pallet_session::ShouldEndSession;
  use pallet_babe::Pallet as Babe;
  use pallet_grandpa::Pallet as Grandpa;

  use serai_abi::{
    primitives::{
      BitVec,
      crypto::{
        EmbeddedEllipticCurveKeys as EmbeddedEllipticCurveKeysStruct,
        SignedEmbeddedEllipticCurveKeys, ExternalKey, KeyPair, Signature,
      },
      network_id::*,
      coin::*,
      balance::*,
      validator_sets::{
        Session, ExternalValidatorSet, ValidatorSet, KeyShares as KeySharesStruct, SlashReport,
        DeallocationTimeline,
      },
    },
    economic_security::EconomicSecurity,
    validator_sets::Event,
  };

  use serai_core_pallet::Pallet as Core;
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;

  use super::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + pallet_session::Config
    + pallet_babe::Config
    + pallet_grandpa::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
  {
    type ShouldEndSession: ShouldEndSession<BlockNumberFor<Self>>;
    type EconomicSecurity: EconomicSecurity;
  }

  #[pallet::genesis_config]
  #[derive(Clone, Debug)]
  pub struct GenesisConfig<T: Config> {
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<(T::AccountId, Vec<SignedEmbeddedEllipticCurveKeys>)>,
  }
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      Self { participants: Default::default() }
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  struct Abstractions<T: Config>(PhantomData<T>);

  // Satisfy the `EmbeddedEllipticCurveKeys` abstraction

  #[pallet::storage]
  type EmbeddedEllipticCurveKeys<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalNetworkId,
    Blake2_128Concat,
    SeraiAddress,
    serai_abi::primitives::crypto::EmbeddedEllipticCurveKeys,
    OptionQuery,
  >;

  impl<T: Config> EmbeddedEllipticCurveKeysStorage for Abstractions<T> {
    type EmbeddedEllipticCurveKeys = EmbeddedEllipticCurveKeys<T>;
  }

  // Satisfy the `Allocations` abstraction

  #[pallet::storage]
  type Allocations<T: Config> =
    StorageMap<_, Blake2_128Concat, AllocationsKey, Amount, OptionQuery>;
  // This has to use `Identity` per the documentation of `AllocationsStorage`
  #[pallet::storage]
  type SortedAllocations<T: Config> =
    StorageMap<_, Identity, SortedAllocationsKey, (), OptionQuery>;

  impl<T: Config> AllocationsStorage for Abstractions<T> {
    type Allocations = Allocations<T>;
    type SortedAllocations = SortedAllocations<T>;
  }

  // Satisfy the `Sessions` abstraction

  // We use `Identity` as the hasher for `NetworkId` due to how constrained it is
  #[pallet::storage]
  type GenesisValidators<T: Config> = StorageValue<_, GenesisValidatorsContainer, OptionQuery>;
  #[pallet::storage]
  type AllocationPerKeyShare<T: Config> = StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  #[pallet::storage]
  type CurrentSession<T: Config> = StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  #[pallet::storage]
  type LatestDecidedSession<T: Config> = StorageMap<_, Identity, NetworkId, Session, OptionQuery>;
  #[pallet::storage]
  type KeyShares<T: Config> = StorageMap<_, Identity, ValidatorSet, KeySharesStruct, OptionQuery>;
  // This has to use `Identity` per the documentation of `SessionsStorage`
  #[pallet::storage]
  type SelectedValidators<T: Config> =
    StorageMap<_, Identity, SelectedValidatorsKey, KeySharesStruct, OptionQuery>;
  #[pallet::storage]
  type TotalAllocatedStake<T: Config> = StorageMap<_, Identity, NetworkId, Amount, OptionQuery>;
  #[pallet::storage]
  type DelayedDeallocations<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, SeraiAddress, Identity, Session, Amount, OptionQuery>;
  #[pallet::storage]
  type PendingSlashReport<T: Config> = StorageMap<_, Identity, ExternalNetworkId, (), OptionQuery>;

  impl<T: Config> SessionsStorage for Abstractions<T> {
    type Config = T;

    type GenesisValidators = GenesisValidators<T>;
    type AllocationPerKeyShare = AllocationPerKeyShare<T>;
    type CurrentSession = CurrentSession<T>;
    type LatestDecidedSession = LatestDecidedSession<T>;
    type KeyShares = KeyShares<T>;
    type SelectedValidators = SelectedValidators<T>;
    type TotalAllocatedStake = TotalAllocatedStake<T>;
    type DelayedDeallocations = DelayedDeallocations<T>;
    type PendingSlashReport = PendingSlashReport<T>;
  }

  // Satisfy the `Keys` abstractions
  #[pallet::storage]
  type OraclizationKeys<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, SchnorrkelPublic, OptionQuery>;
  #[pallet::storage]
  type ExternalKeys<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, ExternalKey, OptionQuery>;

  impl<T: Config> KeysStorage for Abstractions<T> {
    type OraclizationKeys = OraclizationKeys<T>;
    type ExternalKeys = ExternalKeys<T>;
  }

  #[pallet::error]
  pub enum Error<T> {
    /// The provided embedded elliptic curve keys were invalid.
    InvalidEmbeddedEllipticCurveKeys,
    /// Allocation was erroneous.
    AllocationError(AllocationError),
    /// Deallocation was erroneous.
    DeallocationError(DeallocationError),
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      GenesisValidators::<T>::set(Some(
        self
          .participants
          .iter()
          .map(|(participant, _keys)| *participant)
          .collect::<Vec<_>>()
          .try_into()
          .expect("amount of genesis validators exceeded the maximum allowed per set"),
      ));
      for (participant, keys) in &self.participants {
        for (network, keys) in ExternalNetworkId::all().zip(keys.iter().cloned()) {
          assert_eq!(network, keys.network());
          Pallet::<T>::set_embedded_elliptic_curve_keys_internal(*participant, keys)
            .expect("genesis embedded elliptic curve keys weren't valid");
        }
      }
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
      // This conversion assumes `SeraiAddress == SchnorrkelPublic`
      let genesis_serai_validators = Abstractions::<T>::serai_validators(Session(0));
      Babe::<T>::on_genesis_session(
        genesis_serai_validators
          .iter()
          .map(|(validator, key)| (validator, SchnorrkelPublic::from(*key).into())),
      );
      Grandpa::<T>::on_genesis_session(
        genesis_serai_validators
          .iter()
          .map(|(validator, key)| (validator, SchnorrkelPublic::from(*key).into())),
      );
    }
  }

  impl<T: Config> Pallet<T> {
    fn account() -> T::AccountId {
      SeraiAddress::system(b"ValidatorSets")
    }

    /// The current session for a network.
    pub fn current_session(network: NetworkId) -> Option<Session> {
      Abstractions::<T>::current_session(network)
    }

    /// The latest decided session for a network.
    pub fn latest_decided_session(network: NetworkId) -> Option<Session> {
      Abstractions::<T>::latest_decided_session(network)
    }

    /// The amount of key shares a validator has.
    ///
    /// Returns `None` for historic sessions which we no longer have the data for.
    pub fn key_shares(set: ValidatorSet) -> Option<KeySharesStruct> {
      Abstractions::<T>::key_shares(set)
    }

    /// If a validator is present within the specified validator set.
    ///
    /// This MAY return `false` for _any_ historic session, even if the validator _was_ present,
    pub fn in_validator_set(set: ValidatorSet, validator: SeraiAddress) -> bool {
      Abstractions::<T>::in_validator_set(set, validator)
    }

    /// The key shares possessed by a validator, within a validator set.
    ///
    /// This MAY return `None` for _any_ historic session, even if the validator _was_ present,
    pub fn key_shares_possessed_by_validator(
      set: ValidatorSet,
      validator: SeraiAddress,
    ) -> Option<KeySharesStruct> {
      Abstractions::<T>::key_shares_possessed_by_validator(set, validator)
    }

    /// The stake for the current validator set.
    pub fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
      Abstractions::<T>::stake_for_current_validator_set(network)
    }

    fn include_genesis_validators(network: NetworkId) -> bool {
      match network {
        // For Serai, we include the genesis validators as long as any other set does
        NetworkId::Serai => {
          !ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security)
        }
        // For the other networks, we include the genesis validators if they have yet to achieve
        // economic security
        NetworkId::External(network) => !T::EconomicSecurity::achieved_economic_security(network),
      }
    }

    /// The required amount of stake for a balance.
    fn stake_requirement(balance: ExternalBalance) -> AmountRepr {
      let value = T::EconomicSecurity::sri_value(balance).0;
      // As 67% can misbehave, 67% of stake must be sufficient to secure this
      let requirement = value.saturating_mul(3) / 2;
      // We add an additional margin of 20%
      let margin = requirement / 5;
      requirement.saturating_add(margin)
    }

    /// The required amount of stake for a network.
    fn network_stake_requirement(network: ExternalNetworkId) -> AmountRepr {
      let mut requirement = AmountRepr::zero();
      for coin in network.coins() {
        let supply = Coins::<T>::supply(Coin::from(coin));
        requirement = requirement
          .saturating_add(Self::stake_requirement(ExternalBalance { coin, amount: supply }));
      }
      requirement
    }

    pub fn selected_validators(
      set: ValidatorSet,
    ) -> impl Iterator<Item = (SeraiAddress, KeySharesStruct)> {
      Abstractions::<T>::selected_validators(set)
    }

    pub fn oraclization_key(set: ExternalValidatorSet) -> Option<SchnorrkelPublic> {
      Abstractions::<T>::oraclization_key(set)
    }

    pub fn external_key(set: ExternalValidatorSet) -> Option<ExternalKey> {
      Abstractions::<T>::external_key(set)
    }

    pub fn pending_slash_report(network: ExternalNetworkId) -> bool {
      Abstractions::<T>::waiting_for_slash_report(network).is_some()
    }

    pub fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: ExternalNetworkId,
    ) -> Option<EmbeddedEllipticCurveKeysStruct> {
      <Abstractions<T> as crate::EmbeddedEllipticCurveKeys>::embedded_elliptic_curve_keys(
        validator, network,
      )
    }

    fn set_embedded_elliptic_curve_keys_internal(
      validator: SeraiAddress,
      keys: SignedEmbeddedEllipticCurveKeys,
    ) -> DispatchResult {
      let keys =
        <Abstractions<T> as crate::EmbeddedEllipticCurveKeys>::set_embedded_elliptic_curve_keys(
          validator, keys,
        )
        .map_err(|()| Error::<T>::InvalidEmbeddedEllipticCurveKeys)?;
      Core::<T>::emit_event(Event::SetEmbeddedEllipticCurveKeys { validator, keys });
      Ok(())
    }

    /// Have the latest decided session become the current session.
    ///
    /// This is restricted to `ExternalNetworkId` as this process happens internally for
    /// `NetworkId::Serai`.
    pub fn accept_handover(network: ExternalNetworkId) {
      Abstractions::<T>::accept_handover(network.into());
    }

    /* TODO
    pub fn distribute_block_rewards(
      network: NetworkId,
      account: T::AccountId,
      amount: Amount,
    ) -> DispatchResult {
      // TODO: Should this call be part of the `increase_allocation` since we have to have it
      // before each call to it?
      Coins::<T>::transfer_fn(
        account,
        Self::account(),
        Balance { coin: Coin::Serai, amount },
      )?;
      Self::increase_allocation(network, account, amount, true)
    }
    */
  }

  #[pallet::hooks] // TODO: This is unsafe usage of `hooks` as defined by `serai-core-pallet`
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      if <T as Config>::ShouldEndSession::should_end_session(n) {
        Babe::<T>::on_before_session_ending();
        Grandpa::<T>::on_before_session_ending();

        {
          // Accept the hand-over to the next session for the Serai network
          Abstractions::<T>::accept_handover(NetworkId::Serai);
          // Decide the next session for the Serai network
          assert!(
            Abstractions::<T>::attempt_new_session(
              NetworkId::Serai,
              Self::include_genesis_validators(NetworkId::Serai)
            ),
            "failed to attempt the next session for the Serai network"
          );
        }

        // Update BABE, GRANDPA
        {
          let current_serai_session = Abstractions::<T>::current_session(NetworkId::Serai)
            .expect("never selected a session for Serai");
          let latest_decided_serai_session =
            Abstractions::<T>::latest_decided_session(NetworkId::Serai)
              .expect("current session yet no latest decided session for Serai");
          assert_eq!(
            Session(current_serai_session.0 + 1),
            latest_decided_serai_session,
            "latest decided Serai session wasn't the session after the current session"
          );

          let prior_serai_validators = Abstractions::<T>::serai_validators(Session(
            current_serai_session.0.checked_sub(1).expect("ShouldEndSession triggered on genesis"),
          ));
          assert!(
            !prior_serai_validators.is_empty(),
            "prior Serai validators weren't able to be fetched from storage",
          );

          let serai_validators = Abstractions::<T>::serai_validators(current_serai_session);

          let validators_changed = prior_serai_validators != serai_validators;

          let queued_serai_validators =
            Abstractions::<T>::serai_validators(latest_decided_serai_session);

          fn map_babe(
            (validator, key): &(SeraiAddress, SeraiAddress),
          ) -> (&SeraiAddress, pallet_babe::AuthorityId) {
            (validator, SchnorrkelPublic::from(*key).into())
          }
          Babe::<T>::on_new_session(
            validators_changed,
            serai_validators.iter().map(map_babe),
            queued_serai_validators.iter().map(map_babe),
          );

          fn map_grandpa(
            (validator, key): &(SeraiAddress, SeraiAddress),
          ) -> (&SeraiAddress, pallet_grandpa::AuthorityId) {
            (validator, SchnorrkelPublic::from(*key).into())
          }
          Grandpa::<T>::on_new_session(
            validators_changed,
            serai_validators.iter().map(map_grandpa),
            queued_serai_validators.iter().map(map_grandpa),
          );
        }

        // Attempt new sessions for all external networks
        for network in ExternalNetworkId::all() {
          Abstractions::<T>::attempt_new_session(
            network.into(),
            Self::include_genesis_validators(network.into()),
          );
        }

        // TODO Dex::<T>::on_new_session(network);

        Weight::zero() // TODO
      } else {
        Weight::zero()
      }
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
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
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn report_slashes(
      origin: OriginFor<T>,
      network: ExternalNetworkId,
      slashes: SlashReport,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // `signature` is checked within `ValidateUnsigned`
      let _ = signature;

      Abstractions::<T>::handle_slash_report(network, slashes);

      Ok(())
    }

    #[pallet::call_index(2)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn set_embedded_elliptic_curve_keys(
      origin: OriginFor<T>,
      keys: SignedEmbeddedEllipticCurveKeys,
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      Self::set_embedded_elliptic_curve_keys_internal(validator, keys)
    }

    #[pallet::call_index(3)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn allocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      Coins::<T>::transfer_fn(validator, Self::account(), Balance { coin: Coin::Serai, amount })?;
      Abstractions::<T>::increase_allocation(network, validator, amount, false)
        .map_err(Error::<T>::AllocationError)?;
      Ok(())
    }

    #[pallet::call_index(4)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn deallocate(origin: OriginFor<T>, network: NetworkId, amount: Amount) -> DispatchResult {
      let validator = ensure_signed(origin)?;

      let timeline = Abstractions::<T>::decrease_allocation(network, validator, amount)
        .map_err(Error::<T>::DeallocationError)?;

      Core::<T>::emit_event(Event::Deallocation { validator, network, amount, timeline });

      if matches!(timeline, DeallocationTimeline::Immediate) {
        Coins::<T>::transfer_fn(Self::account(), validator, Balance { coin: Coin::Serai, amount })?;
      }

      Ok(())
    }

    #[pallet::call_index(5)]
    #[pallet::weight((0, DispatchClass::Normal))] // TODO
    pub fn claim_deallocation(
      origin: OriginFor<T>,
      network: NetworkId,
      session: Session,
    ) -> DispatchResult {
      let validator = ensure_signed(origin)?;
      let amount = Abstractions::<T>::claim_delayed_deallocation(validator, network, session)
        .map_err(Error::<T>::DeallocationError)?;

      Core::<T>::emit_event(Event::DelayedDeallocationClaimed {
        validator,
        deallocation: ValidatorSet { network, session },
      });

      Coins::<T>::transfer_fn(Self::account(), validator, Balance { coin: Coin::Serai, amount })?;
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
          if Abstractions::<T>::needs_to_set_keys(set) {
            Err(InvalidTransaction::Stale)?;
          }

          let participants = Abstractions::<T>::selected_validators(set.into()).collect::<Vec<_>>();
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
          for ((participant, shares), in_use) in
            participants.into_iter().zip(signature_participants)
          {
            all_key_shares += u16::from(shares);

            if !in_use {
              continue;
            }

            /*
              This assumes `SeraiAddress == SchnorrkelPublic`, again.

              In the future, this will _need_ to be upgraded with post-quantum cryptography. When
              the time comes, the current expectation of non-interactive aggregation may be in
              conflict with how `Signature` is also used for transactions. For this reason, this
              `Signature` type is documented to potentially diverge in the future.
            */
            signers.push(SchnorrkelPublic::from(participant));
            signing_key_shares += u16::from(shares);
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
              if !set
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
        Call::report_slashes { network, ref slashes, ref signature } => {
          let network = *network;

          let Some(key) = Abstractions::<T>::waiting_for_slash_report(network) else {
            Err(InvalidTransaction::Stale)?
          };

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
        Call::set_embedded_elliptic_curve_keys { .. } |
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
}
pub use pallet::*;

sp_api::decl_runtime_apis! {
  #[api_version(1)]
  pub trait ValidatorSetsApi {
    /// Returns the validator set for a given network.
    fn validators(
      network_id: serai_abi::primitives::network_id::NetworkId,
    ) -> Vec<SeraiAddress>;

    /// Returns the external network key for a given external network.
    fn external_network_key(
      network: serai_abi::primitives::network_id::ExternalNetworkId,
    ) -> Option<serai_abi::primitives::crypto::ExternalKey>;
  }
}
