#![expect(clippy::as_conversions, clippy::same_name_method, clippy::used_underscore_binding)]

use core::marker::PhantomData;
use alloc::{borrow::Cow, vec, vec::Vec};

use sp_core::{Get, ConstU32, ConstU64, sr25519::Public};
use sp_runtime::{
  Weight,
  traits::{Header as _, LazyBlock as _},
};
use sp_version::RuntimeVersion;

use serai_abi::{
  primitives::{
    constants::*,
    crypto::EmbeddedEllipticCurveKeys,
    network_id::{ExternalNetworkId, NetworkId},
    coin::Coin,
    balance::{Amount, Balance},
    validator_sets::{Session, ExternalValidatorSet, ValidatorSet},
    address::SeraiAddress,
  },
  SubstrateHeader as Header, SubstrateBlock as Block, LazySubstrateBlock as LazyBlock,
};

use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance};

/// Maps `serai_abi` types into the types expected within the Substrate runtime
mod map;
/// The configuration for `frame_system`.
mod system;

// The `pallet_index`es don't matter here as we define our ABI elsewhere, and they don't affect the
// storage layout. The only important property is the order hooks are executed in.
#[frame_support::runtime]
mod runtime {
  use super::*;

  #[runtime::runtime]
  #[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin)]
  pub struct Runtime;

  #[runtime::pallet_index(0x00)]
  #[runtime::disable_inherent]
  pub type Timestamp = pallet_timestamp::Pallet<Runtime>;

  #[runtime::pallet_index(0x01)]
  pub type Babe = pallet_babe::Pallet<Runtime>;

  #[runtime::pallet_index(0x02)]
  pub type Grandpa = pallet_grandpa::Pallet<Runtime>;

  #[runtime::pallet_index(0x40)]
  pub type System = frame_system::Pallet<Runtime>;

  #[runtime::pallet_index(0x41)]
  pub type Core = serai_core_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x42)]
  pub type Coins = serai_coins_pallet::Pallet<Runtime, CoinsInstance>;

  #[runtime::pallet_index(0x43)]
  pub type ValidatorSets = serai_validator_sets_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x44)]
  pub type Signals = serai_signals_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x45)]
  pub type LiquidityTokens = serai_coins_pallet::Pallet<Runtime, LiquidityTokensInstance>;

  #[runtime::pallet_index(0x46)]
  pub type Dex = serai_dex_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x47)]
  pub type GenesisLiquidity = serai_genesis_liquidity_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x48)]
  pub type EconomicSecurity = serai_economic_security_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x49)]
  pub type InInstructions = serai_in_instructions_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0xc0)]
  pub type Emissions = serai_emissions_pallet::Pallet<Runtime>;
}

impl serai_core_pallet::Config for Runtime {
  // TODO via build script
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  // TODO
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

impl serai_coins_pallet::Config<CoinsInstance> for Runtime {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint; // TODO
  type Weights = (); // TODO
}
impl serai_validator_sets_pallet::Config for Runtime {
  type ShouldEndSession = Babe;
  type EconomicSecurity = EconomicSecurity;
}
impl serai_signals_pallet::Config for Runtime {
  type RetirementLockInDurationInSlots = ConstU64<{ RETIREMENT_LOCK_IN_DURATION_IN_SLOTS }>;
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Runtime {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = (); // TODO
}
impl serai_dex_pallet::Config for Runtime {}
impl serai_genesis_liquidity_pallet::Config for Runtime {}
impl serai_economic_security_pallet::Config for Runtime {}
impl serai_emissions_pallet::Config for Runtime {}
impl serai_in_instructions_pallet::Config for Runtime {}

impl pallet_timestamp::Config for Runtime {
  type Moment = u64;
  type OnTimestampSet = Babe;
  type MinimumPeriod = ConstU64<{ (TARGET_BLOCK_TIME.as_millis() / 2) as u64 }>;
  type WeightInfo = ();
}

// pallet-babe requires `pallet-session` for `GetCurrentSessionForSubstrate` but not it itself
// We ensure this by having patched `pallet-session` to omit the pallet
#[doc(hidden)]
pub struct GetCurrentSessionForSubstrate;
impl pallet_session::GetCurrentSessionForSubstrate for GetCurrentSessionForSubstrate {
  fn get() -> u32 {
    serai_validator_sets_pallet::Pallet::<Runtime>::current_session(NetworkId::Serai)
      .map(|session| session.0)
      .unwrap_or(0)
  }
}
impl pallet_session::Config for Runtime {
  type Session = GetCurrentSessionForSubstrate;
}

type MaxAuthorities =
  ConstU32<{ serai_abi::primitives::validator_sets::KeyShares::MAX_PER_SET_U32 }>;
impl pallet_babe::Config for Runtime {
  type EpochDuration = ConstU64<{ SESSION_LENGTH_IN_SLOTS }>;

  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME.as_millis() as u64 }>;
  type EpochChangeTrigger = pallet_babe::ExternalTrigger;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;
  type MaxNominators = ConstU32<1>;

  // TODO: https://github.com/serai-dex/serai/issues/657
  type DisabledValidators = ();
  type KeyOwnerProof = sp_session::MembershipProof;
  type EquivocationReportSystem = ();
}
impl pallet_grandpa::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;
  type MaxNominators = ConstU32<1>;

  // TODO: https://github.com/serai-dex/serai/issues/657
  type MaxSetIdSessionEntries = ConstU64<0>;
  type KeyOwnerProof = sp_session::MembershipProof;
  type EquivocationReportSystem = ();
}

type ExecutiveContext = PhantomData<(Core, FeeContext)>;
type Executive =
  frame_executive::Executive<Runtime, Block, ExecutiveContext, Runtime, AllPalletsWithSystem>;

const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
  sp_consensus_babe::BabeEpochConfiguration {
    c: PRIMARY_PROBABILITY,
    allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
  };

sp_api::impl_runtime_apis! {
  impl crate::GenesisApi<Block> for Runtime {
    fn build(genesis: crate::GenesisConfig) {
      let config = RuntimeGenesisConfig {
        system: SystemConfig { _config: PhantomData },

        coins: CoinsConfig {
          accounts: genesis.coins.into_iter().map(|(key, balance)| (key.into(), balance)).collect(),
          _instance: PhantomData,
        },

        liquidity_tokens: LiquidityTokensConfig { accounts: vec![], _instance: PhantomData },

        validator_sets: ValidatorSetsConfig {
          participants:
            genesis.validators.into_iter().map(|(key, keys)| (key.into(), keys)).collect(),
        },
        signals: SignalsConfig::default(),

        // We leave these `authorities` empty as `serai-validator-sets-pallet` initializes them
        babe: BabeConfig {
          authorities: vec![],
          epoch_config: BABE_GENESIS_EPOCH_CONFIG,
          _config: PhantomData,
        },
        grandpa: GrandpaConfig { authorities: vec![], _config: PhantomData },
      };

      Core::genesis(&config);
    }
  }

  impl sp_api::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
      <Runtime as frame_system::Config>::Version::get()
    }
    fn initialize_block(header: &Header) -> sp_runtime::ExtrinsicInclusionMode {
      Executive::initialize_block(header)
    }
    fn execute_block(block: LazyBlock) {
      Executive::execute_block(block);
    }
  }

  impl sp_block_builder::BlockBuilder<Block> for Runtime {
    fn apply_extrinsic(
      extrinsic: <Block as sp_runtime::traits::Block>::Extrinsic,
    ) -> sp_runtime::ApplyExtrinsicResult {
      Executive::apply_extrinsic(extrinsic)
    }

    fn finalize_block() -> Header {
      Executive::finalize_block()
    }

    fn inherent_extrinsics(
      data: sp_inherents::InherentData,
    ) -> Vec<<Block as sp_runtime::traits::Block>::Extrinsic> {
      data.create_extrinsics()
    }

    fn check_inherents(
      block: LazyBlock,
      data: sp_inherents::InherentData,
    ) -> sp_inherents::CheckInherentsResult {
      let mut result = data.check_extrinsics(&block);

      // Handle the `SeraiPreExecutionDigest`
      'outer: {
        use serai_abi::SeraiPreExecutionDigest;

        const INHERENT_ID: [u8; 8] = [
          SeraiPreExecutionDigest::CONSENSUS_ID[0],
          SeraiPreExecutionDigest::CONSENSUS_ID[1],
          SeraiPreExecutionDigest::CONSENSUS_ID[2],
          SeraiPreExecutionDigest::CONSENSUS_ID[3],
          0, 0, 0, 0
        ];

        for log in block.header().digest().logs() {
          #[expect(clippy::wildcard_enum_match_arm)]
          match log {
            sp_runtime::DigestItem::PreRuntime(consensus, encoded)
              if *consensus == SeraiPreExecutionDigest::CONSENSUS_ID =>
            {
              let Ok(SeraiPreExecutionDigest { unix_time_in_millis }) =
                <_ as borsh::BorshDeserialize>::deserialize_reader(&mut encoded.as_slice()) else {
                // We don't handle this error as we can't in this position
                let _ = result.put_error(
                  INHERENT_ID,
                  &sp_inherents::MakeFatalError::from("invalid `SeraiPreExecutionDigest`"),
                );
                return result;
              };

              use frame_support::inherent::ProvideInherent;
              match pallet_timestamp::Pallet::<Runtime>::check_inherent(
                &pallet_timestamp::Call::<Runtime>::set { now: unix_time_in_millis },
                &data
              ) {
                Ok(()) => {},
                Err(e) => {
                  let _ = result.put_error(sp_timestamp::INHERENT_IDENTIFIER, &e);
                }
              }

              break 'outer;
            }
            _ => {}
          }
        }

        let _ = result.put_error(
          INHERENT_ID,
          &sp_inherents::MakeFatalError::from("missing `SeraiPreExecutionDigest`")
        );
      }

      result
    }
  }

  impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
    fn validate_transaction(
      source: sp_runtime::transaction_validity::TransactionSource,
      tx: <Block as sp_runtime::traits::Block>::Extrinsic,
      block_hash: <Block as sp_runtime::traits::Block>::Hash,
    ) -> sp_runtime::transaction_validity::TransactionValidity {
      Executive::validate_transaction(source, tx, block_hash)
    }
  }

  impl sp_consensus_babe::BabeApi<Block> for Runtime {
    fn configuration() -> sp_consensus_babe::BabeConfiguration {
      use frame_support::traits::Get;

      let epoch_config = Babe::epoch_config().unwrap_or(BABE_GENESIS_EPOCH_CONFIG);
      sp_consensus_babe::BabeConfiguration {
        slot_duration: Babe::slot_duration(),
        epoch_length: <Runtime as pallet_babe::Config>::EpochDuration::get(),
        c: epoch_config.c,
        authorities: Babe::authorities().to_vec(),
        randomness: Babe::randomness(),
        allowed_slots: epoch_config.allowed_slots,
      }
    }

    fn current_epoch_start() -> sp_consensus_babe::Slot {
      Babe::current_epoch_start()
    }

    fn current_epoch() -> sp_consensus_babe::Epoch {
      Babe::current_epoch()
    }

    fn next_epoch() -> sp_consensus_babe::Epoch {
      Babe::next_epoch()
    }

    // TODO: Revisit
    fn generate_key_ownership_proof(
      _slot: sp_consensus_babe::Slot,
      _authority_id: sp_consensus_babe::AuthorityId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      None
    }

    // TODO: Revisit
    fn submit_report_equivocation_unsigned_extrinsic(
      _equivocation_proof: sp_consensus_babe::EquivocationProof<Header>,
      _: sp_consensus_babe::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      None
    }
  }

  impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
    fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
      Grandpa::grandpa_authorities()
    }

    fn current_set_id() -> sp_consensus_grandpa::SetId {
      Grandpa::current_set_id()
    }

    // TODO: Revisit
    fn generate_key_ownership_proof(
      _set_id: sp_consensus_grandpa::SetId,
      _authority_id: sp_consensus_grandpa::AuthorityId,
    ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
      None
    }

    // TODO: Revisit
    fn submit_report_equivocation_unsigned_extrinsic(
      _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
        <Block as sp_runtime::traits::Block>::Hash,
        u64,
      >,
      _: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      None
    }
  }

  impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
    fn authorities() -> Vec<sp_authority_discovery::AuthorityId> {
      // Converts to `[u8; 32]` so it can be hashed
      let mut all = alloc::collections::BTreeSet::<[u8; 32]>::new();
      for network in NetworkId::all() {
        for participant in
          <Self as super::runtime_decl_for_serai_api::SeraiApi<Block>>::validators(network) {
          all.insert(Public::from(participant).into());
        }
      }
      all
        .into_iter()
        .map(|id| sp_authority_discovery::AuthorityId::from(Public::from(id)))
        .collect()
    }
  }

  impl crate::SeraiApi<Block> for Runtime {
    fn events() -> Vec<Vec<Vec<u8>>> {
      Core::events()
    }
    fn validators(network: NetworkId) -> Vec<SeraiAddress> {
      // Returning the latest-decided, not latest and active, means the active set
      // may fail to peer find if there isn't sufficient overlap. If a large amount reboot,
      // forcing some validators to successfully peer find in order for the threshold to become
      // online again, this may cause a liveness failure.
      //
      // This is assumed not to matter in real life, yet an interesting note.
      let Some(session) = ValidatorSets::latest_decided_session(network) else {
        return vec![]
      };
      ValidatorSets::selected_validators(ValidatorSet { network, session })
        .map(|validator| validator.0.into())
        .collect()
    }
    fn current_session(network: NetworkId) -> Option<Session> {
      ValidatorSets::current_session(network)
    }
    fn current_stake(network: NetworkId) -> Option<Amount> {
      ValidatorSets::stake_for_current_validator_set(network)
    }
    fn keys(set: ExternalValidatorSet) -> Option<serai_abi::primitives::crypto::KeyPair> {
      ValidatorSets::oraclization_key(set)
        .and_then(|oraclization_key| {
          ValidatorSets::external_key(set)
            .map(|external_key| {
              serai_abi::primitives::crypto::KeyPair(oraclization_key.into(), external_key)
            })
        })
    }
    fn current_validators(network: NetworkId) -> Option<Vec<SeraiAddress>> {
      let session = ValidatorSets::current_session(network)?;
      Some(
        ValidatorSets::selected_validators(ValidatorSet { network, session })
          .map(|(key, _key_shares)| SeraiAddress::from(key))
          .collect()
      )
    }
    fn pending_slash_report(network: ExternalNetworkId) -> bool {
      ValidatorSets::pending_slash_report(network)
    }
    fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: ExternalNetworkId,
    ) -> Option<EmbeddedEllipticCurveKeys> {
      ValidatorSets::embedded_elliptic_curve_keys(validator.into(), network)
    }
  }
}

struct FeeContext;
impl serai_abi::TransactionFeeContext for FeeContext {
  /// If the signer can pay the fee.
  fn can_pay_fee(
    signer: &SeraiAddress,
    fee: Balance,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    if fee.coin != Coin::Serai {
      Err(sp_runtime::transaction_validity::TransactionValidityError::Invalid(
        sp_runtime::transaction_validity::InvalidTransaction::Payment,
      ))?;
    }

    if serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::balance(signer, fee.coin) >= fee.amount
    {
      Ok(())
    } else {
      Err(sp_runtime::transaction_validity::TransactionValidityError::Invalid(
        sp_runtime::transaction_validity::InvalidTransaction::Payment,
      ))
    }
  }

  /// Have the transaction pay its fee.
  fn pay_fee(
    signer: &SeraiAddress,
    fee: Balance,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    if fee.coin != Coin::Serai {
      Err(sp_runtime::transaction_validity::TransactionValidityError::Invalid(
        sp_runtime::transaction_validity::InvalidTransaction::Payment,
      ))?;
    }

    serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::burn(RuntimeOrigin::signed(*signer), fee)
      .map_err(|_| {
        sp_runtime::transaction_validity::TransactionValidityError::Invalid(
          sp_runtime::transaction_validity::InvalidTransaction::Payment,
        )
      })
  }
}

/* TODO
use validator_sets::MembershipProof;

impl timestamp::Config for Runtime {
  type MinimumPeriod = ConstU64<{ (TARGET_BLOCK_TIME * 1000) / 2 }>;
  type WeightInfo = ();
}

impl coins::Config for Runtime {
  type AllowMint = ValidatorSets;
}

impl dex::Config for Runtime {
  type LPFee = ConstU32<3>; // 0.3%
  type MintMinLiquidity = ConstU64<10000>;

  type MaxSwapPathLength = ConstU32<3>; // coin1 -> SRI -> coin2

  type MedianPriceWindowLength = ConstU16<{ MEDIAN_PRICE_WINDOW_LENGTH }>;

  type WeightInfo = dex::weights::SubstrateWeight<Runtime>;
}

pub struct IdentityValidatorIdOf;
impl Convert<PublicKey, Option<PublicKey>> for IdentityValidatorIdOf {
  fn convert(key: PublicKey) -> Option<PublicKey> {
    Some(key)
  }
}

impl emissions::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

impl economic_security::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

// for publishing equivocation evidences.
impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
  RuntimeCall: From<C>,
{
  type Extrinsic = Transaction;
  type OverarchingCall = RuntimeCall;
}

// for validating equivocation evidences.
// The following runtime construction doesn't actually implement the pallet as doing so is
// unnecessary
// TODO: Replace the requirement on Config for a requirement on FindAuthor directly
impl pallet_authorship::Config for Runtime {
  type FindAuthor = ValidatorSets;
  type EventHandler = ();
}

/// Longevity of an offence report.
pub type ReportLongevity = <Runtime as pallet_babe::Config>::EpochDuration;
*/
