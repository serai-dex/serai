#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use ::alloc::{borrow::Cow, vec::Vec};

use sp_core::sr25519::Public;
use sp_runtime::{Perbill, Weight, traits::Header as _};
use sp_version::RuntimeVersion;

#[rustfmt::skip]
use serai_abi::{
  primitives::address::SeraiAddress, SubstrateHeader as Header, SubstrateBlock,
};

mod core_pallet;

type Block = SubstrateBlock;

/// The lookup for a SeraiAddress -> Public.
pub struct Lookup;
impl sp_runtime::traits::StaticLookup for Lookup {
  type Source = SeraiAddress;
  type Target = Public;
  fn lookup(source: SeraiAddress) -> Result<Public, sp_runtime::traits::LookupError> {
    Ok(source.into())
  }
  fn unlookup(source: Public) -> SeraiAddress {
    source.into()
  }
}

// TODO: Remove
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
  spec_name: Cow::Borrowed("serai"),
  impl_name: Cow::Borrowed("core"),
  authoring_version: 0,
  spec_version: 0,
  impl_version: 0,
  apis: RUNTIME_API_VERSIONS,
  transaction_version: 0,
  system_version: 0,
};

frame_support::parameter_types! {
  pub const Version: RuntimeVersion = VERSION;

  // TODO
  pub BlockLength: frame_system::limits::BlockLength =
    frame_system::limits::BlockLength::max_with_normal_ratio(0, Perbill::from_percent(0));
  // TODO
  pub BlockWeights: frame_system::limits::BlockWeights =
    frame_system::limits::BlockWeights::with_sensible_defaults(
      Weight::from_parts(0, 0),
      Perbill::from_percent(0),
    );
}

#[frame_support::runtime]
mod runtime {
  use super::*;

  #[runtime::runtime]
  #[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin)]
  pub struct Runtime;

  #[runtime::pallet_index(0)]
  pub type System = frame_system::Pallet<Runtime>;

  #[runtime::pallet_index(1)]
  pub type Core = core_pallet::Pallet<Runtime>;
}

impl frame_system::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type BaseCallFilter = frame_support::traits::Everything;
  type BlockWeights = BlockWeights;
  type BlockLength = BlockLength;
  type RuntimeOrigin = RuntimeOrigin;
  type RuntimeCall = RuntimeCall;
  type RuntimeTask = ();
  type Nonce = u32;
  type Hash = <Self::Block as sp_runtime::traits::Block>::Hash;
  type Hashing = sp_runtime::traits::BlakeTwo256;
  type AccountId = sp_core::sr25519::Public;
  type Lookup = Lookup;
  type Block = Block;
  // Don't track old block hashes within the System pallet
  // We use not a number -> hash index, but a hash -> () index, in our own pallet
  type BlockHashCount = sp_core::ConstU64<1>;
  type DbWeight = frame_support::weights::constants::RocksDbWeight;
  type Version = Version;
  type PalletInfo = PalletInfo;
  type AccountData = ();
  type OnNewAccount = ();
  type OnKilledAccount = ();
  // We use the default weights as we never expose/call any of these methods
  type SystemWeightInfo = ();
  // We also don't use the provided extensions framework
  type ExtensionsWeightInfo = ();
  // We don't invoke any hooks on-set-code as we don't perform upgrades via the blockchain yet via
  // nodes, ensuring everyone who upgrades consents to the rules they upgrade to
  type OnSetCode = ();
  type MaxConsumers = sp_core::ConstU32<{ u32::MAX }>;
  // No migrations set
  type SingleBlockMigrations = ();
  type MultiBlockMigrator = ();
  // We don't define any block-level hooks at this time
  type PreInherents = ();
  type PostInherents = ();
  type PostTransactions = ();
}

impl core_pallet::Config for Runtime {}

impl From<Option<SeraiAddress>> for RuntimeOrigin {
  fn from(signer: Option<SeraiAddress>) -> Self {
    match signer {
      None => RuntimeOrigin::none(),
      Some(signer) => RuntimeOrigin::signed(signer.into()),
    }
  }
}

impl From<serai_abi::Call> for RuntimeCall {
  fn from(call: serai_abi::Call) -> Self {
    match call {
      serai_abi::Call::Coins(call) => {
        use serai_abi::coins::Call;
        match call {
          Call::transfer { .. } | Call::burn { .. } | Call::burn_with_instruction { .. } => {
            todo!("TODO")
          }
        }
      }
      serai_abi::Call::ValidatorSets(call) => {
        use serai_abi::validator_sets::Call;
        match call {
          Call::set_keys { .. } |
          Call::report_slashes { .. } |
          Call::set_embedded_elliptic_curve_keys { .. } |
          Call::allocate { .. } |
          Call::deallocate { .. } |
          Call::claim_deallocation { .. } => todo!("TODO"),
        }
      }
      serai_abi::Call::Signals(call) => {
        use serai_abi::signals::Call;
        match call {
          Call::register_retirement_signal { .. } |
          Call::revoke_retirement_signal { .. } |
          Call::favor { .. } |
          Call::revoke_favor { .. } |
          Call::stand_against { .. } => todo!("TODO"),
        }
      }
      serai_abi::Call::Dex(call) => {
        use serai_abi::dex::Call;
        match call {
          Call::add_liquidity { .. } |
          Call::transfer_liquidity { .. } |
          Call::remove_liquidity { .. } |
          Call::swap_exact { .. } |
          Call::swap_for_exact { .. } => todo!("TODO"),
        }
      }
      serai_abi::Call::GenesisLiquidity(call) => {
        use serai_abi::genesis_liquidity::Call;
        match call {
          Call::oraclize_values { .. } | Call::remove_liquidity { .. } => todo!("TODO"),
        }
      }
      serai_abi::Call::InInstructions(call) => {
        use serai_abi::in_instructions::Call;
        match call {
          Call::execute_batch { .. } => todo!("TODO"),
        }
      }
    }
  }
}

type Executive = frame_executive::Executive<Runtime, Block, Context, Runtime, AllPalletsWithSystem>;

sp_api::impl_runtime_apis! {
  impl sp_api::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
      VERSION
    }
    fn initialize_block(header: &Header) -> sp_runtime::ExtrinsicInclusionMode {
      core_pallet::Blocks::<Runtime>::set(header.parent_hash(), Some(()));
      Executive::initialize_block(header)
    }
    fn execute_block(block: Block) {
      Executive::execute_block(block);
    }
  }
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct Context;
impl serai_abi::TransactionContext for Context {
  // TODO
  const SIGNED_WEIGHT: Weight = Weight::zero();

  type RuntimeCall = RuntimeCall;

  /// The implicit context to verify transactions with.
  fn implicit_context() -> serai_abi::ImplicitContext {
    serai_abi::ImplicitContext {
      genesis: System::block_hash(0).into(),
      protocol_id: [0; 32], // TODO via build script
    }
  }

  /// If a block is present in the blockchain.
  fn block_is_present_in_blockchain(&self, hash: &serai_abi::primitives::BlockHash) -> bool {
    core_pallet::Blocks::<Runtime>::get(hash).is_some()
  }
  /// The time embedded into the current block.
  fn current_time(&self) -> Option<u64> {
    todo!("TODO")
  }
  /// Get, and consume, the next nonce for an account.
  fn get_and_consume_next_nonce(&self, signer: &SeraiAddress) -> u32 {
    core_pallet::NextNonce::<Runtime>::mutate(signer, |value| {
      // Copy the current value for the next nonce
      let next_nonce = *value;
      // Increment the next nonce in the DB, consuming the current value
      *value += 1;
      // Return the existing value
      next_nonce
    })
  }
  /// If the signer can pay the SRI fee.
  fn can_pay_fee(
    &self,
    signer: &SeraiAddress,
    fee: serai_abi::primitives::balance::Amount,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    todo!("TODO")
  }
  /// Have the transaction pay its SRI fee.
  fn pay_fee(
    &self,
    signer: &SeraiAddress,
    fee: serai_abi::primitives::balance::Amount,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    todo!("TODO")
  }
}

/*
use core::marker::PhantomData;

// Re-export all components
pub use serai_primitives as primitives;
pub use primitives::{BlockNumber, Header};

pub use frame_system as system;
pub use frame_support as support;

pub use pallet_timestamp as timestamp;

pub use pallet_transaction_payment as transaction_payment;

pub use coins_pallet as coins;
pub use dex_pallet as dex;

pub use validator_sets_pallet as validator_sets;

pub use in_instructions_pallet as in_instructions;

pub use signals_pallet as signals;

pub use pallet_babe as babe;
pub use pallet_grandpa as grandpa;

pub use genesis_liquidity_pallet as genesis_liquidity;
pub use emissions_pallet as emissions;

pub use economic_security_pallet as economic_security;

// Actually used by the runtime
use sp_core::OpaqueMetadata;
use sp_std::prelude::*;

use sp_version::RuntimeVersion;
#[cfg(feature = "std")]
use sp_version::NativeVersion;

use sp_runtime::{
  create_runtime_str, generic, impl_opaque_keys, KeyTypeId,
  traits::{Convert, BlakeTwo256, Block as BlockT},
  transaction_validity::{TransactionSource, TransactionValidity},
  BoundedVec, Perbill, ApplyExtrinsicResult,
};

#[allow(unused_imports)]
use primitives::{
  NetworkId, ExternalNetworkId, PublicKey, AccountLookup, SubstrateAmount, Coin, EXTERNAL_NETWORKS,
  MEDIAN_PRICE_WINDOW_LENGTH, HOURS, DAYS, MINUTES, TARGET_BLOCK_TIME, BLOCK_SIZE,
  FAST_EPOCH_DURATION,
};

use support::{
  traits::{ConstU8, ConstU16, ConstU32, ConstU64, Contains},
  weights::{
    constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
    IdentityFee, Weight,
  },
  parameter_types, construct_runtime,
};

use validator_sets::MembershipProof;

use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use babe::AuthorityId as BabeId;
use grandpa::AuthorityId as GrandpaId;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

pub type SignedExtra = (
  system::CheckNonZeroSender<Runtime>,
  system::CheckWeight<Runtime>, TODO
);

pub mod opaque {
  use super::*;

  impl_opaque_keys! {
    pub struct SessionKeys {
      pub babe: Babe,
      pub grandpa: Grandpa,
    }
  }
}

pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
  sp_consensus_babe::BabeEpochConfiguration {
    c: PRIMARY_PROBABILITY,
    allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
  };

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
  pub const Version: RuntimeVersion = VERSION;

  pub const SS58Prefix: u8 = 42; // TODO: Remove for Bech32m

  // 1 MB block size limit
  pub BlockLength: system::limits::BlockLength =
    system::limits::BlockLength::max_with_normal_ratio(BLOCK_SIZE, NORMAL_DISPATCH_RATIO);
  pub BlockWeights: system::limits::BlockWeights =
    system::limits::BlockWeights::with_sensible_defaults(
      Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
      NORMAL_DISPATCH_RATIO,
    );
}

impl timestamp::Config for Runtime {
  type Moment = u64;
  type OnTimestampSet = Babe;
  type MinimumPeriod = ConstU64<{ (TARGET_BLOCK_TIME * 1000) / 2 }>;
  type WeightInfo = ();
}

impl transaction_payment::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type OnChargeTransaction = Coins;
  type OperationalFeeMultiplier = ConstU8<5>;
  type WeightToFee = IdentityFee<SubstrateAmount>;
  type LengthToFee = IdentityFee<SubstrateAmount>;
  type FeeMultiplierUpdate = ();
}

impl coins::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type AllowMint = ValidatorSets;
}

impl coins::Config<coins::Instance1> for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type AllowMint = ();
}

impl dex::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type LPFee = ConstU32<3>; // 0.3%
  type MintMinLiquidity = ConstU64<10000>;

  type MaxSwapPathLength = ConstU32<3>; // coin1 -> SRI -> coin2

  type MedianPriceWindowLength = ConstU16<{ MEDIAN_PRICE_WINDOW_LENGTH }>;

  type WeightInfo = dex::weights::SubstrateWeight<Runtime>;
}

impl validator_sets::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type ShouldEndSession = Babe;
}

pub struct IdentityValidatorIdOf;
impl Convert<PublicKey, Option<PublicKey>> for IdentityValidatorIdOf {
  fn convert(key: PublicKey) -> Option<PublicKey> {
    Some(key)
  }
}

impl signals::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  // 1 week
  #[allow(clippy::cast_possible_truncation)]
  type RetirementValidityDuration = ConstU32<{ (7 * 24 * 60 * 60) / (TARGET_BLOCK_TIME as u32) }>;
  // 2 weeks
  #[allow(clippy::cast_possible_truncation)]
  type RetirementLockInDuration = ConstU32<{ (2 * 7 * 24 * 60 * 60) / (TARGET_BLOCK_TIME as u32) }>;
}

impl in_instructions::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

impl genesis_liquidity::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
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

// Maximum number of authorities per session.
pub type MaxAuthorities = ConstU32<{ validator_sets::primitives::MAX_KEY_SHARES_PER_SET_U32 }>;

/// Longevity of an offence report.
pub type ReportLongevity = <Runtime as pallet_babe::Config>::EpochDuration;

impl babe::Config for Runtime {
  #[cfg(feature = "fast-epoch")]
  type EpochDuration = ConstU64<{ FAST_EPOCH_DURATION }>;

  #[cfg(not(feature = "fast-epoch"))]
  type EpochDuration = ConstU64<{ 4 * 7 * DAYS }>;

  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME * 1000 }>;
  type EpochChangeTrigger = babe::ExternalTrigger;
  type DisabledValidators = ValidatorSets;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;

  type KeyOwnerProof = MembershipProof<Self>;
  type EquivocationReportSystem =
    babe::EquivocationReportSystem<Self, ValidatorSets, ValidatorSets, ReportLongevity>;
}

impl grandpa::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;

  type MaxSetIdSessionEntries = ConstU64<0>;
  type KeyOwnerProof = MembershipProof<Self>;
  type EquivocationReportSystem =
    grandpa::EquivocationReportSystem<Self, ValidatorSets, ValidatorSets, ReportLongevity>;
}

construct_runtime!(
  pub enum Runtime {
    System: system exclude_parts { Call },

    Timestamp: timestamp,

    TransactionPayment: transaction_payment,

    Coins: coins,
    LiquidityTokens: coins::<Instance1>::{Pallet, Call, Storage, Event<T>},
    Dex: dex,

    ValidatorSets: validator_sets,
    GenesisLiquidity: genesis_liquidity,
    Emissions: emissions,

    EconomicSecurity: economic_security,

    InInstructions: in_instructions,

    Signals: signals,

    Babe: babe,
    Grandpa: grandpa,
  }
);

#[cfg(feature = "runtime-benchmarks")]
#[macro_use]
extern crate frame_benchmarking;

#[cfg(feature = "runtime-benchmarks")]
mod benches {
  define_benchmarks!(
    [frame_benchmarking, BaselineBench::<Runtime>]

    [system, SystemBench::<Runtime>]

    [pallet_timestamp, Timestamp]

    [balances, Balances]

    [babe, Babe]
    [grandpa, Grandpa]
  );
}

sp_api::impl_runtime_apis! {
  impl sp_api::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
      VERSION
    }

    fn execute_block(block: Block) {
      Executive::execute_block(block);
    }

    fn initialize_block(header: &Header) {
      Executive::initialize_block(header)
    }
  }

  impl sp_api::Metadata<Block> for Runtime {
    fn metadata() -> OpaqueMetadata {
      OpaqueMetadata::new(Runtime::metadata().into())
    }

    fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
      Runtime::metadata_at_version(version)
    }

    fn metadata_versions() -> sp_std::vec::Vec<u32> {
      Runtime::metadata_versions()
    }
  }

  impl sp_block_builder::BlockBuilder<Block> for Runtime {
    fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
      Executive::apply_extrinsic(extrinsic)
    }

    fn finalize_block() -> Header {
      Executive::finalize_block()
    }

    fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
      data.create_extrinsics()
    }

    fn check_inherents(
      block: Block,
      data: sp_inherents::InherentData,
    ) -> sp_inherents::CheckInherentsResult {
      data.check_extrinsics(&block)
    }
  }

  impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
    fn validate_transaction(
      source: TransactionSource,
      tx: <Block as BlockT>::Extrinsic,
      block_hash: <Block as BlockT>::Hash,
    ) -> TransactionValidity {
      Executive::validate_transaction(source, tx, block_hash)
    }
  }

  impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
    fn offchain_worker(header: &Header) {
      Executive::offchain_worker(header)
    }
  }

  impl sp_session::SessionKeys<Block> for Runtime {
    fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
      opaque::SessionKeys::generate(seed)
    }

    fn decode_session_keys(
      encoded: Vec<u8>,
    ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
      opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
    }
  }

  impl sp_consensus_babe::BabeApi<Block> for Runtime {
    fn configuration() -> sp_consensus_babe::BabeConfiguration {
      use support::traits::Get;

      let epoch_config = Babe::epoch_config().unwrap_or(BABE_GENESIS_EPOCH_CONFIG);
      sp_consensus_babe::BabeConfiguration {
        slot_duration: Babe::slot_duration(),
        epoch_length: <Runtime as babe::Config>::EpochDuration::get(),
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

    // This refers to a key being 'owned' by an authority in a system with multiple keys per
    // validator
    // Since we do not have such an infrastructure, we do not need this
    fn generate_key_ownership_proof(
      _slot: sp_consensus_babe::Slot,
      _authority_id: BabeId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      Some(sp_consensus_babe::OpaqueKeyOwnershipProof::new(vec![]))
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_babe::EquivocationProof<Header>,
      _: sp_consensus_babe::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      let proof = MembershipProof(equivocation_proof.offender.clone().into(), PhantomData);
      Babe::submit_unsigned_equivocation_report(equivocation_proof, proof)
    }
  }

  impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
    fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
      Grandpa::grandpa_authorities()
    }

    fn current_set_id() -> sp_consensus_grandpa::SetId {
      Grandpa::current_set_id()
    }

    fn generate_key_ownership_proof(
      _set_id: sp_consensus_grandpa::SetId,
      _authority_id: GrandpaId,
    ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
      Some(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new(vec![]))
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_grandpa::EquivocationProof<<Block as BlockT>::Hash, u64>,
      _: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      let proof = MembershipProof(equivocation_proof.offender().clone().into(), PhantomData);
      Grandpa::submit_unsigned_equivocation_report(equivocation_proof, proof)
    }
  }

  impl frame_system_rpc_runtime_api::AccountNonceApi<Block, PublicKey, Nonce> for Runtime {
    fn account_nonce(account: PublicKey) -> Nonce {
      System::account_nonce(account)
    }
  }

  impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
    Block,
    SubstrateAmount
  > for Runtime {
    fn query_info(
      uxt: <Block as BlockT>::Extrinsic,
      len: u32,
    ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<SubstrateAmount> {
      TransactionPayment::query_info(uxt, len)
    }

    fn query_fee_details(
      uxt: <Block as BlockT>::Extrinsic,
      len: u32,
    ) -> transaction_payment::FeeDetails<SubstrateAmount> {
      TransactionPayment::query_fee_details(uxt, len)
    }

    fn query_weight_to_fee(weight: Weight) -> SubstrateAmount {
      TransactionPayment::weight_to_fee(weight)
    }

    fn query_length_to_fee(length: u32) -> SubstrateAmount {
      TransactionPayment::length_to_fee(length)
    }
  }

  impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
    fn authorities() -> Vec<AuthorityDiscoveryId> {
      // Converts to `[u8; 32]` so it can be hashed
      let serai_validators = Babe::authorities()
        .into_iter()
        .map(|(id, _)| id.into_inner().0)
        .collect::<hashbrown::HashSet<_>>();
      let mut all = serai_validators;
      for network in EXTERNAL_NETWORKS {
        // Returning the latest-decided, not latest and active, means the active set
        // may fail to peer find if there isn't sufficient overlap. If a large amount reboot,
        // forcing some validators to successfully peer find in order for the threshold to become
        // online again, this may cause a liveness failure.
        //
        // This is assumed not to matter in real life, yet an interesting note.
        let participants =
          ValidatorSets::participants_for_latest_decided_set(NetworkId::from(network))
            .map_or(vec![], BoundedVec::into_inner);
        for (participant, _) in participants {
          all.insert(participant.0);
        }
      }
      all.into_iter().map(|id| AuthorityDiscoveryId::from(PublicKey::from_raw(id))).collect()
    }
  }

  impl validator_sets::ValidatorSetsApi<Block> for Runtime {
    fn validators(network_id: NetworkId) -> Vec<PublicKey> {
      if network_id == NetworkId::Serai {
        Babe::authorities()
          .into_iter()
          .map(|(id, _)| id.into_inner())
          .collect()
      } else {
        ValidatorSets::participants_for_latest_decided_set(network_id)
          .map_or(
            vec![],
            |vec| vec.into_inner().into_iter().map(|(validator, _)| validator).collect()
          )
      }
    }

    fn external_network_key(network: ExternalNetworkId) -> Option<Vec<u8>> {
      ValidatorSets::external_network_key(network)
    }
  }

  impl dex::DexApi<Block> for Runtime {
    fn quote_price_exact_tokens_for_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool
    ) -> Option<SubstrateAmount> {
      Dex::quote_price_exact_tokens_for_tokens(coin1, coin2, amount, include_fee)
    }

    fn quote_price_tokens_for_exact_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool
    ) -> Option<SubstrateAmount> {
      Dex::quote_price_tokens_for_exact_tokens(coin1, coin2, amount, include_fee)
    }

    fn get_reserves(coin1: Coin, coin2: Coin) -> Option<(SubstrateAmount, SubstrateAmount)> {
      Dex::get_reserves(&coin1, &coin2).ok()
    }
  }
}
*/
