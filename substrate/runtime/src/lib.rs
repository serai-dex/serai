#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

// Re-export all components
pub use serai_primitives as primitives;

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
  ApplyExtrinsicResult, Perbill,
};

use primitives::{PublicKey, SeraiAddress, AccountLookup, Signature, SubstrateAmount};

use support::{
  traits::{ConstU8, ConstU32, ConstU64, Contains},
  weights::{
    constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
    IdentityFee, Weight,
  },
  parameter_types, construct_runtime,
};

use babe::AuthorityId as BabeId;
use grandpa::AuthorityId as GrandpaId;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;

/// An index to a block.
pub type BlockNumber = u64;

/// Nonce of a transaction in the chain, for a given account.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

pub mod opaque {
  use super::*;

  use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

  pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
  pub type Block = generic::Block<Header, UncheckedExtrinsic>;
  pub type BlockId = generic::BlockId<Block>;

  impl_opaque_keys! {
    pub struct SessionKeys {
      pub babe: Babe,
      pub grandpa: Grandpa,
    }
  }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
  spec_name: create_runtime_str!("serai"),
  impl_name: create_runtime_str!("core"),
  spec_version: 1,
  impl_version: 1,
  apis: RUNTIME_API_VERSIONS,
  transaction_version: 1,
  state_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
  NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

// 1 MB
pub const BLOCK_SIZE: u32 = 1024 * 1024;
// 6 seconds
pub const TARGET_BLOCK_TIME: u64 = 6;

/// Measured in blocks.
pub const MINUTES: BlockNumber = 60 / TARGET_BLOCK_TIME;
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);

pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
  sp_consensus_babe::BabeEpochConfiguration {
    c: PRIMARY_PROBABILITY,
    allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
  };

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
  pub const BlockHashCount: BlockNumber = 2400;
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

  pub const MaxAuthorities: u32 = validator_sets::primitives::MAX_KEY_SHARES_PER_SET;
}

pub struct CallFilter;
impl Contains<RuntimeCall> for CallFilter {
  fn contains(call: &RuntimeCall) -> bool {
    match call {
      RuntimeCall::Timestamp(call) => match call {
        timestamp::Call::set { .. } => true,
        timestamp::Call::__Ignore(_, _) => false,
      },

      // All of these pallets are our own, and all of their written calls are intended to be called
      RuntimeCall::Coins(call) => !matches!(call, coins::Call::__Ignore(_, _)),
      RuntimeCall::LiquidityTokens(call) => match call {
        coins::Call::transfer { .. } => true,
        coins::Call::burn { .. } => true,
        coins::Call::burn_with_instruction { .. } => false,
        coins::Call::__Ignore(_, _) => false,
      },
      RuntimeCall::Dex(call) => !matches!(call, dex::Call::__Ignore(_, _)),
      RuntimeCall::ValidatorSets(call) => !matches!(call, validator_sets::Call::__Ignore(_, _)),
      RuntimeCall::InInstructions(call) => !matches!(call, in_instructions::Call::__Ignore(_, _)),
      RuntimeCall::Signals(call) => !matches!(call, signals::Call::__Ignore(_, _)),

      RuntimeCall::Babe(call) => match call {
        babe::Call::report_equivocation { .. } => true,
        babe::Call::report_equivocation_unsigned { .. } => true,
        babe::Call::plan_config_change { .. } => false,
        babe::Call::__Ignore(_, _) => false,
      },

      RuntimeCall::Grandpa(call) => match call {
        grandpa::Call::report_equivocation { .. } => true,
        grandpa::Call::report_equivocation_unsigned { .. } => true,
        grandpa::Call::note_stalled { .. } => false,
        grandpa::Call::__Ignore(_, _) => false,
      },
    }
  }
}

impl system::Config for Runtime {
  type BaseCallFilter = CallFilter;
  type BlockWeights = BlockWeights;
  type BlockLength = BlockLength;
  type AccountId = PublicKey;
  type RuntimeCall = RuntimeCall;
  type Lookup = AccountLookup;
  type Hash = Hash;
  type Hashing = BlakeTwo256;
  type Nonce = Nonce;
  type Block = Block;
  type RuntimeOrigin = RuntimeOrigin;
  type RuntimeEvent = RuntimeEvent;
  type BlockHashCount = BlockHashCount;
  type DbWeight = RocksDbWeight;
  type Version = Version;
  type PalletInfo = PalletInfo;

  type OnNewAccount = ();
  type OnKilledAccount = ();
  type OnSetCode = ();

  type AccountData = ();
  type SystemWeightInfo = ();
  type SS58Prefix = SS58Prefix; // TODO: Remove for Bech32m

  type MaxConsumers = support::traits::ConstU32<16>;
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
  type AllowMint = ValidatorSets;
}

impl dex::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type LPFee = ConstU32<3>; // 0.3%
  type MintMinLiquidity = ConstU64<10000>;

  type MaxSwapPathLength = ConstU32<3>; // coin1 -> SRI -> coin2

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
  type ValidityDuration = ConstU32<{ (7 * 24 * 60 * 60) / (TARGET_BLOCK_TIME as u32) }>;
  // 2 weeks
  type LockInDuration = ConstU32<{ (2 * 7 * 24 * 60 * 60) / (TARGET_BLOCK_TIME as u32) }>;
}

impl in_instructions::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

impl babe::Config for Runtime {
  #[allow(clippy::identity_op)]
  type EpochDuration = ConstU64<{ 1 * DAYS }>;
  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME * 1000 }>;
  type EpochChangeTrigger = pallet_babe::ExternalTrigger;
  type DisabledValidators = ValidatorSets;

  type WeightInfo = ();

  type MaxAuthorities = MaxAuthorities;

  // TODO: Handle equivocation reports
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

impl grandpa::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;

  // TODO: Handle equivocation reports
  type MaxSetIdSessionEntries = ConstU64<0>;
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedExtra = (
  system::CheckNonZeroSender<Runtime>,
  system::CheckSpecVersion<Runtime>,
  system::CheckTxVersion<Runtime>,
  system::CheckGenesis<Runtime>,
  system::CheckEra<Runtime>,
  system::CheckNonce<Runtime>,
  system::CheckWeight<Runtime>,
  transaction_payment::ChargeTransactionPayment<Runtime>,
);
pub type UncheckedExtrinsic =
  generic::UncheckedExtrinsic<SeraiAddress, RuntimeCall, Signature, SignedExtra>;
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
pub type Executive = frame_executive::Executive<
  Runtime,
  Block,
  system::ChainContext<Runtime>,
  Runtime,
  AllPalletsWithSystem,
>;

construct_runtime!(
  pub enum Runtime {
    System: system exclude_parts { Call },

    Timestamp: timestamp,

    TransactionPayment: transaction_payment,

    Dex: dex,
    Coins: coins,
    LiquidityTokens: coins::<Instance1>::{Pallet, Call, Storage, Event<T>},

    ValidatorSets: validator_sets,

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

    fn initialize_block(header: &<Block as BlockT>::Header) {
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

    fn finalize_block() -> <Block as BlockT>::Header {
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
    fn offchain_worker(header: &<Block as BlockT>::Header) {
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

    fn generate_key_ownership_proof(
      _: sp_consensus_babe::Slot,
      _: BabeId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      None
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      _: sp_consensus_babe::EquivocationProof<<Block as BlockT>::Header>,
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

    fn submit_report_equivocation_unsigned_extrinsic(
      _: sp_consensus_grandpa::EquivocationProof<<Block as BlockT>::Hash, u64>,
      _: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      None
    }

    fn generate_key_ownership_proof(
      _set_id: sp_consensus_grandpa::SetId,
      _authority_id: GrandpaId,
    ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
      None
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
      Babe::authorities()
        .into_iter()
        .map(|(id, _)| AuthorityDiscoveryId::from(id.into_inner()))
        .collect()
    }
  }
}
