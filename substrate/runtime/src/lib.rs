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

pub use pallet_balances as balances;
pub use pallet_transaction_payment as transaction_payment;

pub use pallet_assets as assets;
pub use tokens_pallet as tokens;
pub use in_instructions_pallet as in_instructions;

pub use pallet_asset_conversion as dex;

pub use validator_sets_pallet as validator_sets;

pub use pallet_session as session;
pub use pallet_babe as babe;
pub use pallet_grandpa as grandpa;

pub use pallet_authority_discovery as authority_discovery;

// Actually used by the runtime
use sp_core::OpaqueMetadata;
use sp_std::prelude::*;

use sp_version::RuntimeVersion;
#[cfg(feature = "std")]
use sp_version::NativeVersion;

use sp_runtime::{
  create_runtime_str, generic, impl_opaque_keys, KeyTypeId,
  traits::{Convert, OpaqueKeys, BlakeTwo256, Block as BlockT},
  transaction_validity::{TransactionSource, TransactionValidity},
  ApplyExtrinsicResult, Perbill, Permill,
};

use primitives::{
  PublicKey, SeraiAddress, AccountLookup, Signature, SubstrateAmount, Coin, pallet_address,
};

use support::{
  traits::{ConstU8, ConstU32, ConstU64, ConstBool, Contains, AsEnsureOriginWithArg},
  weights::{
    constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
    IdentityFee, Weight,
  },
  PalletId, parameter_types, construct_runtime, ord_parameter_types,
};

use transaction_payment::CurrencyAdapter;

use babe::AuthorityId as BabeId;
use grandpa::AuthorityId as GrandpaId;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;

use dex::MultiAssetIdConverter;

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
      pub authority_discovery: AuthorityDiscovery,
    }
  }
}

use opaque::SessionKeys;

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
  spec_name: create_runtime_str!("serai"),
  impl_name: create_runtime_str!("core"),
  // TODO: 1? Do we prefer some level of compatibility or our own path?
  spec_version: 100,
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

  pub const MaxAuthorities: u32 = 100;
  // PalletId has to be exactly 8 byte. Hence It is "DexPalet" instead of
  // "DexPallet".
  pub const AssetConversionPalletId: PalletId = PalletId(*b"DexPalet");
  pub const LiquidityWithdrawalFee: Permill = Permill::from_percent(0);
}

ord_parameter_types! {
  // TODO: normally we should do AssetConversionPalletId::get() instead of b"DexPalet"
  // but that gives a lifetime error for now.
  pub const AssetConversionOrigin: PublicKey = PublicKey::from(pallet_address(b"DexPalet"));
}

pub struct CallFilter;
impl Contains<RuntimeCall> for CallFilter {
  fn contains(call: &RuntimeCall) -> bool {
    if let RuntimeCall::Timestamp(call) = call {
      return matches!(call, timestamp::Call::set { .. });
    }

    if let RuntimeCall::Balances(call) = call {
      return matches!(call, balances::Call::transfer { .. } | balances::Call::transfer_all { .. });
    }

    if let RuntimeCall::Assets(call) = call {
      return matches!(
        call,
        assets::Call::approve_transfer { .. } |
          assets::Call::cancel_approval { .. } |
          assets::Call::transfer { .. } |
          assets::Call::transfer_approved { .. }
      );
    }
    if let RuntimeCall::Tokens(call) = call {
      return matches!(call, tokens::Call::burn { .. });
    }
    if let RuntimeCall::InInstructions(call) = call {
      return matches!(call, in_instructions::Call::execute_batch { .. });
    }

    if let RuntimeCall::ValidatorSets(call) = call {
      return matches!(call, validator_sets::Call::set_keys { .. });
    }

    if let RuntimeCall::Dex(call) = call {
      return matches!(
        call,
        dex::Call::create_pool { .. } |
          dex::Call::add_liquidity { .. } |
          dex::Call::swap_exact_tokens_for_tokens { .. } |
          dex::Call::swap_tokens_for_exact_tokens { .. } |
          dex::Call::remove_liquidity { .. }
      );
    }

    false
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

  type AccountData = balances::AccountData<SubstrateAmount>;
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

impl balances::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type Balance = SubstrateAmount;

  type ReserveIdentifier = ();
  type FreezeIdentifier = ();
  type RuntimeHoldReason = ();

  type MaxLocks = ();
  type MaxReserves = ();
  type MaxHolds = ();
  type MaxFreezes = ();

  type DustRemoval = ();
  type ExistentialDeposit = ConstU64<1>;
  // TODO: What's the benefit to this?
  type AccountStore = System;
  type WeightInfo = balances::weights::SubstrateWeight<Runtime>;
}

impl transaction_payment::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type OnChargeTransaction = CurrencyAdapter<Balances, ()>;
  type OperationalFeeMultiplier = ConstU8<5>;
  type WeightToFee = IdentityFee<SubstrateAmount>;
  type LengthToFee = IdentityFee<SubstrateAmount>;
  type FeeMultiplierUpdate = ();
}

#[cfg(feature = "runtime-benchmarks")]
pub struct SeraiAssetBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl assets::BenchmarkHelper<Coin> for SeraiAssetBenchmarkHelper {
  fn create_asset_id_parameter(id: u32) -> Coin {
    match (id % 4) + 1 {
      1 => Coin::Bitcoin,
      2 => Coin::Ether,
      3 => Coin::Dai,
      4 => Coin::Monero,
      _ => panic!("(id % 4) + 1 wasn't in [1, 4]"),
    }
  }
}

impl assets::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type Balance = SubstrateAmount;
  type Currency = Balances;

  type AssetId = Coin;
  type AssetIdParameter = Coin;
  type StringLimit = ConstU32<32>;

  // Don't allow anyone to create assets
  type CreateOrigin = AsEnsureOriginWithArg<system::EnsureNever<PublicKey>>;
  type ForceOrigin = system::EnsureRoot<PublicKey>;

  // Don't charge fees nor kill accounts
  type RemoveItemsLimit = ConstU32<0>;
  type AssetDeposit = ConstU64<0>;
  type AssetAccountDeposit = ConstU64<0>;
  type MetadataDepositBase = ConstU64<0>;
  type MetadataDepositPerByte = ConstU64<0>;
  type ApprovalDeposit = ConstU64<0>;

  // Unused hooks
  type CallbackHandle = ();
  type Freezer = ();
  type Extra = ();

  type WeightInfo = assets::weights::SubstrateWeight<Runtime>;
  #[cfg(feature = "runtime-benchmarks")]
  type BenchmarkHelper = SeraiAssetBenchmarkHelper;
}

impl assets::Config<assets::Instance1> for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type Balance = SubstrateAmount;
  type RemoveItemsLimit = ConstU32<0>;
  type AssetId = u32;
  type AssetIdParameter = u32;
  type Currency = Balances;

  type CreateOrigin =
    AsEnsureOriginWithArg<system::EnsureSignedBy<AssetConversionOrigin, PublicKey>>;
  type ForceOrigin = system::EnsureRoot<PublicKey>;

  // Deposits are zero because creation/admin is limited to Asset Conversion pallet.
  type AssetDeposit = ConstU64<0>;
  type AssetAccountDeposit = ConstU64<0>;
  type MetadataDepositBase = ConstU64<0>;
  type MetadataDepositPerByte = ConstU64<0>;
  type ApprovalDeposit = ConstU64<1>; // TODO: is this supposed to be 0 too?
  type StringLimit = ConstU32<32>;

  type Freezer = ();
  type Extra = ();
  type CallbackHandle = ();

  type WeightInfo = assets::weights::SubstrateWeight<Runtime>; // same as the normal assets?
  #[cfg(feature = "runtime-benchmarks")]
  type BenchmarkHelper = SeraiAssetBenchmarkHelper;
}

impl tokens::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

impl in_instructions::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

impl validator_sets::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
}

pub struct CoinConverter;
impl MultiAssetIdConverter<Coin, Coin> for CoinConverter {
  /// Returns the MultiAssetId representing the native currency of the chain.
  fn get_native() -> Coin {
    Coin::Serai
  }

  /// Returns true if the given MultiAssetId is the native currency.
  fn is_native(coin: &Coin) -> bool {
    *coin == Coin::Serai
  }

  /// If it's not native, returns the AssetId for the given MultiAssetId.
  fn try_convert(coin: &Coin) -> Result<Coin, ()> {
    if *coin == Coin::Serai {
      return Err(());
    }
    Ok(*coin)
  }

  /// Wraps an AssetId as a MultiAssetId.
  fn into_multiasset_id(coin: &Coin) -> Coin {
    *coin
  }
}

impl dex::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type Currency = Balances;
  type Balance = SubstrateAmount;
  type AssetBalance = SubstrateAmount;
  // TODO review if this should be u64/u128 or u64/u256 (and rounding in general).
  type HigherPrecisionBalance = u128;

  type AssetId = Coin;
  type MultiAssetId = Coin;
  type MultiAssetIdConverter = CoinConverter;
  type PoolAssetId = u32;

  type Assets = Assets;
  type PoolAssets = LiquidityTokens;

  type LPFee = ConstU32<3>; // 0.3%
  type PoolSetupFee = ConstU64<0>; // Asset class deposit fees are sufficient to prevent spam
  type LiquidityWithdrawalFee = LiquidityWithdrawalFee;
  type MintMinLiquidity = ConstU64<10000>;

  type MaxSwapPathLength = ConstU32<3>; // asset1 -> SRI -> asset2

  type PalletId = AssetConversionPalletId;
  type PoolSetupFeeReceiver = AssetConversionOrigin;
  type AllowMultiAssetPools = ConstBool<false>;

  type WeightInfo = dex::weights::SubstrateWeight<Runtime>;
  #[cfg(feature = "runtime-benchmarks")]
  type BenchmarkHelper = SeraiAssetBenchmarkHelper;
}

pub struct IdentityValidatorIdOf;
impl Convert<PublicKey, Option<PublicKey>> for IdentityValidatorIdOf {
  fn convert(key: PublicKey) -> Option<PublicKey> {
    Some(key)
  }
}

impl session::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;
  type ValidatorId = PublicKey;
  type ValidatorIdOf = IdentityValidatorIdOf;
  type ShouldEndSession = Babe;
  type NextSessionRotation = Babe;
  type SessionManager = (); // TODO?
  type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
  type Keys = SessionKeys;
  type WeightInfo = session::weights::SubstrateWeight<Runtime>;
}

impl babe::Config for Runtime {
  #[allow(clippy::identity_op)]
  type EpochDuration = ConstU64<{ 1 * DAYS }>;
  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME * 1000 }>;
  type EpochChangeTrigger = pallet_babe::ExternalTrigger;
  type DisabledValidators = Session;

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

impl authority_discovery::Config for Runtime {
  type MaxAuthorities = MaxAuthorities;
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
    System: system,

    Timestamp: timestamp,

    Balances: balances,
    TransactionPayment: transaction_payment,

    Assets: assets,
    LiquidityTokens: assets::<Instance1>::{Pallet, Call, Storage, Event<T>},
    Tokens: tokens,
    InInstructions: in_instructions,

    Dex: dex,

    ValidatorSets: validator_sets,

    Session: session,
    Babe: babe,
    Grandpa: grandpa,

    AuthorityDiscovery: authority_discovery,
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
      AuthorityDiscovery::authorities()
    }
  }

}
