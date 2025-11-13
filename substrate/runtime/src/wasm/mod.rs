use core::marker::PhantomData;
use alloc::{borrow::Cow, vec, vec::Vec};

use sp_core::{ConstU32, ConstU64, sr25519::Public};
use sp_runtime::{Perbill, Weight};
use sp_version::RuntimeVersion;

use serai_abi::{
  primitives::{
    network_id::{ExternalNetworkId, NetworkId},
    balance::{Amount, ExternalBalance},
    validator_sets::ValidatorSet,
    address::SeraiAddress,
  },
  SubstrateHeader as Header, SubstrateBlock,
};

use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance};

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
    frame_system::limits::BlockLength::max_with_normal_ratio(
      100 * 1024,
      Perbill::from_percent(75),
    );
  // TODO
  pub BlockWeights: frame_system::limits::BlockWeights =
    frame_system::limits::BlockWeights::with_sensible_defaults(
      Weight::from_parts(
        2u64 * frame_support::weights::constants::WEIGHT_REF_TIME_PER_SECOND,
        u64::MAX,
      ),
      Perbill::from_percent(75),
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
  pub type Core = serai_core_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(2)]
  pub type Coins = serai_coins_pallet::Pallet<Runtime, CoinsInstance>;

  #[runtime::pallet_index(3)]
  pub type ValidatorSets = serai_validator_sets_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(4)]
  pub type Signals = serai_signals_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(5)]
  pub type LiquidityTokens = serai_coins_pallet::Pallet<Runtime, LiquidityTokensInstance>;

  #[runtime::pallet_index(0xfe)]
  pub type Babe = pallet_babe::Pallet<Runtime>;

  #[runtime::pallet_index(0xff)]
  pub type Grandpa = pallet_grandpa::Pallet<Runtime>;
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
  type BlockHashCount = ConstU64<1>;
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
  type MaxConsumers = ConstU32<{ u32::MAX }>;
  // No migrations set
  type SingleBlockMigrations = ();
  type MultiBlockMigrator = ();

  type PreInherents = serai_core_pallet::StartOfBlock<Runtime>;
  type PostInherents = ();
  type PostTransactions = serai_core_pallet::EndOfBlock<Runtime>;
}

impl serai_core_pallet::Config for Runtime {}

impl serai_coins_pallet::Config<CoinsInstance> for Runtime {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint; // TODO
}

#[doc(hidden)]
pub struct EconomicSecurity; // TODO
impl serai_abi::economic_security::EconomicSecurity for EconomicSecurity {
  fn achieved_economic_security(_network: ExternalNetworkId) -> bool {
    false
  }
  fn sri_value(_balance: ExternalBalance) -> Amount {
    Amount(0)
  }
}
impl serai_validator_sets_pallet::Config for Runtime {
  type ShouldEndSession = Babe;
  type EconomicSecurity = EconomicSecurity;
}
impl serai_signals_pallet::Config for Runtime {
  type RetirementValidityDuration = ConstU64<0>; // TODO
  type RetirementLockInDuration = ConstU64<1>; // TODO
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Runtime {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
}

/*
  `pallet-babe` requires we implement `pallet-timestamp` for the associated constants. It does not
  actually require we offer the timestamp pallet however, and we don't as we follow our methodology
  (using the block header for timestamps, not an inherent transaction).

  TODO: Set timestamp when executing a block.
*/
impl pallet_timestamp::Config for Runtime {
  type Moment = u64;
  type OnTimestampSet = Babe;
  // TODO
  type MinimumPeriod = ConstU64<{ (6 * 1000) / 2 }>;
  type WeightInfo = ();
}

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
  // TODO
  type EpochDuration = ConstU64<{ (7 * 24 * 60 * 60 * 1000) / (6 * 1000) }>;

  type ExpectedBlockTime = ConstU64<{ 6 * 1000 }>; // TODO
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
        use serai_coins_pallet::Call as Scall;
        RuntimeCall::Coins(match call {
          Call::transfer { to, coins } => Scall::transfer { to: to.into(), coins },
          Call::burn { coins } => Scall::burn { coins },
          Call::burn_with_instruction { instruction } => {
            Scall::burn_with_instruction { instruction }
          }
        })
      }
      serai_abi::Call::ValidatorSets(call) => {
        use serai_abi::validator_sets::Call;
        use serai_validator_sets_pallet::Call as Scall;
        RuntimeCall::ValidatorSets(match call {
          Call::set_keys { network, key_pair, signature_participants, signature } => {
            Scall::set_keys { network, key_pair, signature_participants, signature }
          }
          Call::report_slashes { network, slashes, signature } => {
            Scall::report_slashes { network, slashes, signature }
          }
          Call::set_embedded_elliptic_curve_keys { keys } => {
            Scall::set_embedded_elliptic_curve_keys { keys }
          }
          Call::allocate { network, amount } => Scall::allocate { network, amount },
          Call::deallocate { network, amount } => Scall::deallocate { network, amount },
          Call::claim_deallocation { deallocation } => Scall::claim_deallocation {
            network: deallocation.network,
            session: deallocation.session,
          },
        })
      }
      serai_abi::Call::Signals(call) => {
        use serai_abi::signals::Call;
        use serai_signals_pallet::Call as Scall;
        RuntimeCall::Signals(match call {
          Call::register_retirement_signal { in_favor_of } => {
            Scall::register_retirement_signal { in_favor_of }
          }
          Call::revoke_retirement_signal { was_in_favor_of } => {
            Scall::revoke_retirement_signal { retirement_signal: was_in_favor_of }
          }
          Call::favor { signal, with_network } => Scall::favor { signal, with_network },
          Call::revoke_favor { signal, with_network } => {
            Scall::revoke_favor { signal, with_network }
          }
          Call::stand_against { signal, with_network } => {
            Scall::stand_against { signal, with_network }
          }
        })
      }
      serai_abi::Call::Dex(call) => {
        use serai_abi::dex::Call;
        match call {
          Call::transfer_liquidity { to, liquidity_tokens } => {
            RuntimeCall::LiquidityTokens(serai_coins_pallet::Call::transfer {
              to: to.into(),
              coins: liquidity_tokens.into(),
            })
          }
          Call::add_liquidity { .. } |
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

      Core::genesis();
      Core::start_transaction();
      <RuntimeGenesisConfig as frame_support::traits::BuildGenesisConfig>::build(&config);
      Core::end_transaction([0; 32]);

      <
        serai_core_pallet::EndOfBlock<Runtime> as frame_support::traits::PostTransactions
      >::post_transactions();
    }
  }

  impl sp_api::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
      VERSION
    }
    fn initialize_block(header: &Header) -> sp_runtime::ExtrinsicInclusionMode {
      Executive::initialize_block(header)
    }
    fn execute_block(block: Block) {
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
      block: Block,
      data: sp_inherents::InherentData,
    ) -> sp_inherents::CheckInherentsResult {
      data.check_extrinsics(&block)
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
      equivocation_proof: sp_consensus_babe::EquivocationProof<Header>,
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
      equivocation_proof: sp_consensus_grandpa::EquivocationProof<
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
          all.insert(sp_core::sr25519::Public::from(participant).into());
        }
      }
      all
        .into_iter()
        .map(|id| sp_authority_discovery::AuthorityId::from(sp_core::sr25519::Public::from(id)))
        .collect()
    }
  }

  impl crate::SeraiApi<Block> for Runtime {
    fn events() -> Vec<Vec<u8>> {
      Core::events()
    }
    fn validators(network: NetworkId) -> Vec<serai_abi::primitives::crypto::Public> {
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
    serai_core_pallet::Pallet::<Runtime>::block_exists(hash)
  }
  /// The time embedded into the current block.
  fn current_time(&self) -> Option<u64> {
    todo!("TODO")
  }
  /// Get the next nonce for an account.
  fn next_nonce(&self, signer: &SeraiAddress) -> u32 {
    serai_core_pallet::Pallet::<Runtime>::next_nonce(signer)
  }
  /// If the signer can pay the SRI fee.
  fn can_pay_fee(
    &self,
    signer: &SeraiAddress,
    fee: serai_abi::primitives::balance::Amount,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    use serai_abi::primitives::coin::Coin;
    if serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::balance(signer, Coin::Serai) >= fee {
      Ok(())
    } else {
      Err(sp_runtime::transaction_validity::TransactionValidityError::Invalid(
        sp_runtime::transaction_validity::InvalidTransaction::Payment,
      ))
    }
  }

  fn start_transaction(&self) {
    Core::start_transaction()
  }
  fn consume_next_nonce(&self, signer: &SeraiAddress) {
    serai_core_pallet::Pallet::<Runtime>::consume_next_nonce(signer)
  }
  /// Have the transaction pay its SRI fee.
  fn pay_fee(
    &self,
    signer: &SeraiAddress,
    fee: serai_abi::primitives::balance::Amount,
  ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
    use serai_abi::primitives::{coin::*, balance::*};
    serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::burn(
      RuntimeOrigin::signed(Public::from(*signer)),
      Balance { coin: Coin::Serai, amount: fee },
    )
    .map_err(|_| {
      sp_runtime::transaction_validity::TransactionValidityError::Invalid(
        sp_runtime::transaction_validity::InvalidTransaction::Payment,
      )
    })
  }
  fn end_transaction(&self, transaction_hash: [u8; 32]) {
    Core::end_transaction(transaction_hash);
  }
}

/* TODO
use validator_sets::MembershipProof;

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

/// Longevity of an offence report.
pub type ReportLongevity = <Runtime as pallet_babe::Config>::EpochDuration;

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
  impl validator_sets::ValidatorSetsApi<Block> for Runtime {
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
