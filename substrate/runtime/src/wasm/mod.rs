#![expect(clippy::as_conversions, clippy::same_name_method, clippy::used_underscore_binding)]

use core::{marker::PhantomData, convert::AsRef as _};
use alloc::{borrow::Cow, vec, vec::Vec};

use sp_core::{Get, ConstU32, ConstU64};
use sp_runtime::{
  Weight,
  transaction_validity::{InvalidTransaction, TransactionValidityError},
  traits::{Header as _, LazyBlock as _},
};
use sp_version::RuntimeVersion;

use serai_abi::{
  primitives::{
    constants::*,
    crypto::{Public, EmbeddedEllipticCurveKeys},
    network_id::{ExternalNetworkId, NetworkId},
    coin::{Coin, ExternalCoin},
    balance::{Amount, Balance},
    dex::Reserves,
    validator_sets::{Session, ExternalValidatorSet, ValidatorSet},
    address::SeraiAddress,
  },
  TransactionContext as _, SubstrateHeader as Header, SubstrateBlock as Block,
  LazySubstrateBlock as LazyBlock,
};

use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance, GenesisLiquidityTokensInstance};

/// Maps `serai_abi` types into the types expected within the Substrate runtime
mod map;
/// The configuration for `frame_system`.
mod system;
/// Definitions, functions for the usage of BABE and GRANDPA.
mod babe_grandpa;
use babe_grandpa::*;

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
  pub type GenesisLiquidityTokens =
    serai_coins_pallet::Pallet<Runtime, GenesisLiquidityTokensInstance>;

  #[runtime::pallet_index(0x48)]
  pub type GenesisLiquidity = serai_genesis_liquidity_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x49)]
  pub type EconomicSecurity = serai_economic_security_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0x50)]
  pub type InInstructions = serai_in_instructions_pallet::Pallet<Runtime>;

  #[runtime::pallet_index(0xc0)]
  pub type Emissions = serai_emissions_pallet::Pallet<Runtime>;
}

impl serai_core_pallet::Config for Runtime {
  const PROTOCOL_ID: [u8; 32] = match core::option_env!("SERAI_PROTOCOL_ID") {
    Some(hex) => match const_hex::const_decode_to_array(hex.as_bytes()) {
      Ok(result) => result,
      Err(_) => panic!("`SERAI_PROTOCOL_ID` wasn't specified as a 32-byte hex string"),
    },
    None => [0; 32],
  };
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero(); // TODO
  type PreInherents = (Emissions, ValidatorSets, InInstructions);
}

impl serai_coins_pallet::Config<CoinsInstance> for Runtime {
  type AllowMint = serai_economic_security_pallet::CoinsInstanceAllowMint<Self>;
  type AllowBurnWithInstruction = serai_signals_pallet::Pallet<Self>;
  type Weights = (); // TODO
}
impl serai_validator_sets_pallet::Config for Runtime {
  type ShouldEndSession = Babe;
  type EconomicSecurity = EconomicSecurity;
  type Emissions = Emissions;
  type Weights = (); // TODO
}
impl serai_signals_pallet::Config for Runtime {
  type RetirementLockInDurationInSlots = ConstU64<{ RETIREMENT_LOCK_IN_DURATION_IN_SLOTS }>;
  type ValidatorSets = ValidatorSets;
  type Weights = (); // TODO
}

#[doc(hidden)]
pub struct NeverAllowBurnWithInstruction;
impl serai_abi::signals::Halted for NeverAllowBurnWithInstruction {
  fn halted(_network: ExternalNetworkId) -> bool {
    true
  }
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Runtime {
  type AllowMint = serai_economic_security_pallet::LiquidityTokensInstanceAllowMint<Self>;
  type AllowBurnWithInstruction = NeverAllowBurnWithInstruction;
  // This does not have weights actually set as its call isn't exposed
  type Weights = ();
}
impl serai_dex_pallet::Config for Runtime {
  type AllowSwap = Signals;
  type Weights = (); // TODO
}
impl serai_coins_pallet::Config<GenesisLiquidityTokensInstance> for Runtime {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type AllowBurnWithInstruction = NeverAllowBurnWithInstruction;
  // This does not have weights actually set as its call isn't exposed
  type Weights = ();
}
impl serai_genesis_liquidity_pallet::Config for Runtime {
  type EconomicSecurity = EconomicSecurity;
  type ValidatorSets = ValidatorSets;
  type Weights = (); // TODO
}
impl serai_economic_security_pallet::Config for Runtime {
  type ValidatorSets = ValidatorSets;
}
impl serai_emissions_pallet::Config for Runtime {
  type ValidatorSets = ValidatorSets;
  type EconomicSecurity = EconomicSecurity;
}
impl serai_in_instructions_pallet::Config for Runtime {
  type Weights = (); // TODO
}

impl pallet_timestamp::Config for Runtime {
  type Moment = u64;
  type OnTimestampSet = Babe;
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  type MinimumPeriod = ConstU64<{ (TARGET_BLOCK_TIME.as_millis() / 2) as u64 }>;
  // This call is never propagated, hence why we are able to use null weights for it
  type WeightInfo = ();
}

type ExecutiveContext = PhantomData<(Core, FeeContext)>;
type Executive =
  frame_executive::Executive<Runtime, Block, ExecutiveContext, Runtime, AllPalletsWithSystem>;

sp_api::impl_runtime_apis! {
  impl crate::GenesisApi<Block> for Runtime {
    fn build(genesis: crate::GenesisConfig) {
      let validator_sets = ValidatorSetsConfig {
        participants: genesis.validators,
      };
      let config = RuntimeGenesisConfig {
        system: SystemConfig { _config: PhantomData },

        // We leave these `authorities` empty as `serai-validator-sets-pallet` initializes them
        babe: BabeConfig {
          authorities: vec![],
          epoch_config: BABE_GENESIS_EPOCH_CONFIG,
          _config: PhantomData,
        },
        grandpa: GrandpaConfig { authorities: vec![], _config: PhantomData },

        coins: CoinsConfig {
          accounts: genesis.coins,
          _instance: PhantomData,
        },

        liquidity_tokens: LiquidityTokensConfig { accounts: vec![], _instance: PhantomData },

        dex: DexConfig {
          fees: genesis.fees,
          _config: PhantomData,
        },

        genesis_liquidity_tokens: GenesisLiquidityTokensConfig {
          accounts: vec![],
          _instance: PhantomData,
        },

        validator_sets: validator_sets.clone(),

        genesis_liquidity: validator_sets.try_into().unwrap(),

        signals: SignalsConfig::default(),
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
      /*
        If this contains a slash for a Serai validator, check its integrity.

        This is awkward. `serai-validator-sets-pallet` never sees this `reason` and is accordingly
        unable to validate it. This is intentional as the reason is explicitly intended to be not
        part of the codified protocol. The only requirement for acceptance on-chain is intended to
        be that it's included in a block a supermajority of validators agreed on (and finalized).

        At the same time however, for matters of feasibility, as of now, it _is_ codified within
        the Serai protocol here, in this very spot. We treat it as an inherent transaction, being
        checked when the block's execution begins, but also as an unsigned transaction, propagating
        it across mempools and checking it when it enters the mempool.

        Ideally, in the future, this is moved entirely into the node. For now, as it is present in
        the runtime, it likely would have been better to make use of the `ValidateUnsigned` within
        `serai-validator-sets-pallet`.
      */
      if let Some((validator, reason)) = (|| {
        let serai_abi::Transaction::Unsigned { call } = &extrinsic else { None? };
        let call: &serai_abi::Call = call.as_ref();
        let serai_abi::Call::ValidatorSets(call) = call else { None? };
        let serai_abi::validator_sets::Call::report_slashes(slashes) = call else { None? };
        let serai_abi::validator_sets::Slashes::Serai {
          validator,
          reason,
        } = slashes else {
          None?
        };
        Some((*validator, reason))
      })() {
        if !verify_serai_slash_reason(validator, reason.as_ref()) {
          Err(TransactionValidityError::Invalid(InvalidTransaction::BadProof))?;
        }
      }

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
              // This ignores `proposer` as it's handled within `serai-validator-sets-pallet`
              let Ok(SeraiPreExecutionDigest { proposer: _, unix_time_in_millis }) =
                <_ as borsh::BorshDeserialize>::deserialize_reader(&mut encoded.as_slice()) else {
                // We don't handle this error as we can't in this position
                let _ = result.put_error(
                  INHERENT_ID,
                  &sp_inherents::MakeFatalError::from("invalid `SeraiPreExecutionDigest`"),
                );
                return result;
              };

              use frame_support::inherent::ProvideInherent as _;
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
      use frame_support::traits::Get as _;

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

    fn generate_key_ownership_proof(
      _slot: sp_consensus_babe::Slot,
      _authority_id: sp_consensus_babe::AuthorityId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      Some(sp_consensus_babe::OpaqueKeyOwnershipProof::new(vec![]))
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_babe::EquivocationProof<Header>,
      _: sp_consensus_babe::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      submit_babe_equivocation(equivocation_proof)
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
      _authority_id: sp_consensus_grandpa::AuthorityId,
    ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
      Some(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new(vec![]))
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: GrandpaEquivocationProof,
      _: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      submit_grandpa_equivocation(equivocation_proof)
    }
  }

  impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
    fn authorities() -> Vec<sp_authority_discovery::AuthorityId> {
      /*
        This represents validator keys by their underlying bytes to satisfy `Hash` and allow us to
        to use a `BTreeSet` to deduplicate the list of validators.
      */
      NetworkId::all()
        .flat_map(
          <Self as super::runtime_decl_for_serai_api::SeraiApi<Block>>::validators_for_peering
        )
        .map(|validator| <[u8; 32]>::from(validator.into_inner()))
        .collect::<alloc::collections::BTreeSet<_>>()
        .into_iter()
        .map(|validator| {
          sp_authority_discovery::AuthorityId::from(sp_core::sr25519::Public::from(validator))
        })
        .collect()
    }
  }

  impl crate::SeraiApi<Block> for Runtime {
    fn events() -> Vec<Vec<Vec<u8>>> {
      Core::events()
    }
    fn validators_for_peering(network: NetworkId) -> Vec<sp_authority_discovery::AuthorityId> {
      [
        ValidatorSets::current_session(network),
        ValidatorSets::latest_decided_session(network)
      ]
        .into_iter()
        .filter_map(|session| {
          session.map(|session| {
            ValidatorSets::selected_validators(ValidatorSet { network, session })
              .map(|(validator, _key_shares)| validator)
          })
        })
        .flatten()
        .map(|validator: SeraiAddress| validator.0)
        .collect::<alloc::collections::BTreeSet<_>>()
        .into_iter()
        .map(|validator| {
          match ValidatorSets::auxiliary_keys(SeraiAddress(validator), NetworkId::Serai) {
            Some(EmbeddedEllipticCurveKeys::Serai(key)) => {
              sp_authority_discovery::AuthorityId::from(serai_validator_sets_pallet::subkey(
                &Public(key).into(),
                sp_core::crypto::key_types::AUTHORITY_DISCOVERY,
              ))
            },
            Some(_) => panic!("`auxiliary_keys()` returned auxiliary keys for another network"),
            None => panic!("selected validator lacking Serai auxiliary key"),
          }
        })
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
          .map(|(key, _key_shares)| key)
          .collect()
      )
    }
    fn pending_slash_report(set: ExternalValidatorSet) -> bool {
      ValidatorSets::pending_slash_report(set)
    }
    fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: NetworkId,
    ) -> Option<EmbeddedEllipticCurveKeys> {
      ValidatorSets::auxiliary_keys(validator, network)
    }

    fn balance(of: SeraiAddress, coin: Coin) -> Amount {
      Coins::balance(of, coin)
    }
    fn liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount {
      LiquidityTokens::balance(of, coin)
    }
    fn genesis_liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount {
      GenesisLiquidityTokens::balance(of, coin)
    }

    fn supply(coin: Coin) -> Amount {
      Coins::supply(coin)
    }
    fn liquidity_supply(coin: ExternalCoin) -> Amount {
      LiquidityTokens::supply(coin)
    }
    fn genesis_liquidity_supply(coin: ExternalCoin) -> Amount {
      GenesisLiquidityTokens::supply(coin)
    }

    fn genesis_completed() -> bool {
      GenesisLiquidity::completed()
    }

    fn pool_reserves(coin: ExternalCoin) -> Reserves {
      let pool = serai_abi::dex::address(coin);
      Reserves {
        sri: Coins::balance(pool, Coin::Serai),
        external_coin: Coins::balance(pool, coin),
      }
    }

    fn account_nonce(of: SeraiAddress) -> u32 {
      Core::next_nonce(&of)
    }
  }
}

struct FeeContext;
impl serai_abi::TransactionFeeContext for FeeContext {
  fn can_pay_fee(signer: &SeraiAddress, fee: Balance) -> Result<(), TransactionValidityError> {
    if fee.coin != Coin::Serai {
      Err(TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
    }

    if serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::balance(signer, fee.coin) < fee.amount
    {
      Err(TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
    }
    Ok(())
  }

  fn pay_fee(signer: &SeraiAddress, fee: Balance) -> Result<(), TransactionValidityError> {
    if fee.coin != Coin::Serai {
      Err(TransactionValidityError::Invalid(InvalidTransaction::Payment))?;
    }

    // `clippy::disallowed_methods` as this can be called for non-`CoinsInstance`,
    // but this is `CoinsInstance` so it's fine
    #[expect(clippy::disallowed_methods)]
    serai_coins_pallet::Pallet::<Runtime, CoinsInstance>::burn(RuntimeOrigin::signed(*signer), fee)
      .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))
  }
}
