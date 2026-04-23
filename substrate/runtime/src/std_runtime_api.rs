#![expect(missing_docs, unused_variables, clippy::used_underscore_binding)]

use alloc::borrow::Cow;

use serai_abi::{
  primitives::{
    crypto::{KeyPair, EmbeddedEllipticCurveKeys},
    network_id::NetworkId,
    validator_sets::{Session, ExternalValidatorSet},
    coin::{Coin, ExternalCoin},
    balance::Amount,
    address::SeraiAddress,
  },
  SubstrateHeader as Header, SubstrateBlock as Block, LazySubstrateBlock as LazyBlock,
};

use super::*;

/// A `struct` representing the runtime as necessary to define the available APIs.
// This `struct` itself is never instantiated, solely the `RuntimeApi` derived around it.
struct Runtime;

sp_api::impl_runtime_apis! {
  impl sp_api::Core<Block> for Runtime {
    fn version() -> sp_version::RuntimeVersion {
      sp_version::RuntimeVersion {
        spec_name: Cow::Borrowed("serai"),
        impl_name: Cow::Borrowed("core"),
        authoring_version: 0,
        // Use the highest possible value so the node doesn't attempt to use this over the WASM
        spec_version: 0xff_ff_ff_ffu32,
        impl_version: 0,
        apis: RUNTIME_API_VERSIONS,
        transaction_version: 0,
        system_version: 0,
      }
    }
    fn initialize_block(header: &Header) -> sp_runtime::ExtrinsicInclusionMode {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn execute_block(block: LazyBlock) {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl sp_block_builder::BlockBuilder<Block> for Runtime {
    fn apply_extrinsic(
      extrinsic: <Block as sp_runtime::traits::Block>::Extrinsic,
    ) -> sp_runtime::ApplyExtrinsicResult {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn finalize_block() -> Header {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn inherent_extrinsics(
      data: sp_inherents::InherentData,
    ) -> Vec<<Block as sp_runtime::traits::Block>::Extrinsic> {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn check_inherents(
      block: LazyBlock,
      data: sp_inherents::InherentData,
    ) -> sp_inherents::CheckInherentsResult {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
    fn validate_transaction(
      source: sp_runtime::transaction_validity::TransactionSource,
      tx: <Block as sp_runtime::traits::Block>::Extrinsic,
      block_hash: <Block as sp_runtime::traits::Block>::Hash,
    ) -> sp_runtime::transaction_validity::TransactionValidity {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl sp_consensus_babe::BabeApi<Block> for Runtime {
    fn configuration() -> sp_consensus_babe::BabeConfiguration {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn current_epoch_start() -> sp_consensus_babe::Slot {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn current_epoch() -> sp_consensus_babe::Epoch {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn next_epoch() -> sp_consensus_babe::Epoch {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn generate_key_ownership_proof(
      _slot: sp_consensus_babe::Slot,
      _authority_id: sp_consensus_babe::AuthorityId,
    ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_babe::EquivocationProof<Header>,
      _: sp_consensus_babe::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
    fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn current_set_id() -> sp_consensus_grandpa::SetId {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn generate_key_ownership_proof(
      _set_id: sp_consensus_grandpa::SetId,
      _authority_id: sp_consensus_grandpa::AuthorityId,
    ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn submit_report_equivocation_unsigned_extrinsic(
      equivocation_proof: sp_consensus_grandpa::EquivocationProof<
        <Block as sp_runtime::traits::Block>::Hash,
        u64,
      >,
      _: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
    ) -> Option<()> {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl sp_authority_discovery::AuthorityDiscoveryApi<Block> for Runtime {
    fn authorities() -> Vec<sp_authority_discovery::AuthorityId> {
      unimplemented!("runtime is only implemented when WASM")
    }
  }

  impl crate::SeraiApi<Block> for Runtime {
    fn events() -> Vec<Vec<Vec<u8>>> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn validators_for_peering(
      network: NetworkId
    ) -> Vec<sp_authority_discovery::AuthorityId> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn current_session(network: NetworkId) -> Option<Session> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn current_stake(network: NetworkId) -> Option<Amount> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn keys(set: ExternalValidatorSet) -> Option<KeyPair> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn current_validators(network: NetworkId) -> Option<Vec<SeraiAddress>> {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn pending_slash_report(set: ExternalValidatorSet) -> bool {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn embedded_elliptic_curve_keys(
      validator: SeraiAddress,
      network: NetworkId,
    ) -> Option<EmbeddedEllipticCurveKeys> {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn balance(of: SeraiAddress, coin: Coin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn genesis_liquidity_balance(of: SeraiAddress, coin: ExternalCoin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn supply(coin: Coin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn liquidity_supply(coin: ExternalCoin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }
    fn genesis_liquidity_supply(coin: ExternalCoin) -> Amount {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn genesis_completed() -> bool {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn account_nonce(of: SeraiAddress) -> u32 {
      unimplemented!("runtime is only implemented when WASM")
    }

    fn economic_security_time() -> u64 {
      unimplemented!("runtime is only implemented when WASM")
    }
  }
}
