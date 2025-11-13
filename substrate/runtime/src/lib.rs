#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use serai_abi::primitives::{
  crypto::{Public, SignedEmbeddedEllipticCurveKeys},
  network_id::NetworkId,
  balance::Balance,
};

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

#[cfg(target_family = "wasm")]
mod wasm;

/// The genesis configuration for Serai.
#[derive(scale::Encode, scale::Decode)]
pub struct GenesisConfig {
  /// The genesis validators for the network.
  pub validators: Vec<(Public, Vec<SignedEmbeddedEllipticCurveKeys>)>,
  /// The accounts to start with balances, intended solely for testing purposes.
  pub coins: Vec<(Public, Balance)>,
}

sp_api::decl_runtime_apis! {
  pub trait GenesisApi {
    fn build(genesis: GenesisConfig);
  }
  pub trait SeraiApi {
    fn validators(network_id: NetworkId) -> Vec<Public>;
  }
}

// We stub `impl_runtime_apis` to generate the `RuntimeApi` object the node needs
#[cfg(not(target_family = "wasm"))]
mod apis {
  use alloc::borrow::Cow;
  use serai_abi::{SubstrateHeader as Header, SubstrateBlock as Block};

  #[sp_version::runtime_version]
  pub const VERSION: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
    spec_name: Cow::Borrowed("serai"),
    impl_name: Cow::Borrowed("core"),
    authoring_version: 0,
    // Use the highest possible value so the node doesn't attempt to use this in place of the WASM
    spec_version: 0xffffffff,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 0,
    system_version: 0,
  };

  /// A `struct` representing the runtime as necessary to define the available APIs.
  pub struct Runtime;
  sp_api::impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
      fn version() -> sp_version::RuntimeVersion {
        VERSION
      }
      fn initialize_block(header: &Header) -> sp_runtime::ExtrinsicInclusionMode {
        unimplemented!("runtime is only implemented when WASM")
      }
      fn execute_block(block: Block) {
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
        block: Block,
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
      fn validators(
        network: serai_abi::primitives::network_id::NetworkId
      ) -> Vec<serai_abi::primitives::crypto::Public> {
        unimplemented!("runtime is only implemented when WASM")
      }
    }
  }
}
#[cfg(not(target_family = "wasm"))]
pub use apis::RuntimeApi;
