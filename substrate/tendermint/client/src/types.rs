use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Header, Block};

use sp_blockchain::HeaderBackend;
use sp_api::{StateBackend, StateBackendFor, TransactionFor, ApiExt, ProvideRuntimeApi};

use sp_consensus::Environment;
use sc_consensus::BlockImport;

use sc_client_api::{BlockBackend, Backend, Finalizer};
use sc_network::NetworkBlock;
use sc_network_gossip::Network;

use sp_tendermint::TendermintApi;

/// Trait consolidating all generics required by sc_tendermint for processing.
pub trait TendermintClient: Send + Sync + 'static {
  const BLOCK_TIME_IN_SECONDS: u32;

  type Block: Block;
  type Backend: Backend<Self::Block> + 'static;

  /// TransactionFor<Client, Block>
  type BackendTransaction: Send + Sync + 'static;
  /// StateBackendFor<Client, Block>
  type StateBackend: StateBackend<
    <<Self::Block as Block>::Header as Header>::Hashing,
    Transaction = Self::BackendTransaction,
  >;
  // Client::Api
  type Api: ApiExt<Self::Block, StateBackend = Self::StateBackend> + TendermintApi<Self::Block>;
  type Client: Send
    + Sync
    + HeaderBackend<Self::Block>
    + BlockBackend<Self::Block>
    + BlockImport<Self::Block, Transaction = Self::BackendTransaction>
    + Finalizer<Self::Block, Self::Backend>
    + ProvideRuntimeApi<Self::Block, Api = Self::Api>
    + 'static;
}

/// Trait implementable on firm types to automatically provide a full TendermintClient impl.
pub trait TendermintClientMinimal: Send + Sync + 'static {
  const BLOCK_TIME_IN_SECONDS: u32;

  type Block: Block;
  type Backend: Backend<Self::Block> + 'static;
  type Api: ApiExt<Self::Block> + TendermintApi<Self::Block>;
  type Client: Send
    + Sync
    + HeaderBackend<Self::Block>
    + BlockBackend<Self::Block>
    + BlockImport<Self::Block, Transaction = TransactionFor<Self::Client, Self::Block>>
    + Finalizer<Self::Block, Self::Backend>
    + ProvideRuntimeApi<Self::Block, Api = Self::Api>
    + 'static;
}

impl<T: TendermintClientMinimal> TendermintClient for T
where
  <T::Client as ProvideRuntimeApi<T::Block>>::Api: TendermintApi<T::Block>,
  TransactionFor<T::Client, T::Block>: Send + Sync + 'static,
{
  const BLOCK_TIME_IN_SECONDS: u32 = T::BLOCK_TIME_IN_SECONDS;

  type Block = T::Block;
  type Backend = T::Backend;

  type BackendTransaction = TransactionFor<T::Client, T::Block>;
  type StateBackend = StateBackendFor<T::Client, T::Block>;
  type Api = <T::Client as ProvideRuntimeApi<T::Block>>::Api;
  type Client = T::Client;
}

/// Trait consolidating additional generics required by sc_tendermint for authoring.
pub trait TendermintValidator: TendermintClient {
  type CIDP: CreateInherentDataProviders<Self::Block, ()> + 'static;
  type Environment: Send + Sync + Environment<Self::Block> + 'static;

  type Network: Clone
    + Send
    + Sync
    + Network<Self::Block>
    + NetworkBlock<<Self::Block as Block>::Hash, <<Self::Block as Block>::Header as Header>::Number>
    + 'static;
}
