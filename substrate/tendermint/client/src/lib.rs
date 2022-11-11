use std::sync::Arc;

use sp_core::crypto::KeyTypeId;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Header, Block};
use sp_blockchain::HeaderBackend;
use sp_api::{StateBackend, StateBackendFor, TransactionFor, ApiExt, ProvideRuntimeApi};
use sp_consensus::{Error, Environment};

use sc_client_api::{BlockBackend, Backend, Finalizer};
use sc_block_builder::BlockBuilderApi;
use sc_consensus::{BlockImport, BasicQueue};

use sc_network_common::config::NonDefaultSetConfig;
use sc_network::{ProtocolName, NetworkBlock};
use sc_network_gossip::Network;

use sp_tendermint::TendermintApi;

use substrate_prometheus_endpoint::Registry;

mod validators;

pub(crate) mod tendermint;
pub use tendermint::TendermintImport;

mod block_import;
pub use block_import::TendermintSelectChain;

pub(crate) mod authority;
pub use authority::TendermintAuthority;

pub const CONSENSUS_ID: [u8; 4] = *b"tend";
pub(crate) const KEY_TYPE_ID: KeyTypeId = KeyTypeId(CONSENSUS_ID);

const PROTOCOL_NAME: &str = "/tendermint/1";

pub fn protocol_name<Hash: AsRef<[u8]>>(genesis: Hash, fork: Option<&str>) -> ProtocolName {
  let mut name = format!("/{}", hex::encode(genesis.as_ref()));
  if let Some(fork) = fork {
    name += &format!("/{}", fork);
  }
  name += PROTOCOL_NAME;
  name.into()
}

pub fn set_config(protocol: ProtocolName) -> NonDefaultSetConfig {
  // TODO: 1 MiB Block Size + 1 KiB
  let mut cfg = NonDefaultSetConfig::new(protocol, (1024 * 1024) + 1024);
  cfg.allow_non_reserved(25, 25);
  cfg
}

/// Trait consolidating all generics required by sc_tendermint for processing.
pub trait TendermintClient: Send + Sync + 'static {
  const BLOCK_PROCESSING_TIME_IN_SECONDS: u32;
  const LATENCY_TIME_IN_SECONDS: u32;

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
  type Api: ApiExt<Self::Block, StateBackend = Self::StateBackend>
    + BlockBuilderApi<Self::Block>
    + TendermintApi<Self::Block>;
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
  const BLOCK_PROCESSING_TIME_IN_SECONDS: u32;
  const LATENCY_TIME_IN_SECONDS: u32;

  type Block: Block;
  type Backend: Backend<Self::Block> + 'static;
  type Api: ApiExt<Self::Block> + BlockBuilderApi<Self::Block> + TendermintApi<Self::Block>;
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
  <T::Client as ProvideRuntimeApi<T::Block>>::Api:
    BlockBuilderApi<T::Block> + TendermintApi<T::Block>,
  TransactionFor<T::Client, T::Block>: Send + Sync + 'static,
{
  const BLOCK_PROCESSING_TIME_IN_SECONDS: u32 = T::BLOCK_PROCESSING_TIME_IN_SECONDS;
  const LATENCY_TIME_IN_SECONDS: u32 = T::LATENCY_TIME_IN_SECONDS;

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

pub type TendermintImportQueue<Block, Transaction> = BasicQueue<Block, Transaction>;

/// Create an import queue, additionally returning the Tendermint Import object iself, enabling
/// creating an author later as well.
pub fn import_queue<T: TendermintValidator>(
  spawner: &impl sp_core::traits::SpawnEssentialNamed,
  client: Arc<T::Client>,
  registry: Option<&Registry>,
) -> (TendermintImport<T>, TendermintImportQueue<T::Block, T::BackendTransaction>)
where
  Arc<T::Client>: BlockImport<T::Block, Transaction = T::BackendTransaction>,
  <Arc<T::Client> as BlockImport<T::Block>>::Error: Into<Error>,
{
  let import = TendermintImport::<T>::new(client);

  let boxed = Box::new(import.clone());
  // Use None for the justification importer since justifications always come with blocks
  // Therefore, they're never imported after the fact, which is what mandates an importer
  let queue = || BasicQueue::new(import.clone(), boxed.clone(), None, spawner, registry);

  *futures::executor::block_on(import.queue.write()) = Some(queue());
  (import.clone(), queue())
}
