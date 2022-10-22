use std::{sync::Arc, future::Future};

use sp_runtime::traits::Block as BlockTrait;
use sp_api::TransactionFor;

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_service::{TaskManager, TFullClient};

use substrate_prometheus_endpoint::Registry;

use serai_runtime::{self, opaque::Block, RuntimeApi};

mod signature_scheme;
mod weights;

mod tendermint;
mod block_import;
mod verifier;

mod import_queue;
use import_queue::TendermintImportQueue;

mod select_chain;
pub use select_chain::TendermintSelectChain;

const CONSENSUS_ID: [u8; 4] = *b"tend";

pub struct ExecutorDispatch;
impl NativeExecutionDispatch for ExecutorDispatch {
  #[cfg(feature = "runtime-benchmarks")]
  type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
  #[cfg(not(feature = "runtime-benchmarks"))]
  type ExtendHostFunctions = ();

  fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
    serai_runtime::api::dispatch(method, data)
  }

  fn native_version() -> NativeVersion {
    serai_runtime::native_version()
  }
}

pub type FullClient = TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub trait Announce<B: BlockTrait>: Send + Sync + Clone + 'static {
  fn announce(&self, hash: B::Hash);
}

pub fn import_queue<A: Announce<Block>>(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  announce: A,
  pool: Arc<FullPool<Block, FullClient>>,
  registry: Option<&Registry>,
) -> (impl Future<Output = ()>, TendermintImportQueue<Block, TransactionFor<FullClient, Block>>) {
  import_queue::import_queue(
    client.clone(),
    client.clone(),
    announce,
    Arc::new(|_, _| async { Ok(sp_timestamp::InherentDataProvider::from_system_time()) }),
    sc_basic_authorship::ProposerFactory::new(
      task_manager.spawn_handle(),
      client,
      pool,
      registry,
      None,
    ),
    &task_manager.spawn_essential_handle(),
    registry,
  )
}

/*
// If we're an authority, produce blocks
pub fn authority<S: sp_consensus::SelectChain<Block> + 'static>(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  network: Arc<sc_network::NetworkService<Block, <Block as sp_runtime::traits::Block>::Hash>>,
  pool: Arc<sc_transaction_pool::FullPool<Block, FullClient>>,
  select_chain: S,
  registry: Option<&Registry>,
) {
  let proposer = sc_basic_authorship::ProposerFactory::new(
    task_manager.spawn_handle(),
    client.clone(),
    pool,
    registry,
    None,
  );

  let pow_block_import = Box::new(sc_pow::PowBlockImport::new(
    client.clone(),
    client.clone(),
    algorithm::AcceptAny,
    0, // Block to start checking inherents at
    select_chain.clone(),
    move |_, _| async { Ok(sp_timestamp::InherentDataProvider::from_system_time()) },
  ));

  let (worker, worker_task) = sc_pow::start_mining_worker(
    pow_block_import,
    client,
    select_chain,
    algorithm::AcceptAny,
    proposer,
    network.clone(),
    network,
    None,
    move |_, _| async { Ok(sp_timestamp::InherentDataProvider::from_system_time()) },
    Duration::from_secs(6),
    Duration::from_secs(2),
  );

  task_manager.spawn_essential_handle().spawn_blocking("pow", None, worker_task);

  task_manager.spawn_essential_handle().spawn("producer", None, produce(worker));
}
*/
