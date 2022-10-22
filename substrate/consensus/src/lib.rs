use std::sync::Arc;

use sp_api::TransactionFor;
use sp_consensus::Error;

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_service::{TaskManager, TFullClient};

use substrate_prometheus_endpoint::Registry;

use serai_runtime::{self, opaque::Block, RuntimeApi};

mod signature_scheme;
mod weights;

mod import_queue;
use import_queue::TendermintImportQueue;

mod select_chain;
pub use select_chain::TendermintSelectChain;

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

pub fn import_queue(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  pool: Arc<FullPool<Block, FullClient>>,
  registry: Option<&Registry>,
) -> Result<TendermintImportQueue<Block, TransactionFor<FullClient, Block>>, Error> {
  Ok(import_queue::import_queue(
    client.clone(),
    client.clone(),
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
  ))
}

// If we're an authority, produce blocks
pub fn authority(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  network: Arc<sc_network::NetworkService<Block, <Block as sp_runtime::traits::Block>::Hash>>,
  pool: Arc<FullPool<Block, FullClient>>,
  registry: Option<&Registry>,
) {
  todo!()
}

/*
// Produce a block every 6 seconds
async fn produce<
  Block: sp_api::BlockT<Hash = sp_core::H256>,
  Algorithm: sc_pow::PowAlgorithm<Block, Difficulty = sp_core::U256> + Send + Sync + 'static,
  C: sp_api::ProvideRuntimeApi<Block> + 'static,
  Link: sc_consensus::JustificationSyncLink<Block> + 'static,
  P: Send + 'static,
>(
  worker: sc_pow::MiningHandle<Block, Algorithm, C, Link, P>,
) where
  sp_api::TransactionFor<C, Block>: Send + 'static,
{
  loop {
    let worker_clone = worker.clone();
    std::thread::spawn(move || {
      tokio::runtime::Runtime::new().unwrap().handle().block_on(async {
        worker_clone.submit(vec![]).await;
      });
    });
    tokio::time::sleep(Duration::from_secs(6)).await;
  }
}

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
