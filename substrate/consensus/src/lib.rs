use std::{marker::Sync, sync::Arc, time::Duration};

use substrate_prometheus_endpoint::Registry;

use sc_consensus_pow as sc_pow;
use sc_executor::NativeElseWasmExecutor;
use sc_service::TaskManager;

use serai_runtime::{self, opaque::Block, RuntimeApi};

mod algorithm;

pub struct ExecutorDispatch;
impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
  #[cfg(feature = "runtime-benchmarks")]
  type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
  #[cfg(not(feature = "runtime-benchmarks"))]
  type ExtendHostFunctions = ();

  fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
    serai_runtime::api::dispatch(method, data)
  }

  fn native_version() -> sc_executor::NativeVersion {
    serai_runtime::native_version()
  }
}

pub type FullClient =
  sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

type Db = sp_trie::PrefixedMemoryDB<sp_runtime::traits::BlakeTwo256>;

pub fn import_queue<S: sp_consensus::SelectChain<Block> + 'static>(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  select_chain: S,
  registry: Option<&Registry>,
) -> Result<sc_pow::PowImportQueue<Block, Db>, sp_consensus::Error> {
  let pow_block_import = Box::new(sc_pow::PowBlockImport::new(
    client.clone(),
    client,
    algorithm::AcceptAny,
    0,
    select_chain,
    |_, _| async { Ok(sp_timestamp::InherentDataProvider::from_system_time()) },
  ));

  sc_pow::import_queue(
    pow_block_import,
    None,
    algorithm::AcceptAny,
    &task_manager.spawn_essential_handle(),
    registry,
  )
}

// Produce a block every 5 seconds
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
