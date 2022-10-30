use std::{marker::PhantomData, boxed::Box, sync::Arc, error::Error};

use sp_runtime::traits::Block as BlockTrait;
use sp_inherents::CreateInherentDataProviders;
use sp_consensus::DisableProofRecording;
use sp_api::{TransactionFor, ProvideRuntimeApi};

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_service::{TaskManager, TFullClient};

use substrate_prometheus_endpoint::Registry;

use serai_runtime::{self, opaque::Block, RuntimeApi};

mod types;
use types::{TendermintClientMinimal, TendermintValidator};

mod validators;

mod tendermint;
pub use tendermint::TendermintAuthority;
mod block_import;
mod verifier;

mod import_queue;
use import_queue::TendermintImportQueue;

mod gossip;

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

pub struct Cidp;
#[async_trait::async_trait]
impl CreateInherentDataProviders<Block, ()> for Cidp {
  type InherentDataProviders = (sp_timestamp::InherentDataProvider,);
  async fn create_inherent_data_providers(
    &self,
    _: <Block as BlockTrait>::Hash,
    _: (),
  ) -> Result<Self::InherentDataProviders, Box<dyn Send + Sync + Error>> {
    Ok((sp_timestamp::InherentDataProvider::from_system_time(),))
  }
}

pub struct TendermintValidatorFirm<A: Announce<Block>>(PhantomData<A>);
impl<A: Announce<Block>> TendermintClientMinimal for TendermintValidatorFirm<A> {
  type Block = Block;
  type Backend = sc_client_db::Backend<Block>;
  type Api = <FullClient as ProvideRuntimeApi<Block>>::Api;
  type Client = FullClient;
}

impl<A: Announce<Block>> TendermintValidator for TendermintValidatorFirm<A> {
  type CIDP = Cidp;
  type Environment = sc_basic_authorship::ProposerFactory<
    FullPool<Block, FullClient>,
    Self::Backend,
    Self::Client,
    DisableProofRecording,
  >;

  type Announce = A;
}

pub fn import_queue<A: Announce<Block>>(
  task_manager: &TaskManager,
  client: Arc<FullClient>,
  announce: A,
  pool: Arc<FullPool<Block, FullClient>>,
  registry: Option<&Registry>,
) -> (
  TendermintAuthority<TendermintValidatorFirm<A>>,
  TendermintImportQueue<Block, TransactionFor<FullClient, Block>>,
) {
  import_queue::import_queue::<TendermintValidatorFirm<A>>(
    client.clone(),
    announce,
    Arc::new(Cidp),
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
