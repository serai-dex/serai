use std::{
  error::Error,
  boxed::Box,
  sync::Arc,
  time::{UNIX_EPOCH, SystemTime, Duration},
  str::FromStr,
};

use sp_runtime::traits::{Block as BlockTrait};
use sp_inherents::CreateInherentDataProviders;
use sp_consensus::DisableProofRecording;
use sp_api::ProvideRuntimeApi;

use in_instructions_client::InherentDataProvider as InstructionsProvider;

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_network::NetworkService;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, TFullClient};

use sc_client_api::BlockBackend;
use sc_client_api::BlockchainEvents;

use sc_telemetry::{Telemetry, TelemetryWorker};

pub(crate) use sc_tendermint::{
  TendermintClientMinimal, TendermintValidator, TendermintImport, TendermintAuthority,
  TendermintSelectChain, import_queue,
};
use serai_runtime::{self as runtime, BLOCK_SIZE, TARGET_BLOCK_TIME, opaque::Block, RuntimeApi};

type FullBackend = sc_service::TFullBackend<Block>;
pub type FullClient = TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

type PartialComponents = sc_service::PartialComponents<
  FullClient,
  FullBackend,
  TendermintSelectChain<Block, FullBackend>,
  sc_consensus::DefaultImportQueue<Block, FullClient>,
  sc_transaction_pool::FullPool<Block, FullClient>,
  Option<Telemetry>,
>;

pub struct ExecutorDispatch;
impl NativeExecutionDispatch for ExecutorDispatch {
  #[cfg(feature = "runtime-benchmarks")]
  type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
  #[cfg(not(feature = "runtime-benchmarks"))]
  type ExtendHostFunctions = ();

  fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
    runtime::api::dispatch(method, data)
  }

  fn native_version() -> NativeVersion {
    serai_runtime::native_version()
  }
}

pub struct Cidp;
#[async_trait::async_trait]
impl CreateInherentDataProviders<Block, ()> for Cidp {
  type InherentDataProviders = (InstructionsProvider,);
  async fn create_inherent_data_providers(
    &self,
    _: <Block as BlockTrait>::Hash,
    _: (),
  ) -> Result<Self::InherentDataProviders, Box<dyn Send + Sync + Error>> {
    Ok((InstructionsProvider::new(),))
  }
}

pub struct TendermintValidatorFirm;
impl TendermintClientMinimal for TendermintValidatorFirm {
  // TODO: This is passed directly to propose, which warns not to use the hard limit as finalize
  // may grow the block. We don't use storage proofs and use the Executive finalize_block. Is that
  // guaranteed not to grow the block?
  const PROPOSED_BLOCK_SIZE_LIMIT: usize = { BLOCK_SIZE as usize };
  // 3 seconds
  const BLOCK_PROCESSING_TIME_IN_SECONDS: u32 = { (TARGET_BLOCK_TIME / 2 / 1000) as u32 };
  // 1 second
  const LATENCY_TIME_IN_SECONDS: u32 = { (TARGET_BLOCK_TIME / 2 / 3 / 1000) as u32 };

  type Block = Block;
  type Backend = sc_client_db::Backend<Block>;
  type Api = <FullClient as ProvideRuntimeApi<Block>>::Api;
  type Client = FullClient;
}

impl TendermintValidator for TendermintValidatorFirm {
  type CIDP = Cidp;
  type Environment = sc_basic_authorship::ProposerFactory<
    FullPool<Block, FullClient>,
    Self::Backend,
    Self::Client,
    DisableProofRecording,
  >;

  type Network = Arc<NetworkService<Block, <Block as BlockTrait>::Hash>>;
}

pub fn new_partial(
  config: &Configuration,
) -> Result<(TendermintImport<TendermintValidatorFirm>, PartialComponents), ServiceError> {
  debug_assert_eq!(TARGET_BLOCK_TIME, 6000);

  if config.keystore_remote.is_some() {
    return Err(ServiceError::Other("Remote Keystores are not supported".to_string()));
  }

  let telemetry = config
    .telemetry_endpoints
    .clone()
    .filter(|x| !x.is_empty())
    .map(|endpoints| -> Result<_, sc_telemetry::Error> {
      let worker = TelemetryWorker::new(16)?;
      let telemetry = worker.handle().new_telemetry(endpoints);
      Ok((worker, telemetry))
    })
    .transpose()?;

  let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
    config.wasm_method,
    config.default_heap_pages,
    config.max_runtime_instances,
    config.runtime_cache_size,
  );

  let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts::<Block, RuntimeApi, _>(
      config,
      telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
      executor,
    )?;

  let finality_notification_stream = client.finality_notification_stream();

  // listen to finality_notification_stream and output events from all pallets
  
  let client = Arc::new(client);

  let telemetry = telemetry.map(|(worker, telemetry)| {
    task_manager.spawn_handle().spawn("telemetry", None, worker.run());
    telemetry
  });

  let transaction_pool = sc_transaction_pool::BasicPool::new_full(
    config.transaction_pool.clone(),
    config.role.is_authority().into(),
    config.prometheus_registry(),
    task_manager.spawn_essential_handle(),
    client.clone(),
  );

  let (authority, import_queue) = import_queue(
    &task_manager.spawn_essential_handle(),
    client.clone(),
    config.prometheus_registry(),
  );

  let select_chain = TendermintSelectChain::new(backend.clone());

  Ok((
    authority,
    sc_service::PartialComponents {
      client,
      backend,
      task_manager,
      import_queue,
      keystore_container,
      select_chain,
      transaction_pool,
      other: telemetry,
    },
  ))
}

pub async fn new_full(mut config: Configuration) -> Result<TaskManager, ServiceError> {
  let (
    authority,
    sc_service::PartialComponents {
      client,
      backend,
      mut task_manager,
      import_queue,
      keystore_container,
      select_chain: _,
      other: mut telemetry,
      transaction_pool,
    },
  ) = new_partial(&config)?;

  let is_authority = config.role.is_authority();
  let genesis = client.block_hash(0).unwrap().unwrap();
  let tendermint_protocol = sc_tendermint::protocol_name(genesis, config.chain_spec.fork_id());
  if is_authority {
    config
      .network
      .extra_sets
      .push(sc_tendermint::set_config(tendermint_protocol.clone(), BLOCK_SIZE.into()));
  }

  let (network, system_rpc_tx, tx_handler_controller, network_starter) =
    sc_service::build_network(sc_service::BuildNetworkParams {
      config: &config,
      client: client.clone(),
      transaction_pool: transaction_pool.clone(),
      spawn_handle: task_manager.spawn_handle(),
      import_queue,
      block_announce_validator_builder: None,
      warp_sync: None,
    })?;

  if config.offchain_worker.enabled {
    sc_service::build_offchain_workers(
      &config,
      task_manager.spawn_handle(),
      client.clone(),
      network.clone(),
    );
  }

  let rpc_extensions_builder = {
    let client = client.clone();
    let pool = transaction_pool.clone();

    Box::new(move |deny_unsafe, _| {
      let deps =
      crate::rpc::FullDeps { client: client.clone(), pool: pool.clone(), deny_unsafe };
      crate::rpc::create_full(deps)
      .map_err(Into::into)
    })
  };

  let genesis_time = if config.chain_spec.id() != "devnet" {
    UNIX_EPOCH + Duration::from_secs(u64::from_str(&std::env::var("GENESIS").unwrap()).unwrap())
  } else {
    SystemTime::now()
  };

  let registry = config.prometheus_registry().cloned();
  let _pool = transaction_pool.clone();
  //let kafkaModule = crate::kafka::create_full(crate::kafka::KafkaDeps {
  //  client: client.clone(),
  //  pool: pool.clone(),
  //});

  let _rpc_handlers =  sc_service::spawn_tasks(sc_service::SpawnTasksParams {
    network: network.clone(),
    client: client.clone(),
    keystore: keystore_container.sync_keystore(),
    task_manager: &mut task_manager,
    transaction_pool: transaction_pool.clone(),
    rpc_builder: rpc_extensions_builder,
    backend,
    system_rpc_tx,
    tx_handler_controller,
    config,
    telemetry: telemetry.as_mut(),
  })?;

  if is_authority {
    task_manager.spawn_essential_handle().spawn(
      "tendermint",
      None,
      TendermintAuthority::new(
        genesis_time,
        tendermint_protocol,
        authority,
        keystore_container.keystore(),
        Cidp,
        task_manager.spawn_essential_handle(),
        sc_basic_authorship::ProposerFactory::new(
          task_manager.spawn_handle(),
          client,
          transaction_pool,
          registry.as_ref(),
          telemetry.map(|telemtry| telemtry.handle()),
        ),
        network,
        None,
      ),
    );
  }

  network_starter.start_network();
  Ok(task_manager)
}
