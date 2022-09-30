use std::sync::Arc;

use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_executor::NativeElseWasmExecutor;
use sc_telemetry::{Telemetry, TelemetryWorker};

use serai_runtime::{self, opaque::Block, RuntimeApi};
pub(crate) use serai_consensus::{ExecutorDispatch, FullClient};

type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

type PartialComponents = sc_service::PartialComponents<
  FullClient,
  FullBackend,
  FullSelectChain,
  sc_consensus::DefaultImportQueue<Block, FullClient>,
  sc_transaction_pool::FullPool<Block, FullClient>,
  Option<Telemetry>,
>;

pub fn new_partial(config: &Configuration) -> Result<PartialComponents, ServiceError> {
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
  let client = Arc::new(client);

  let telemetry = telemetry.map(|(worker, telemetry)| {
    task_manager.spawn_handle().spawn("telemetry", None, worker.run());
    telemetry
  });

  let select_chain = sc_consensus::LongestChain::new(backend.clone());

  let transaction_pool = sc_transaction_pool::BasicPool::new_full(
    config.transaction_pool.clone(),
    config.role.is_authority().into(),
    config.prometheus_registry(),
    task_manager.spawn_essential_handle(),
    client.clone(),
  );

  let import_queue = serai_consensus::import_queue(
    &task_manager,
    client.clone(),
    select_chain.clone(),
    config.prometheus_registry(),
  )?;

  Ok(sc_service::PartialComponents {
    client,
    backend,
    task_manager,
    import_queue,
    keystore_container,
    select_chain,
    transaction_pool,
    other: telemetry,
  })
}

pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
  let sc_service::PartialComponents {
    client,
    backend,
    mut task_manager,
    import_queue,
    keystore_container,
    select_chain,
    other: mut telemetry,
    transaction_pool,
  } = new_partial(&config)?;

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

  let role = config.role.clone();
  let prometheus_registry = config.prometheus_registry().cloned();

  let rpc_extensions_builder = {
    let client = client.clone();
    let pool = transaction_pool.clone();

    Box::new(move |deny_unsafe, _| {
      crate::rpc::create_full(crate::rpc::FullDeps {
        client: client.clone(),
        pool: pool.clone(),
        deny_unsafe,
      })
      .map_err(Into::into)
    })
  };

  sc_service::spawn_tasks(sc_service::SpawnTasksParams {
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

  if role.is_authority() {
    serai_consensus::authority(
      &task_manager,
      client,
      network,
      transaction_pool,
      select_chain,
      prometheus_registry.as_ref(),
    );
  }

  network_starter.start_network();
  Ok(task_manager)
}
