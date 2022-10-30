use std::sync::{Arc, RwLock};

use sp_core::H256;

use sc_executor::NativeElseWasmExecutor;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_network::{NetworkService, NetworkBlock};
use sc_telemetry::{Telemetry, TelemetryWorker};

use serai_runtime::{self, opaque::Block, RuntimeApi};
pub(crate) use serai_consensus::{
  TendermintAuthority, ExecutorDispatch, Announce, FullClient, TendermintValidatorFirm,
};

type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = serai_consensus::TendermintSelectChain<Block, FullBackend>;

type PartialComponents = sc_service::PartialComponents<
  FullClient,
  FullBackend,
  FullSelectChain,
  sc_consensus::DefaultImportQueue<Block, FullClient>,
  sc_transaction_pool::FullPool<Block, FullClient>,
  Option<Telemetry>,
>;

#[derive(Clone)]
pub struct NetworkAnnounce(Arc<RwLock<Option<Arc<NetworkService<Block, H256>>>>>);
impl NetworkAnnounce {
  fn new() -> NetworkAnnounce {
    NetworkAnnounce(Arc::new(RwLock::new(None)))
  }
}
impl Announce<Block> for NetworkAnnounce {
  fn announce(&self, hash: H256) {
    if let Some(network) = self.0.read().unwrap().as_ref() {
      network.announce_block(hash, None);
    }
  }
}

pub fn new_partial(
  config: &Configuration,
) -> Result<
  (
    (NetworkAnnounce, TendermintAuthority<TendermintValidatorFirm<NetworkAnnounce>>),
    PartialComponents,
  ),
  ServiceError,
> {
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

  let transaction_pool = sc_transaction_pool::BasicPool::new_full(
    config.transaction_pool.clone(),
    config.role.is_authority().into(),
    config.prometheus_registry(),
    task_manager.spawn_essential_handle(),
    client.clone(),
  );

  let announce = NetworkAnnounce::new();
  let (authority, import_queue) = serai_consensus::import_queue(
    &task_manager,
    client.clone(),
    announce.clone(),
    transaction_pool.clone(),
    config.prometheus_registry(),
  );

  let select_chain = serai_consensus::TendermintSelectChain::new(backend.clone());

  Ok((
    (announce, authority),
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

pub async fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
  let (
    (announce, authority),
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
  *announce.0.write().unwrap() = Some(network.clone());

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
      crate::rpc::create_full(crate::rpc::FullDeps {
        client: client.clone(),
        pool: pool.clone(),
        deny_unsafe,
      })
      .map_err(Into::into)
    })
  };

  let is_authority = config.role.is_authority();

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

  if is_authority {
    authority.validate().await;
  }

  network_starter.start_network();
  Ok(task_manager)
}
