use std::{boxed::Box, sync::Arc, error::Error};

use sp_keystore::SyncCryptoStore;
use sp_runtime::traits::{Block as BlockTrait};
use sp_inherents::CreateInherentDataProviders;
use sp_consensus::DisableProofRecording;
use sp_api::{BlockId, ProvideRuntimeApi};
use sp_tendermint::TendermintApi;

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_network::NetworkService;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, TFullClient};

use sc_telemetry::{Telemetry, TelemetryWorker};

pub(crate) use sc_tendermint::{
  TendermintClientMinimal, TendermintValidator, TendermintImport, TendermintAuthority,
  TendermintSelectChain, import_queue,
};
use serai_runtime::{self, MILLISECS_PER_BLOCK, opaque::Block, RuntimeApi};

type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = TendermintSelectChain<Block, FullBackend>;

type PartialComponents = sc_service::PartialComponents<
  FullClient,
  FullBackend,
  FullSelectChain,
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
    serai_runtime::api::dispatch(method, data)
  }

  fn native_version() -> NativeVersion {
    serai_runtime::native_version()
  }
}

pub type FullClient = TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

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

pub struct TendermintValidatorFirm;
impl TendermintClientMinimal for TendermintValidatorFirm {
  const BLOCK_TIME_IN_SECONDS: u32 = { (MILLISECS_PER_BLOCK / 1000) as u32 };

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

  if config.role.is_authority() {
    // Block size + 1 KiB
    let mut cfg = sc_service::config::NonDefaultSetConfig::new(
      sc_tendermint::PROTOCOL_NAME.into(),
      (1024 * 1024) + 1024,
    );
    cfg.allow_non_reserved(25, 25);
    config.network.extra_sets.push(cfg);
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
      crate::rpc::create_full(crate::rpc::FullDeps {
        client: client.clone(),
        pool: pool.clone(),
        deny_unsafe,
      })
      .map_err(Into::into)
    })
  };

  let is_authority = config.role.is_authority();

  let registry = config.prometheus_registry().cloned();
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
    let keys = keystore_container.sync_keystore();
    let key = SyncCryptoStore::sr25519_public_keys(&*keys, sc_tendermint::KEY_TYPE_ID)
      .get(0)
      .cloned()
      .unwrap_or_else(|| {
        SyncCryptoStore::sr25519_generate_new(&*keys, sc_tendermint::KEY_TYPE_ID, None).unwrap()
      });

    let mut spawned = false;
    let mut validators =
      client.runtime_api().validators(&BlockId::Hash(client.chain_info().finalized_hash)).unwrap();
    for (i, validator) in validators.drain(..).enumerate() {
      if validator == key {
        task_manager.spawn_essential_handle().spawn(
          "tendermint",
          None,
          TendermintAuthority::new(authority).authority(
            (u16::try_from(i).unwrap(), keystore_container.keystore()),
            Cidp,
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
        spawned = true;
        break;
      }
    }

    if !spawned {
      log::warn!("authority role yet not a validator");
    }
  }

  network_starter.start_network();
  Ok(task_manager)
}
