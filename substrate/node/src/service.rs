use std::{boxed::Box, sync::Arc};

use futures_util::stream::StreamExt;

use sp_timestamp::InherentDataProvider as TimestampInherent;
use sp_consensus_babe::{SlotDuration, inherents::InherentDataProvider as BabeInherent};

use sp_io::SubstrateHostFunctions;
use sc_executor::{sp_wasm_interface::ExtendedHostFunctions, WasmExecutor};

use sc_network_common::sync::warp::WarpSyncParams;
use sc_network::{Event, NetworkEventStream};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, TFullClient};

use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_client_api::{BlockBackend, Backend};

use sc_telemetry::{Telemetry, TelemetryWorker};

use serai_runtime::{Block, RuntimeApi};

use sc_consensus_babe::{self, SlotProportion};
use sc_consensus_grandpa as grandpa;

#[cfg(not(feature = "runtime-benchmarks"))]
pub type Executor = WasmExecutor<ExtendedHostFunctions<SubstrateHostFunctions, ()>>;
#[cfg(feature = "runtime-benchmarks")]
pub type Executor = WasmExecutor<
  ExtendedHostFunctions<SubstrateHostFunctions, frame_benchmarking::benchmarking::HostFunctions>,
>;

type FullBackend = sc_service::TFullBackend<Block>;
pub type FullClient = TFullClient<Block, RuntimeApi, Executor>;

type SelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type GrandpaBlockImport = grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, SelectChain>;
type BabeBlockImport = sc_consensus_babe::BabeBlockImport<Block, FullClient, GrandpaBlockImport>;

type PartialComponents = sc_service::PartialComponents<
  FullClient,
  FullBackend,
  SelectChain,
  sc_consensus::DefaultImportQueue<Block, FullClient>,
  sc_transaction_pool::FullPool<Block, FullClient>,
  (
    BabeBlockImport,
    sc_consensus_babe::BabeLink<Block>,
    grandpa::LinkHalf<Block, FullClient, SelectChain>,
    grandpa::SharedVoterState,
    Option<Telemetry>,
  ),
>;

fn create_inherent_data_providers(
  slot_duration: SlotDuration,
) -> (BabeInherent, TimestampInherent) {
  let timestamp = TimestampInherent::from_system_time();
  (BabeInherent::from_timestamp_and_slot_duration(*timestamp, slot_duration), timestamp)
}

pub fn new_partial(
  config: &Configuration,
) -> Result<(PartialComponents, Arc<dyn sp_keystore::Keystore>), ServiceError> {
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

  #[allow(deprecated)]
  let executor = Executor::new(
    config.wasm_method,
    config.default_heap_pages,
    config.max_runtime_instances,
    None,
    config.runtime_cache_size,
  );

  let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts::<Block, RuntimeApi, _>(
      config,
      telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
      executor,
    )?;
  let client = Arc::new(client);

  let keystore: Arc<dyn sp_keystore::Keystore> =
    if let Some(keystore) = crate::keystore::Keystore::from_env() {
      Arc::new(keystore)
    } else {
      keystore_container.keystore()
    };

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

  let (grandpa_block_import, grandpa_link) = grandpa::block_import(
    client.clone(),
    &client,
    select_chain.clone(),
    telemetry.as_ref().map(Telemetry::handle),
  )?;
  let justification_import = grandpa_block_import.clone();

  let (block_import, babe_link) = sc_consensus_babe::block_import(
    sc_consensus_babe::configuration(&*client)?,
    grandpa_block_import,
    client.clone(),
  )?;

  let slot_duration = babe_link.config().slot_duration();
  let (import_queue, babe_handle) =
    sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
      link: babe_link.clone(),
      block_import: block_import.clone(),
      justification_import: Some(Box::new(justification_import)),
      client: client.clone(),
      select_chain: select_chain.clone(),
      create_inherent_data_providers: move |_, ()| async move {
        Ok(create_inherent_data_providers(slot_duration))
      },
      spawner: &task_manager.spawn_essential_handle(),
      registry: config.prometheus_registry(),
      telemetry: telemetry.as_ref().map(Telemetry::handle),
      offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
    })?;
  // This can't be dropped, or BABE breaks
  // We don't have anything to do with it though
  // This won't grow in size, so forgetting this isn't a disastrous memleak
  std::mem::forget(babe_handle);

  Ok((
    sc_service::PartialComponents {
      client,
      backend,
      task_manager,
      keystore_container,
      select_chain,
      import_queue,
      transaction_pool,
      other: (block_import, babe_link, grandpa_link, grandpa::SharedVoterState::empty(), telemetry),
    },
    keystore,
  ))
}

pub fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
  let (
    sc_service::PartialComponents {
      client,
      backend,
      mut task_manager,
      keystore_container: _,
      import_queue,
      select_chain,
      transaction_pool,
      other: (block_import, babe_link, grandpa_link, shared_voter_state, mut telemetry),
    },
    keystore_container,
  ) = new_partial(&config)?;

  let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);
  let grandpa_protocol_name =
    grandpa::protocol_standard_name(&client.block_hash(0).unwrap().unwrap(), &config.chain_spec);
  net_config.add_notification_protocol(sc_consensus_grandpa::grandpa_peers_set_config(
    grandpa_protocol_name.clone(),
  ));

  let publish_non_global_ips = config.network.allow_non_globals_in_dht;

  let warp_sync = Arc::new(grandpa::warp_proof::NetworkProvider::new(
    backend.clone(),
    grandpa_link.shared_authority_set().clone(),
    vec![],
  ));

  let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
    sc_service::build_network(sc_service::BuildNetworkParams {
      config: &config,
      net_config,
      client: client.clone(),
      transaction_pool: transaction_pool.clone(),
      spawn_handle: task_manager.spawn_handle(),
      import_queue,
      block_announce_validator_builder: None,
      warp_sync_params: Some(WarpSyncParams::WithProvider(warp_sync)),
    })?;

  if config.offchain_worker.enabled {
    task_manager.spawn_handle().spawn(
      "offchain-workers-runner",
      "offchain-worker",
      sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
        runtime_api_provider: client.clone(),
        is_validator: config.role.is_authority(),
        keystore: Some(keystore_container.clone()),
        offchain_db: backend.offchain_storage(),
        transaction_pool: Some(OffchainTransactionPoolFactory::new(transaction_pool.clone())),
        network_provider: network.clone(),
        enable_http_requests: true,
        custom_extensions: |_| vec![],
      })
      .run(client.clone(), task_manager.spawn_handle()),
    );
  }

  let role = config.role.clone();
  let keystore = keystore_container;
  let prometheus_registry = config.prometheus_registry().cloned();

  // TODO: Ensure we're considered as an authority is a validator of an external network
  let authority_discovery = if role.is_authority() {
    let (worker, service) = sc_authority_discovery::new_worker_and_service_with_config(
      #[allow(clippy::field_reassign_with_default)]
      {
        let mut worker = sc_authority_discovery::WorkerConfig::default();
        worker.publish_non_global_ips = publish_non_global_ips;
        worker.strict_record_validation = true;
        worker
      },
      client.clone(),
      network.clone(),
      Box::pin(network.event_stream("authority-discovery").filter_map(|e| async move {
        match e {
          Event::Dht(e) => Some(e),
          _ => None,
        }
      })),
      sc_authority_discovery::Role::PublishAndDiscover(keystore.clone()),
      prometheus_registry.clone(),
    );
    task_manager.spawn_handle().spawn(
      "authority-discovery-worker",
      Some("networking"),
      worker.run(),
    );

    Some(service)
  } else {
    None
  };

  let rpc_builder = {
    let client = client.clone();
    let pool = transaction_pool.clone();

    Box::new(move |deny_unsafe, _| {
      crate::rpc::create_full(crate::rpc::FullDeps {
        client: client.clone(),
        pool: pool.clone(),
        deny_unsafe,
        authority_discovery: authority_discovery.clone(),
      })
      .map_err(Into::into)
    })
  };

  let enable_grandpa = !config.disable_grandpa;
  let force_authoring = config.force_authoring;
  let name = config.network.node_name.clone();

  sc_service::spawn_tasks(sc_service::SpawnTasksParams {
    config,
    backend,
    client: client.clone(),
    keystore: keystore.clone(),
    network: network.clone(),
    rpc_builder,
    transaction_pool: transaction_pool.clone(),
    task_manager: &mut task_manager,
    system_rpc_tx,
    tx_handler_controller,
    sync_service: sync_service.clone(),
    telemetry: telemetry.as_mut(),
  })?;

  if let sc_service::config::Role::Authority { .. } = &role {
    let slot_duration = babe_link.config().slot_duration();
    let babe_config = sc_consensus_babe::BabeParams {
      keystore: keystore.clone(),
      client: client.clone(),
      select_chain,
      env: sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client,
        transaction_pool.clone(),
        prometheus_registry.as_ref(),
        telemetry.as_ref().map(Telemetry::handle),
      ),
      block_import,
      sync_oracle: sync_service.clone(),
      justification_sync_link: sync_service.clone(),
      create_inherent_data_providers: move |_, ()| async move {
        Ok(create_inherent_data_providers(slot_duration))
      },
      force_authoring,
      backoff_authoring_blocks: None::<()>,
      babe_link,
      block_proposal_slot_portion: SlotProportion::new(0.5),
      max_block_proposal_slot_portion: None,
      telemetry: telemetry.as_ref().map(Telemetry::handle),
    };

    task_manager.spawn_essential_handle().spawn_blocking(
      "babe-proposer",
      Some("block-authoring"),
      sc_consensus_babe::start_babe(babe_config)?,
    );
  }

  if enable_grandpa {
    task_manager.spawn_essential_handle().spawn_blocking(
      "grandpa-voter",
      None,
      grandpa::run_grandpa_voter(grandpa::GrandpaParams {
        config: grandpa::Config {
          gossip_duration: std::time::Duration::from_millis(333),
          justification_period: 512,
          name: Some(name),
          observer_enabled: false,
          keystore: if role.is_authority() { Some(keystore) } else { None },
          local_role: role,
          telemetry: telemetry.as_ref().map(Telemetry::handle),
          protocol_name: grandpa_protocol_name,
        },
        link: grandpa_link,
        network,
        sync: Arc::new(sync_service),
        telemetry: telemetry.as_ref().map(Telemetry::handle),
        voting_rule: grandpa::VotingRulesBuilder::default().build(),
        prometheus_registry,
        shared_voter_state,
        offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
      })?,
    );
  }

  network_starter.start_network();
  Ok(task_manager)
}
