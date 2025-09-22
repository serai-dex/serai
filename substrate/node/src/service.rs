use std::{boxed::Box, sync::Arc};

use futures_util::stream::StreamExt;

use sp_timestamp::InherentDataProvider as TimestampInherent;
use sp_consensus_babe::{SlotDuration, inherents::InherentDataProvider as BabeInherent};

use sp_io::SubstrateHostFunctions;
use sc_executor::{sp_wasm_interface::ExtendedHostFunctions, WasmExecutor};

use sc_network::{Event, NetworkEventStream, NetworkBackend};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, TFullClient};

use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_client_api::BlockBackend;

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
  sc_consensus::DefaultImportQueue<Block>,
  sc_transaction_pool::TransactionPoolWrapper<Block, FullClient>,
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
    config.executor.wasm_method,
    config.executor.default_heap_pages,
    config.executor.max_runtime_instances,
    None,
    config.executor.runtime_cache_size,
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

  let transaction_pool = sc_transaction_pool::Builder::new(
    task_manager.spawn_essential_handle(),
    client.clone(),
    config.role.is_authority().into(),
  )
  .with_options(config.transaction_pool.clone())
  .with_prometheus(config.prometheus_registry())
  .build();
  let transaction_pool = Arc::new(transaction_pool);

  let (grandpa_block_import, grandpa_link) = grandpa::block_import(
    client.clone(),
    u32::MAX,
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

pub fn new_full(mut config: Configuration) -> Result<TaskManager, ServiceError> {
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

  config.network.node_name = "serai".to_string();
  config.network.client_version = "0.1.0".to_string();
  config.network.listen_addresses =
    vec!["/ip4/0.0.0.0/tcp/30333".parse().unwrap(), "/ip6/::/tcp/30333".parse().unwrap()];

  type N = sc_network::service::NetworkWorker<Block, <Block as sp_runtime::traits::Block>::Hash>;
  let mut net_config = sc_network::config::FullNetworkConfiguration::<_, _, N>::new(
    &config.network,
    config.prometheus_registry().cloned(),
  );
  let metrics = N::register_notification_metrics(config.prometheus_registry());

  let grandpa_protocol_name =
    grandpa::protocol_standard_name(&client.block_hash(0).unwrap().unwrap(), &config.chain_spec);
  let (grandpa_protocol_config, grandpa_notification_service) =
    sc_consensus_grandpa::grandpa_peers_set_config::<Block, N>(
      grandpa_protocol_name.clone(),
      metrics.clone(),
      net_config.peer_store_handle(),
    );
  net_config.add_notification_protocol(grandpa_protocol_config);

  let publish_non_global_ips = config.network.allow_non_globals_in_dht;

  let (network, system_rpc_tx, tx_handler_controller, sync_service) =
    sc_service::build_network(sc_service::BuildNetworkParams {
      config: &config,
      net_config,
      client: client.clone(),
      transaction_pool: transaction_pool.clone(),
      spawn_handle: task_manager.spawn_handle(),
      import_queue,
      block_announce_validator_builder: None,
      metrics,
      block_relay: None,
      warp_sync_config: None,
    })?;

  task_manager.spawn_handle().spawn("bootnodes", "bootnodes", {
    let network = network.clone();
    let id = config.chain_spec.id().to_string();

    async move {
      // Transforms the above Multiaddrs into MultiaddrWithPeerIds
      // While the PeerIds *should* be known in advance and hardcoded, that data wasn't collected in
      // time and this fine for a testnet
      let bootnodes = || async {
        use libp2p::{
          core::{
            Endpoint,
            transport::{PortUse, DialOpts},
          },
          Transport as TransportTrait,
          tcp::tokio::Transport,
          noise::Config,
        };

        let bootnode_multiaddrs = crate::chain_spec::bootnode_multiaddrs(&id);

        let mut tasks = vec![];
        for multiaddr in bootnode_multiaddrs {
          tasks.push(tokio::time::timeout(
            core::time::Duration::from_secs(10),
            tokio::task::spawn(async move {
              let Ok(noise) = Config::new(&sc_network::Keypair::generate_ed25519()) else { None? };
              let mut transport = Transport::default()
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(noise)
                .multiplex(libp2p::yamux::Config::default());
              let Ok(transport) = transport.dial(
                multiaddr.clone(),
                DialOpts { role: Endpoint::Dialer, port_use: PortUse::Reuse },
              ) else {
                None?
              };
              let Ok((peer_id, _)) = transport.await else { None? };
              Some(sc_network::config::MultiaddrWithPeerId {
                multiaddr: multiaddr.into(),
                peer_id: peer_id.into(),
              })
            }),
          ));
        }

        let mut res = vec![];
        for task in tasks {
          if let Ok(Ok(Some(bootnode))) = task.await {
            res.push(bootnode);
          }
        }
        res
      };

      use sc_network::{NetworkStatusProvider, NetworkPeers};
      loop {
        if let Ok(status) = network.status().await {
          if status.num_connected_peers < 3 {
            for bootnode in bootnodes().await {
              let _ = network.add_reserved_peer(bootnode);
            }
          }
        }
        tokio::time::sleep(core::time::Duration::from_secs(60)).await;
      }
    }
  });

  let role = config.role;
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
      Arc::new(network.clone()),
      Box::pin(network.event_stream("authority-discovery").filter_map(|e| async move {
        match e {
          Event::Dht(e) => Some(e),
          _ => None,
        }
      })),
      sc_authority_discovery::Role::PublishAndDiscover(keystore.clone()),
      prometheus_registry.clone(),
      task_manager.spawn_handle(),
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
    let id = config.chain_spec.id().to_string();
    let client = client.clone();
    let pool = transaction_pool.clone();

    Box::new(move |_| {
      crate::rpc::create_full(crate::rpc::FullDeps {
        id: id.clone(),
        client: client.clone(),
        pool: pool.clone(),
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
          justification_generation_period: 512,
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
        notification_service: grandpa_notification_service,
      })?,
    );
  }

  Ok(task_manager)
}
