use core::{marker::PhantomData, time::Duration};
use std::{boxed::Box, sync::Arc};

use futures_util::stream::StreamExt as _;

use sp_keystore::Keystore;
use sp_timestamp::InherentDataProvider as TimestampInherent;
use sp_consensus_babe::{SlotDuration, inherents::InherentDataProvider as BabeInherent};

use sp_io::SubstrateHostFunctions;
use sc_executor::{sp_wasm_interface::ExtendedHostFunctions, HeapAllocStrategy, WasmExecutor};

use sc_client_api::BlockBackend as _;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_network::{config::FullNetworkConfiguration, NetworkEventStream as _, NetworkBackend as _};
use sc_consensus::{LongestChain, DefaultImportQueue};
use sc_consensus_grandpa::GrandpaParams;
use sc_consensus_babe::{SlotProportion, BabeParams};
use sc_service::{
  error::Error as ServiceError,
  config::{Role, ExecutorConfiguration, KeystoreConfig, Configuration},
  KeystoreContainer, TaskManager, BuildNetworkParams, SpawnTasksParams,
};
use sc_telemetry::{Telemetry, TelemetryWorker};

use serai_abi::{primitives::address::SeraiAddress, SubstrateBlock as Block};
use serai_runtime::RuntimeApi;

mod proposer;
use proposer::SeraiProposerFactory;

use crate::rpc;

#[cfg(not(feature = "runtime-benchmarks"))]
pub(crate) type Executor = WasmExecutor<ExtendedHostFunctions<SubstrateHostFunctions, ()>>;
#[cfg(feature = "runtime-benchmarks")]
pub(crate) type Executor = WasmExecutor<
  ExtendedHostFunctions<SubstrateHostFunctions, frame_benchmarking::benchmarking::HostFunctions>,
>;

type FullBackend = sc_service::TFullBackend<Block>;
pub(crate) type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;

pub(crate) type TransactionPool = sc_transaction_pool::TransactionPoolWrapper<Block, FullClient>;

type SelectChain = LongestChain<FullBackend, Block>;
type GrandpaBlockImport =
  sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, SelectChain>;
type BabeBlockImport<CIDP> =
  sc_consensus_babe::BabeBlockImport<Block, FullClient, GrandpaBlockImport, CIDP, SelectChain>;

type NetworkWorker =
  sc_network::service::NetworkWorker<Block, <Block as sp_runtime::traits::Block>::Hash>;

/// Serai's analogue of [`sc_service::PartialComponents`].
///
/// The main reason for this is due to [`sc_service::PartialComponents`] insisting on containing a
/// [`KeystoreContainer`] when we want to return a [`Arc<dyn Keystore>`].
///
/// The original intent of [`sc_service::PartialComponents`] was to satisfy subcommands within
/// [`sc-cli`], which raises the question of why should Serai maintain this structure when we do
/// not plain to maintain use of [`sc-cli`]. Reviewing the current CLI (at the time of writing this
/// comment), only three of these fields are actually needed/used by subcommands. That implies this
/// layout is largely legacy and not an independently justified design decision. There's no need to
/// refactor it at this time however.
pub(crate) struct Partial<CIDP> {
  pub(crate) backend: Arc<FullBackend>,
  pub(crate) select_chain: SelectChain,
  pub(crate) client: Arc<FullClient>,
  pub(crate) block_import: BabeBlockImport<CIDP>,
  pub(crate) transaction_pool: Arc<TransactionPool>,
  pub(crate) import_queue: DefaultImportQueue<Block>,
  pub(crate) validator_identity: Option<SeraiAddress>,
  pub(crate) keystore: Arc<dyn Keystore>,
  pub(crate) grandpa_link: sc_consensus_grandpa::LinkHalf<Block, FullClient, SelectChain>,
  pub(crate) babe_link: sc_consensus_babe::BabeLink<Block>,
  pub(crate) telemetry: Option<Telemetry>,
  pub(crate) task_manager: TaskManager,
}

fn create_inherent_data_providers(
  slot_duration: SlotDuration,
) -> (BabeInherent, TimestampInherent) {
  // TODO: We should bound this timestamp as Serai does regarding the minimum increment and so on
  let timestamp = TimestampInherent::from_system_time();
  (BabeInherent::from_timestamp_and_slot_duration(*timestamp, slot_duration), timestamp)
}

pub(crate) fn new_partial(
  validator_identity_and_keystore: Option<(SeraiAddress, crate::keystore::Keystore)>,
  config: &mut Configuration,
) -> Result<
  Partial<
    impl sp_inherents::CreateInherentDataProviders<
      Block,
      (),
      InherentDataProviders: sc_consensus_slots::InherentDataProviderExt,
    >,
  >,
  ServiceError,
> {
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

  let executor = {
    /*
      `default_heap_pages` would be used with `HeapAllocStrategy::Static { extra_pages }`. Because
      we trust our WASM blob, we want to let it request as many pages as it wants, whenever it
      wants. This effects the 4 GB limit inherent to WASM.
    */
    let ExecutorConfiguration {
      wasm_method,
      max_runtime_instances,
      default_heap_pages: _,
      runtime_cache_size,
    } = config.executor;
    Executor::builder()
      .with_execution_method(wasm_method)
      .with_onchain_heap_alloc_strategy(HeapAllocStrategy::Dynamic { maximum_pages: None })
      .with_offchain_heap_alloc_strategy(HeapAllocStrategy::Dynamic { maximum_pages: None })
      .with_max_runtime_instances(max_runtime_instances)
      .with_runtime_cache_size(runtime_cache_size)
      .build()
  };

  let (client, backend, validator_identity, keystore, task_manager) = {
    /*
      Traditionally, `new_full_parts_with_genesis_builder` would be used to obtain the keystore. We
      want to use the `keystore` this function was called with however, only falling back to the
      keystore within the configuration if Serai keystore wasn't used.
    */
    let (validator_identity, keystore): (_, Arc<dyn Keystore>) =
      if let Some((validator_identity, keystore)) = validator_identity_and_keystore {
        (Some(validator_identity), Arc::new(keystore))
      } else {
        (None, KeystoreContainer::new(&config.keystore)?.keystore())
      };

    /*
      Because we've now instantiated our keystore, we want to clear the configuration within
      `config` to prevent it from being used/referred to in the future. Unfortunately, we cannot
      clear it entirely as this `struct Configuration` will continue to be used with various
      methods of `sc_service`. Accordingly, we set it to stub values so any attempted further usage
      should be rather obvious.
    */
    config.dev_key_seed = None;
    config.keystore = KeystoreConfig::InMemory;

    let telemetry = telemetry.as_ref().map(|(_, telemetry)| telemetry.handle());
    let backend = sc_service::new_db_backend(config.db_config())?;
    let genesis_block_builder =
      super::chain_spec::genesis_block(&*config.chain_spec, backend.clone(), executor.clone())?;
    let enable_import_proof_recording = false;

    /*
      TODO: Patch `new_full_parts_with_genesis_builder` to remove the keystore from it. It solely
      instantiates it, never using it nor storing any references to it.
    */
    let (client, backend, _keystore, task_manager) =
      sc_service::new_full_parts_with_genesis_builder::<Block, RuntimeApi, _, _>(
        config,
        telemetry,
        executor,
        backend,
        genesis_block_builder,
        enable_import_proof_recording,
      )?;

    (Arc::new(client), backend, validator_identity, keystore, task_manager)
  };

  let telemetry = telemetry.map(|(worker, telemetry)| {
    task_manager.spawn_handle().spawn("telemetry", None, worker.run());
    telemetry
  });

  let select_chain = LongestChain::new(backend.clone());

  let transaction_pool = Arc::new(
    sc_transaction_pool::Builder::new(
      task_manager.spawn_essential_handle(),
      client.clone(),
      config.role.is_authority().into(),
    )
    .with_options(config.transaction_pool.clone())
    .with_prometheus(config.prometheus_registry())
    .build(),
  );

  let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
    client.clone(),
    u32::MAX,
    &client,
    select_chain.clone(),
    telemetry.as_ref().map(Telemetry::handle),
  )?;

  let (block_import, babe_link, slot_duration) = {
    let babe_config = sc_consensus_babe::configuration(&*client)?;
    let slot_duration = babe_config.slot_duration();
    let (block_import, babe_link) = sc_consensus_babe::block_import(
      babe_config,
      grandpa_block_import.clone(),
      client.clone(),
      /*
        For whatever reason, this doesn't work when defined as an `async` closure. This lint rule
        may assume lifetime capture rules part of the 2024 edition?

        TODO: Create an upstream issue with Rust for how this lint is too eagerly applied.
      */
      #[expect(closure_returning_async_block)]
      move |_, ()| async move { Ok(create_inherent_data_providers(slot_duration)) },
      select_chain.clone(),
      OffchainTransactionPoolFactory::new(transaction_pool.clone()),
    )?;
    (block_import, babe_link, slot_duration)
  };

  let import_queue = {
    let (import_queue, babe_handle) =
      sc_consensus_babe::import_queue(sc_consensus_babe::ImportQueueParams {
        link: babe_link.clone(),
        block_import: block_import.clone(),
        justification_import: Some(Box::new(grandpa_block_import)),
        slot_duration,
        client: client.clone(),
        spawner: &task_manager.spawn_essential_handle(),
        registry: config.prometheus_registry(),
        telemetry: telemetry.as_ref().map(Telemetry::handle),
      })?;

    /*
      BABE requires this handle be held, where its task will end if it's dropped.

      We don't have any use for it though. It solely allows fetching epoch data, and doesn't even
      have a channel one could receive events over.

      Because we don't need it, and because we don't _have_ to poll it (for BABE to function/to
      prevent an unbounded channel from serving as an effective memory leak), we simply forget it.

      TODO: Review how feasible it'd be to patch out, so we don't have to be concerned about if
      this has an unbounded channel added to it someday which we would have to spawn a task to
      actively drain or similar.
    */
    std::mem::forget(babe_handle);

    import_queue
  };

  Ok(Partial {
    backend,
    client,
    select_chain,
    block_import,
    transaction_pool,
    import_queue,
    validator_identity,
    keystore,
    grandpa_link,
    babe_link,
    telemetry,
    task_manager,
  })
}

pub(crate) fn new_full(
  validator_identity_and_keystore: Option<(SeraiAddress, crate::keystore::Keystore)>,
  mut config: Configuration,
) -> Result<TaskManager, ServiceError> {
  let Partial {
    backend,
    client,
    select_chain,
    block_import,
    transaction_pool,
    import_queue,
    validator_identity,
    keystore,
    grandpa_link,
    babe_link,
    mut telemetry,
    mut task_manager,
  } = new_partial(validator_identity_and_keystore, &mut config)?;

  let mut net_config = FullNetworkConfiguration::<_, _, NetworkWorker>::new(
    &config.network,
    config.prometheus_registry().cloned(),
  );
  let metrics = NetworkWorker::register_notification_metrics(config.prometheus_registry());

  let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
    &client.block_hash(0).unwrap().unwrap(),
    &config.chain_spec,
  );
  let (grandpa_protocol_config, grandpa_notification_service) =
    sc_consensus_grandpa::grandpa_peers_set_config::<Block, NetworkWorker>(
      grandpa_protocol_name.clone(),
      metrics.clone(),
      net_config.peer_store_handle(),
    );
  net_config.add_notification_protocol(grandpa_protocol_config);

  let (network, system_rpc_tx, tx_handler_controller, sync_service) =
    sc_service::build_network(BuildNetworkParams {
      config: &config,
      net_config,
      client: client.clone(),
      transaction_pool: transaction_pool.clone(),
      spawn_handle: task_manager.spawn_handle(),
      import_queue,
      block_announce_validator_builder: None,
      warp_sync_config: None,
      block_relay: None,
      metrics,
    })?;

  let authority_discovery = config.role.is_authority().then(|| {
    let (worker, service) = sc_authority_discovery::new_worker_and_service_with_config(
      {
        // The following pattern has us explicitly set every field, even if we generally defer to
        // the default values
        let default = sc_authority_discovery::WorkerConfig::default();
        sc_authority_discovery::WorkerConfig {
          max_publish_interval: default.max_publish_interval,
          keystore_refresh_interval: default.keystore_refresh_interval,
          max_query_interval: default.max_query_interval,
          publish_non_global_ips: config.network.allow_non_globals_in_dht,
          public_addresses: config.network.public_addresses.clone(),
          // This defaults to `false` for legacy compatibility, yet Serai always set it to `true`
          // and is unshackled from the bounds of history and time past in this regard
          strict_record_validation: true,
          persisted_cache_directory: config.network.net_config_path.clone(),
        }
      },
      client.clone(),
      Arc::new(network.clone()),
      Box::pin(network.event_stream("authority-discovery").filter_map(async |event| {
        if let sc_network::Event::Dht(event) = event {
          Some(event)
        } else {
          None
        }
      })),
      sc_authority_discovery::Role::PublishAndDiscover(keystore.clone()),
      config.prometheus_registry().cloned(),
      task_manager.spawn_handle(),
    );
    task_manager.spawn_handle().spawn(
      "authority-discovery-worker",
      Some("networking"),
      worker.run(),
    );
    service
  });

  let rpc_builder = {
    let bootnodes = config.chain_spec.boot_nodes().to_vec();
    let client = client.clone();
    let pool = transaction_pool.clone();

    // TODO(never): Why is this bound `Fn` and not `FnOnce`?
    Box::new(move |_| {
      rpc::create_full(rpc::FullDeps {
        bootnodes: bootnodes.clone(),
        client: client.clone(),
        pool: pool.clone(),
        authority_discovery: authority_discovery.clone(),
      })
      .map_err(Into::into)
    })
  };

  let name = config.network.node_name.clone();
  let role = config.role;
  let force_authoring = config.force_authoring;
  let prometheus_registry = config.prometheus_registry().cloned();

  sc_service::spawn_tasks(SpawnTasksParams {
    config,
    client: client.clone(),
    backend,
    task_manager: &mut task_manager,
    keystore: keystore.clone(),
    transaction_pool: transaction_pool.clone(),
    rpc_builder,
    network: network.clone(),
    system_rpc_tx,
    tx_handler_controller,
    sync_service: sync_service.clone(),
    telemetry: telemetry.as_mut(),
    tracing_execute_block: None,
  })?;

  if let Role::Authority = &role {
    let slot_duration = babe_link.config().slot_duration();
    let env = SeraiProposerFactory {
      proposer_identity: validator_identity.expect("validator yet validator identity wasn't set"),
      underlying: sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        prometheus_registry.as_ref(),
        telemetry.as_ref().map(Telemetry::handle),
      ),
      _block: PhantomData,
    };
    task_manager.spawn_essential_handle().spawn_blocking(
      "babe-proposer",
      Some("block-authoring"),
      sc_consensus_babe::start_babe(BabeParams {
        keystore: keystore.clone(),
        client,
        select_chain,
        env,
        block_import,
        sync_oracle: sync_service.clone(),
        justification_sync_link: sync_service.clone(),
        #[expect(closure_returning_async_block)]
        create_inherent_data_providers: move |_, ()| async move {
          Ok(create_inherent_data_providers(slot_duration))
        },
        force_authoring,
        backoff_authoring_blocks: None::<()>,
        babe_link,
        block_proposal_slot_portion: SlotProportion::new(0.5),
        max_block_proposal_slot_portion: None,
        telemetry: telemetry.as_ref().map(Telemetry::handle),
      })?,
    );
  }

  {
    // https://docs.rs/sc-consensus-grandpa/0.4.0/sc_consensus_grandpa/fn.run_grandpa_observer.html
    // "we don't consider it stable enough to use on a live network"
    let observer_enabled = false;
    task_manager.spawn_essential_handle().spawn_blocking(
      "grandpa-voter",
      Some("block-finalizing"),
      sc_consensus_grandpa::run_grandpa_voter(GrandpaParams {
        config: sc_consensus_grandpa::Config {
          gossip_duration: Duration::from_millis(500),
          justification_generation_period: 1,

          observer_enabled,
          local_role: role,
          name: Some(name),
          keystore: role.is_authority().then_some(keystore),
          telemetry: telemetry.as_ref().map(Telemetry::handle),
          protocol_name: grandpa_protocol_name,
        },
        link: grandpa_link,
        network,
        sync: sync_service,
        notification_service: grandpa_notification_service,
        voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
        prometheus_registry,
        shared_voter_state: sc_consensus_grandpa::SharedVoterState::empty(),
        offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
        telemetry: telemetry.as_ref().map(Telemetry::handle),
      })?,
    );
  }

  Ok(task_manager)
}
