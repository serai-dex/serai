use core::future::Future;
use std::{sync::OnceLock, collections::HashMap};

use tokio::sync::Mutex;

use serai_client::primitives::NetworkId;

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification,
  DockerOperations, DockerTest,
};

use serai_docker_tests::fresh_logs_folder;
use serai_processor_tests::{network_instance, processor_instance};
use serai_message_queue_tests::instance as message_queue_instance;
use serai_coordinator_tests::{coordinator_instance, serai_composition};

use crate::*;

mod mint_and_burn;

pub(crate) const VALIDATORS: usize = 4;
// pub(crate) const THRESHOLD: usize = ((VALIDATORS * 2) / 3) + 1;

static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

#[async_trait::async_trait]
pub(crate) trait TestBody: 'static + Send + Sync {
  async fn body(&self, ops: DockerOperations, handles: Vec<Handles>);
}
#[async_trait::async_trait]
impl<F: Send + Future, TB: 'static + Send + Sync + Fn(DockerOperations, Vec<Handles>) -> F> TestBody
  for TB
{
  async fn body(&self, ops: DockerOperations, handles: Vec<Handles>) {
    (self)(ops, handles).await;
  }
}

pub(crate) async fn new_test(test_body: impl TestBody) {
  let mut unique_id_lock = UNIQUE_ID.get_or_init(|| Mutex::new(0)).lock().await;

  let mut all_handles = vec![];
  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  let mut coordinator_compositions = vec![];
  for i in 0 .. VALIDATORS {
    let name = match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    };

    let (coord_key, message_queue_keys, message_queue_composition) = message_queue_instance();

    let (bitcoin_composition, bitcoin_port) = network_instance(NetworkId::Bitcoin);
    let mut bitcoin_processor_composition =
      processor_instance(NetworkId::Bitcoin, bitcoin_port, message_queue_keys[&NetworkId::Bitcoin]);
    assert_eq!(bitcoin_processor_composition.len(), 1);
    let bitcoin_processor_composition = bitcoin_processor_composition.swap_remove(0);

    let (monero_composition, monero_port) = network_instance(NetworkId::Monero);
    let mut monero_processor_composition =
      processor_instance(NetworkId::Monero, monero_port, message_queue_keys[&NetworkId::Monero]);
    assert_eq!(monero_processor_composition.len(), 1);
    let monero_processor_composition = monero_processor_composition.swap_remove(0);

    let coordinator_composition = coordinator_instance(name, coord_key);
    let serai_composition = serai_composition(name, false);

    // Give every item in this stack a unique ID
    // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
    let (first, unique_id) = {
      let first = *unique_id_lock == 0;
      let unique_id = *unique_id_lock;
      *unique_id_lock += 1;
      (first, unique_id)
    };

    let logs_path = fresh_logs_folder(first, "full-stack");

    let mut compositions = HashMap::new();
    let mut handles = HashMap::new();
    for (name, composition) in [
      ("message_queue", message_queue_composition),
      ("bitcoin", bitcoin_composition),
      ("bitcoin_processor", bitcoin_processor_composition),
      ("monero", monero_composition),
      ("monero_processor", monero_processor_composition),
      ("coordinator", coordinator_composition),
      ("serai", serai_composition),
    ] {
      let handle = format!("full_stack-{name}-{unique_id}");
      compositions.insert(
        name,
        composition
          .set_start_policy(StartPolicy::Strict)
          .set_handle(handle.clone())
          .set_log_options(Some(LogOptions {
            action: if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
              LogAction::Forward
            } else {
              LogAction::ForwardToFile { path: logs_path.clone() }
            },
            policy: LogPolicy::Always,
            source: LogSource::Both,
          })),
      );
      handles.insert(name, handle);
    }

    let handles = Handles {
      message_queue: handles.remove("message_queue").unwrap(),
      bitcoin: (handles.remove("bitcoin").unwrap(), bitcoin_port),
      bitcoin_processor: handles.remove("bitcoin_processor").unwrap(),
      monero: (handles.remove("monero").unwrap(), monero_port),
      monero_processor: handles.remove("monero_processor").unwrap(),
      serai: handles.remove("serai").unwrap(),
    };

    {
      let bitcoin_processor_composition = compositions.get_mut("bitcoin_processor").unwrap();
      bitcoin_processor_composition
        .inject_container_name(handles.message_queue.clone(), "MESSAGE_QUEUE_RPC");
      bitcoin_processor_composition
        .inject_container_name(handles.bitcoin.0.clone(), "NETWORK_RPC_HOSTNAME");
    }

    {
      let monero_processor_composition = compositions.get_mut("monero_processor").unwrap();
      monero_processor_composition
        .inject_container_name(handles.message_queue.clone(), "MESSAGE_QUEUE_RPC");
      monero_processor_composition
        .inject_container_name(handles.monero.0.clone(), "NETWORK_RPC_HOSTNAME");
    }

    coordinator_compositions.push(compositions.remove("coordinator").unwrap());

    all_handles.push(handles);
    for (_, composition) in compositions {
      test.provide_container(composition);
    }
  }

  struct Context {
    pending_coordinator_compositions: Mutex<Vec<TestBodySpecification>>,
    handles: Vec<Handles>,
    test_body: Box<dyn TestBody>,
  }
  static CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();
  *CONTEXT.get_or_init(|| Mutex::new(None)).lock().await = Some(Context {
    pending_coordinator_compositions: Mutex::new(coordinator_compositions),
    handles: all_handles,
    test_body: Box::new(test_body),
  });

  // The DockerOperations from the first invocation, containing the Message Queue servers and the
  // Serai nodes.
  static OUTER_OPS: OnceLock<Mutex<Option<DockerOperations>>> = OnceLock::new();

  // Reset OUTER_OPS
  *OUTER_OPS.get_or_init(|| Mutex::new(None)).lock().await = None;

  // Spawns a coordinator, if one has yet to be spawned, or else runs the test.
  pub(crate) fn spawn_coordinator_or_run_test(
    inner_ops: DockerOperations,
  ) -> core::pin::Pin<Box<impl Send + Future<Output = ()>>> {
    Box::pin(async {
      // If the outer operations have yet to be set, these *are* the outer operations
      let outer_ops = OUTER_OPS.get().unwrap();
      if outer_ops.lock().await.is_none() {
        *outer_ops.lock().await = Some(inner_ops);
      }

      let context_lock = CONTEXT.get().unwrap().lock().await;
      let Context { pending_coordinator_compositions, handles, test_body } =
        context_lock.as_ref().unwrap();

      // Check if there is a coordinator left
      let maybe_coordinator = {
        let mut remaining = pending_coordinator_compositions.lock().await;
        let maybe_coordinator = if !remaining.is_empty() {
          let handles = handles[handles.len() - remaining.len()].clone();
          let composition = remaining.remove(0);
          Some((composition, handles))
        } else {
          None
        };
        drop(remaining);
        maybe_coordinator
      };

      if let Some((mut composition, handles)) = maybe_coordinator {
        let network = {
          let outer_ops = outer_ops.lock().await;
          let outer_ops = outer_ops.as_ref().unwrap();
          // Spawn it by building another DockerTest which recursively calls this function
          // TODO: Spawn this outside of DockerTest so we can remove the recursion
          let serai_container = outer_ops.handle(&handles.serai);
          composition.modify_env("SERAI_HOSTNAME", serai_container.ip());
          let message_queue_container = outer_ops.handle(&handles.message_queue);
          composition.modify_env("MESSAGE_QUEUE_RPC", message_queue_container.ip());

          format!("container:{}", serai_container.name())
        };
        let mut test = DockerTest::new().with_network(dockertest::Network::External(network));
        test.provide_container(composition);

        drop(context_lock);
        test.run_async(spawn_coordinator_or_run_test).await;
      } else {
        let outer_ops = outer_ops.lock().await.take().unwrap();
        test_body.body(outer_ops, handles.clone()).await;
      }
    })
  }

  test.run_async(spawn_coordinator_or_run_test).await;
}
