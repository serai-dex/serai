use core::future::Future;
use std::{sync::OnceLock, collections::HashMap};

use tokio::sync::Mutex;

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification,
  DockerOperations, DockerTest,
};

use serai_docker_tests::fresh_logs_folder;

use crate::*;

mod key_gen;
pub use key_gen::key_gen;

mod batch;
pub use batch::batch;

mod sign;
#[allow(unused_imports)]
pub use sign::sign;

mod rotation;

pub(crate) const COORDINATORS: usize = 4;
pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

// Provide a unique ID and ensures only one invocation occurs at a time.
static UNIQUE_ID: OnceLock<Mutex<u16>> = OnceLock::new();

#[async_trait::async_trait]
pub(crate) trait TestBody: 'static + Send + Sync {
  async fn body(&self, processors: Vec<Processor>);
}
#[async_trait::async_trait]
impl<F: Send + Future, TB: 'static + Send + Sync + Fn(Vec<Processor>) -> F> TestBody for TB {
  async fn body(&self, processors: Vec<Processor>) {
    (self)(processors).await;
  }
}

pub(crate) async fn new_test(test_body: impl TestBody, fast_epoch: bool) {
  let mut unique_id_lock = UNIQUE_ID.get_or_init(|| Mutex::new(0)).lock().await;

  let mut coordinators = vec![];
  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  let mut coordinator_compositions = vec![];
  // Spawn one extra coordinator which isn't in-set
  #[allow(clippy::range_plus_one)]
  for i in 0 .. (COORDINATORS + 1) {
    let name = match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    };
    let serai_composition = serai_composition(name, fast_epoch);

    let (processor_key, message_queue_keys, message_queue_composition) =
      serai_message_queue_tests::instance();

    let coordinator_composition = coordinator_instance(name, processor_key);

    // Give every item in this stack a unique ID
    // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
    let (first, unique_id) = {
      let first = *unique_id_lock == 0;
      let unique_id = *unique_id_lock;
      *unique_id_lock += 1;
      (first, unique_id)
    };

    let logs_path = fresh_logs_folder(first, "coordinator");

    let mut compositions = vec![];
    let mut handles = HashMap::new();
    for (name, composition) in [
      ("serai_node", serai_composition),
      ("message_queue", message_queue_composition),
      ("coordinator", coordinator_composition),
    ] {
      let handle = format!("coordinator-{name}-{unique_id}");

      compositions.push(
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

    let processor_key = message_queue_keys[&NetworkId::Bitcoin];

    coordinators.push((
      Handles {
        serai: handles.remove("serai_node").unwrap(),
        message_queue: handles.remove("message_queue").unwrap(),
      },
      processor_key,
    ));
    coordinator_compositions.push(compositions.pop().unwrap());
    for composition in compositions {
      test.provide_container(composition);
    }
  }

  struct Context {
    pending_coordinator_compositions: Mutex<Vec<TestBodySpecification>>,
    handles_and_keys: Vec<(Handles, <Ristretto as Ciphersuite>::F)>,
    test_body: Box<dyn TestBody>,
  }
  static CONTEXT: OnceLock<Mutex<Option<Context>>> = OnceLock::new();
  *CONTEXT.get_or_init(|| Mutex::new(None)).lock().await = Some(Context {
    pending_coordinator_compositions: Mutex::new(coordinator_compositions),
    handles_and_keys: coordinators,
    test_body: Box::new(test_body),
  });

  // The DockerOperations from the first invocation, containing the Message Queue servers and the
  // Serai nodes.
  static OUTER_OPS: OnceLock<Mutex<Option<DockerOperations>>> = OnceLock::new();

  // Reset OUTER_OPS
  *OUTER_OPS.get_or_init(|| Mutex::new(None)).lock().await = None;

  // Spawns a coordinator, if one has yet to be spawned, or else runs the test.
  async fn spawn_coordinator_or_run_test(inner_ops: DockerOperations) {
    // If the outer operations have yet to be set, these *are* the outer operations
    let outer_ops = OUTER_OPS.get().unwrap();
    if outer_ops.lock().await.is_none() {
      *outer_ops.lock().await = Some(inner_ops);
    }

    let context_lock = CONTEXT.get().unwrap().lock().await;
    let Context { pending_coordinator_compositions, handles_and_keys: coordinators, test_body } =
      context_lock.as_ref().unwrap();

    // Check if there is a coordinator left
    let maybe_coordinator = {
      let mut remaining = pending_coordinator_compositions.lock().await;
      let maybe_coordinator = if !remaining.is_empty() {
        let handles = coordinators[coordinators.len() - remaining.len()].0.clone();
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
      fn recurse(ops: DockerOperations) -> core::pin::Pin<Box<impl Send + Future<Output = ()>>> {
        Box::pin(spawn_coordinator_or_run_test(ops))
      }
      test.run_async(recurse).await;
    } else {
      let outer_ops = outer_ops.lock().await.take().unwrap();

      // Wait for the Serai node to boot, and for the Tendermint chain to get past the first block
      // TODO: Replace this with a Coordinator RPC we can query
      tokio::time::sleep(Duration::from_secs(60)).await;

      // Connect to the Message Queues as the processor
      let mut processors: Vec<Processor> = vec![];
      for (i, (handles, key)) in coordinators.iter().enumerate() {
        processors.push(
          Processor::new(
            i.try_into().unwrap(),
            NetworkId::Bitcoin,
            &outer_ops,
            handles.clone(),
            *key,
          )
          .await,
        );
      }

      test_body.body(processors).await;
    }
  }

  test.run_async(spawn_coordinator_or_run_test).await;
}

// TODO: Don't use a pessimistic sleep
// Use an RPC to enaluate if a condition was met, with the following time being a timeout
// https://github.com/serai-dex/serai/issues/340
pub(crate) async fn wait_for_tributary() {
  tokio::time::sleep(Duration::from_secs(15)).await;
  if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
    tokio::time::sleep(Duration::from_secs(6)).await;
  }
}
