use core::future::Future;
use std::{
  sync::{Mutex, OnceLock},
  fs,
};

use tokio::sync::Mutex;

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification,
  DockerOperations, DockerTest,
};

use crate::*;

mod key_gen;
pub use key_gen::key_gen;

mod batch;
pub use batch::batch;

mod sign;
#[allow(unused_imports)]
pub use sign::sign;

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

pub(crate) async fn new_test(test_body: impl TestBody) {
  let mut unique_id_lock = UNIQUE_ID.get_or_init(|| Mutex::new(0)).lock();

  let mut coordinators = vec![];
  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  let mut coordinator_compositions = vec![];
  for i in 0 .. COORDINATORS {
    let name = match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    };
    let serai_composition = serai_composition(name);

    let (coord_key, message_queue_keys, message_queue_composition) =
      serai_message_queue_tests::instance();

    let coordinator_composition = coordinator_instance(name, coord_key);

    // Give every item in this stack a unique ID
    // Uses a Mutex as we can't generate a 8-byte random ID without hitting hostname length limits
    let (first, unique_id) = {
      let first = *unique_id_lock == 0;
      let unique_id = *unique_id_lock;
      *unique_id_lock += 1;
      (first, unique_id)
    };

    let logs_path =
      [std::env::current_dir().unwrap().to_str().unwrap(), ".test-logs", "coordinator"]
        .iter()
        .collect::<std::path::PathBuf>();
    if first {
      let _ = fs::remove_dir_all(&logs_path);
      fs::create_dir_all(&logs_path).expect("couldn't create logs directory");
      assert!(
        fs::read_dir(&logs_path).expect("couldn't read the logs folder").next().is_none(),
        "logs folder wasn't empty, despite removing it at the start of the run",
      );
    }
    let logs_path = logs_path.to_str().unwrap().to_string();

    let mut compositions = vec![];
    let mut handles = vec![];
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

      handles.push(handle);
    }

    let coord_key = message_queue_keys[&NetworkId::Bitcoin];

    coordinators.push(((handles[0].clone(), handles[1].clone()), coord_key));
    coordinator_compositions.push(compositions.pop().unwrap());
    for composition in compositions {
      test.provide_container(composition);
    }
  }

  static COORDINATOR_COMPOSITIONS: OnceLock<Mutex<Vec<TestBodySpecification>>> = OnceLock::new();
  COORDINATOR_COMPOSITIONS.set(Mutex::new(coordinator_compositions)).map_err(|_| ()).unwrap();

  struct Context {
    handles_and_keys: Vec<((String, String), <Ristretto as Ciphersuite>::F)>,
    test_body: Box<dyn TestBody>,
  }
  static CONTEXT: OnceLock<Context> = OnceLock::new();
  CONTEXT
    .set(Context { handles_and_keys: coordinators, test_body: Box::new(test_body) })
    .map_err(|_| ())
    .unwrap();

  static OUTER_OPS: OnceLock<DockerOperations> = OnceLock::new();

  #[async_recursion::async_recursion]
  async fn spawn_coordinator_or_run_test(inner_ops: DockerOperations) {
    let outer_ops = OUTER_OPS.get_or_init(|| inner_ops);

    let Context { handles_and_keys: coordinators, test_body } = CONTEXT.get().unwrap();

    // Now that the Message Queue and Node containers have spawned, spawn the coordinator if there
    // are ones left to spawn
    // If not, run the test body
    let maybe_composition_and_handles = {
      let mut remaining = COORDINATOR_COMPOSITIONS.get().unwrap().lock().unwrap();
      let maybe_composition_and_handles = if !remaining.is_empty() {
        let handles = coordinators[coordinators.len() - remaining.len()].0.clone();
        let composition = remaining.remove(0);
        Some((composition, handles))
      } else {
        None
      };
      drop(remaining);
      maybe_composition_and_handles
    };
    if let Some((mut composition, handles)) = maybe_composition_and_handles {
      let serai_container = outer_ops.handle(&handles.0);
      composition.modify_env("SERAI_HOSTNAME", serai_container.ip());
      let message_queue_container = outer_ops.handle(&handles.1);
      composition.modify_env("MESSAGE_QUEUE_RPC", message_queue_container.ip());
      let mut test = DockerTest::new().with_network(dockertest::Network::External(format!(
        "container:{}",
        serai_container.name()
      )));
      test.provide_container(composition);

      // Recurse until none remain
      test.run_async(spawn_coordinator_or_run_test).await;
    } else {
      // Wait for the Serai node to boot, and for the Tendermint chain to get past the first block
      // TODO: Replace this with a Coordinator RPC
      tokio::time::sleep(Duration::from_secs(150)).await;

      // Sleep even longer if in the CI due to it being slower than commodity hardware
      if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
        tokio::time::sleep(Duration::from_secs(120)).await;
      }

      // Connect to the Message Queues as the processor
      let mut processors: Vec<Processor> = vec![];
      for (i, (handles, key)) in coordinators.iter().enumerate() {
        processors.push(
          Processor::new(
            i.try_into().unwrap(),
            NetworkId::Bitcoin,
            outer_ops,
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
