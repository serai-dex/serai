use core::time::Duration;

use lazy_static::lazy_static;

use tokio::{sync::Mutex, time::sleep};

use serai_client::{
  subxt::config::Header,
  in_instructions::{primitives::SignedBatch, InInstructionsEvent},
  Serai,
};

pub const URL: &str = "ws://127.0.0.1:9944";

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[allow(dead_code)]
pub async fn provide_batch(batch: SignedBatch) -> [u8; 32] {
  let serai = Serai::new(URL).await.unwrap();

  let mut latest = serai
    .get_block(serai.get_latest_block_hash().await.unwrap())
    .await
    .unwrap()
    .unwrap()
    .header
    .number();

  let execution = serai.execute_batch(batch.clone()).unwrap();
  serai.publish(&execution).await.unwrap();

  // Get the block it was included in
  let mut block;
  let mut ticks = 0;
  'get_block: loop {
    latest += 1;

    block = {
      let mut block;
      while {
        block = serai.get_block_by_number(latest).await.unwrap();
        block.is_none()
      } {
        sleep(Duration::from_secs(1)).await;
        ticks += 1;

        if ticks > 60 {
          panic!("60 seconds without inclusion in a finalized block");
        }
      }
      block.unwrap()
    };

    for extrinsic in block.extrinsics {
      if extrinsic.0 == execution.0[2 ..] {
        break 'get_block;
      }
    }
  }
  let block = block.header.hash().into();

  let batches = serai.get_batch_events(block).await.unwrap();
  // TODO: impl From<Batch> for BatchEvent?
  assert_eq!(
    batches,
    vec![InInstructionsEvent::Batch {
      network: batch.batch.network,
      id: batch.batch.id,
      block: batch.batch.block,
    }],
  );

  // TODO: Check the tokens events

  block
}

#[macro_export]
macro_rules! serai_test {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        use std::process::Command;

        let guard = runner::SEQUENTIAL.lock().await;

        let is_running = || {
          !Command::new("pidof").arg("serai-node").output().unwrap().stdout.is_empty()
        };

        // Spawn a fresh Serai node
        let mut command = {
          use core::time::Duration;
          use std::path::Path;

          // Make sure a node isn't already running
          assert!(!is_running());

          let node = {
            let this_crate = Path::new(env!("CARGO_MANIFEST_DIR"));
            let top_level = this_crate.join("../../../");
            top_level.join("target/debug/serai-node")
          };

          let command = Command::new(node).arg("--dev").spawn().unwrap();
          while Serai::new(URL).await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
          }
          while Serai::new(URL).await.unwrap().get_latest_block_hash().await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
          }
          // TODO: https://github.com/serai-dex/serai/247
          if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
            tokio::time::sleep(Duration::from_secs(60)).await;
          }

          // Sanity check the pidof command is well-formed
          assert!(is_running());

          command
        };

        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            let _ = command.kill();
            Err(err).unwrap()
          } else {
            command.kill().unwrap();
          }
          assert!(!is_running());
        }).await;
      }
    )*
  }
}
