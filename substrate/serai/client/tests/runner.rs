use core::time::Duration;
use std::sync::Arc;

use lazy_static::lazy_static;

use tokio::{sync::Mutex, time::sleep};

use serai_runtime::in_instructions::Update;
use serai_client::{primitives::Coin, in_instructions::InInstructionsEvent, Serai};

use jsonrpsee_server::RpcModule;

pub const URL: &str = "ws://127.0.0.1:9944";

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[allow(dead_code)]
pub async fn provide_updates(updates: Vec<Option<Update>>) -> [u8; 32] {
  let done = Arc::new(Mutex::new(false));
  let done_clone = done.clone();
  let updates_clone = updates.clone();

  let mut rpc = RpcModule::new(());
  rpc
    .register_async_method("processor_coinUpdates", move |_, _| {
      let done_clone = done_clone.clone();
      let updates_clone = updates_clone.clone();
      async move {
        // Sleep to prevent a race condition where we submit the inherents for this block and the
        // next one, then remove them, making them unverifiable, causing the node to panic for
        // being self-malicious
        sleep(Duration::from_millis(500)).await;
        if !*done_clone.lock().await {
          Ok(updates_clone)
        } else {
          Ok(vec![])
        }
      }
    })
    .unwrap();
  let _handle = jsonrpsee_server::ServerBuilder::default()
    .build("127.0.0.1:5134")
    .await
    .unwrap()
    .start(rpc)
    .unwrap();

  let serai = Serai::new(URL).await.unwrap();
  loop {
    let latest = serai.get_latest_block_hash().await.unwrap();
    let mut batches = serai.get_batch_events(latest).await.unwrap();
    if batches.is_empty() {
      sleep(Duration::from_millis(50)).await;
      continue;
    }
    *done.lock().await = true;

    for (index, update) in updates.iter().enumerate() {
      if let Some(update) = update {
        let coin_by_index = Coin(u32::try_from(index).unwrap() + 1);

        for expected in &update.batches {
          match batches.swap_remove(0) {
            InInstructionsEvent::Batch { coin, id } => {
              assert_eq!(coin, coin_by_index);
              assert_eq!(expected.id, id);
            }
            _ => panic!("get_batches returned non-batch"),
          }
        }
        assert_eq!(
          serai.get_coin_block_number(coin_by_index, latest).await.unwrap(),
          update.block_number
        );
      }
    }
    // This will fail if there were more batch events than expected
    assert!(batches.is_empty());

    return latest;
  }
}

#[macro_export]
macro_rules! serai_test {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.lock().await;

        // Spawn a fresh Serai node
        let mut command = {
          use core::time::Duration;
          use std::{path::Path, process::Command};

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
        }).await;
      }
    )*
  }
}
