use lazy_static::lazy_static;

use tokio::sync::Mutex;

use serai_client::Serai;

pub mod tx;
pub mod validator_sets;
pub mod in_instructions;

pub const URL: &str = "ws://127.0.0.1:9944";

pub async fn serai() -> Serai {
  Serai::new(URL).await.unwrap()
}

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[macro_export]
macro_rules! serai_test {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        use std::process::Command;

        let guard = common::SEQUENTIAL.lock().await;

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
          while Serai::new(common::URL).await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
          }
          let serai = serai().await;
          while serai.get_latest_block_hash().await.is_err() {
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
