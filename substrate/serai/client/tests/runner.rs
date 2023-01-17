use lazy_static::lazy_static;

use tokio::sync::Mutex;

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
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

          let this_crate = Path::new(env!("CARGO_MANIFEST_DIR"));
          let top_level = this_crate.join("../../../");
          let node = top_level.join("target/debug/serai-node");
          dbg!(node.clone());
          let command = Command::new(node).arg("--dev").spawn().unwrap();
          while Serai::new().await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
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
