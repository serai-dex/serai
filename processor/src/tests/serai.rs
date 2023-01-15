use core::time::Duration;
use std::process::Command;

use lazy_static::lazy_static;

use tokio::sync::Mutex;

use serai_runtime::{
  primitives::{BlockNumber, NativeAddress},
  in_instructions::{
    primitives::{ExternalAddress, Target, InInstruction},
    Batch, Update,
  },
};

use jsonrpsee_server::RpcModule;

use crate::serai::{InInstructionsEvent, Serai};

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[macro_export]
macro_rules! serai_test {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = SEQUENTIAL.lock().await;

        // Spawn a fresh Serai node
        let mut command = Command::new("../target/debug/serai-node").arg("--dev").spawn().unwrap();
        {
          while Serai::new().await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
          }
        }

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

serai_test!(
  async fn publish_update() {
    let mut rpc = RpcModule::new(());
    rpc
      .register_async_method("processor_coinUpdates", |_, _| async move {
        let batch = Batch {
          id: 0,
          instructions: vec![InInstruction {
            origin: ExternalAddress::new(b"external".to_vec()).unwrap(),
            target: Target::Address(NativeAddress::from_raw([0xff; 32])),
          }],
        };

        Ok(vec![Some(Update { block_number: BlockNumber(100), batches: vec![batch] })])
      })
      .unwrap();

    let _handle = jsonrpsee_server::ServerBuilder::default()
      .build("127.0.0.1:5134")
      .await
      .unwrap()
      .start(rpc)
      .unwrap();

    let serai = Serai::new().await.unwrap();
    loop {
      let batches =
        serai.get_batch_events(serai.get_latest_block_hash().await.unwrap()).await.unwrap();
      if let Some(batch) = batches.get(0) {
        match batch {
          InInstructionsEvent::Batch { .. } => {
            return;
          }
          _ => panic!("get_batches returned non-batch"),
        }
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
  }
);
