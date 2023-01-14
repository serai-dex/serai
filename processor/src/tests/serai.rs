use core::time::Duration;
use std::{sync::Arc, process::Command};

use lazy_static::lazy_static;

use tokio::sync::Mutex;

use serai_primitives::{BlockNumber, NativeAddress};

use in_instructions_primitives::{ExternalAddress, Target, InInstruction};
use serai_runtime::in_instructions_pallet::{Batch, Update};

use jsonrpsee_core::server::rpc_module::RpcModule;

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
        while Serai::get_latest_block_hash().await.is_err() {
          tokio::time::sleep(Duration::from_secs(1)).await;
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
    let next_id = Arc::new(Mutex::new(0));

    let mut rpc = RpcModule::new(next_id.clone());
    rpc
      .register_async_method("processor_coinUpdates", |_, context| async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let batch = Batch {
          id: *context.lock().await,
          instructions: vec![InInstruction {
            origin: ExternalAddress::new(b"external".to_vec()).unwrap(),
            target: Target::Address(NativeAddress::from_raw([0xff; 32])),
          }],
        };
        println!("Offering batch {}", batch.id);

        // Re-use the batch ID as the coin's block number
        let coin_block_number = BlockNumber(u32::try_from(batch.id + 100).unwrap());

        let update = Update { block_number: coin_block_number, batches: vec![batch] };

        Ok(vec![Some(update)])
      })
      .unwrap();

    let _handle = jsonrpsee_server::ServerBuilder::default()
      .build("127.0.0.1:5134")
      .await
      .unwrap()
      .start(rpc)
      .unwrap();

    let serai = Serai::new().await;
    loop {
      let batches =
        serai.get_batch_events(Serai::get_latest_block_hash().await.unwrap()).await.unwrap();
      if let Some(batch) = batches.get(0) {
        match batch {
          InInstructionsEvent::Batch { id, .. } => {
            *next_id.lock().await = dbg!(id + 1);
            return;
          }
          _ => panic!("get_batches returned non-batch"),
        }
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
  }
);
