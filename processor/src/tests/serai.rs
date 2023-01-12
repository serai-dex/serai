use core::time::Duration;
use std::sync::{Arc, Mutex};

use serai_primitives::NativeAddress;

use in_instructions_primitives::{ExternalAddress, Target, InInstruction};
use in_instructions_pallet::{Batch, PendingBatch, Coin};

use jsonrpsee_core::server::rpc_module::RpcModule;

use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  let next_id = Arc::new(Mutex::new(0));

  let mut rpc = RpcModule::new(next_id.clone());
  rpc
    .register_async_method("processor_coins", |_, context| async move {
      tokio::time::sleep(Duration::from_millis(1500)).await;
      let batch = Batch {
        id: *context.lock().unwrap(),
        instructions: vec![InInstruction {
          origin: ExternalAddress::new(b"external".to_vec()).unwrap(),
          target: Target::Address(NativeAddress::from_raw([0xff; 32])),
        }],
      };
      println!("Offering batch {}", batch.id);

      // Re-use the batch ID as the Substrate block we reported at
      let serai_block_number = batch.id;
      // Just set the coin block number to a distinct, incremental number
      let coin_block_number = batch.id + 100;

      let pending = PendingBatch { reported_at: serai_block_number, batch };

      let coin = Coin { block_number: coin_block_number, batches: vec![pending] };

      Ok(vec![Some(coin)])
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
    let batches = serai.get_batches(Serai::get_latest_block_hash().await.unwrap()).await.unwrap();
    if let Some(batch) = batches.get(0) {
      *next_id.lock().unwrap() = dbg!(batch).id + 1;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
}
