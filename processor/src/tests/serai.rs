use core::time::Duration;
use std::sync::{Arc, Mutex};

use serai_primitives::{BlockNumber, NativeAddress};

use in_instructions_primitives::{ExternalAddress, Target, InInstruction};
use in_instructions_pallet::{Batch, Update};

use jsonrpsee_core::server::rpc_module::RpcModule;

use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  let next_id = Arc::new(Mutex::new(0));

  let mut rpc = RpcModule::new(next_id.clone());
  rpc
    .register_async_method("processor_coinUpdates", |_, context| async move {
      tokio::time::sleep(Duration::from_millis(1000)).await;
      let batch = Batch {
        id: *context.lock().unwrap(),
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
    let batches = serai.get_batches(Serai::get_latest_block_hash().await.unwrap()).await.unwrap();
    if let Some(batch) = batches.get(0) {
      *next_id.lock().unwrap() = dbg!(batch).id + 1;
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
  }
}
