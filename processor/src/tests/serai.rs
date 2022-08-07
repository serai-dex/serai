use std::sync::{Arc, Mutex};

use futures::StreamExt;

use in_instructions::{InInstruction, Batch, PendingBatch, Coin};

use jsonrpsee_core::server::rpc_module::RpcModule;

use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  let height = Arc::new(Mutex::new(Serai::height().await.unwrap() + 2));
  let next_id = Arc::new(Mutex::new(0));

  let mut rpc = RpcModule::new((height.clone(), next_id.clone()));
  rpc
    .register_async_method("processor_coins", |_, context| async move {
      let mut batch = Batch {
        id: context.1.lock().unwrap().clone(),
        instructions: vec![InInstruction { destination: [0xff; 32], amount: 1, data: vec![] }],
      };

      let height = Serai::height().await.unwrap();
      // Workaround for the delay in the notifications subscription
      if *context.0.lock().unwrap() < height {
        batch.id += 1;
      }
      // Subtract by 2 for now to bypass the delay period in this naive queue
      let pending = PendingBatch { reported_at: height - 2, batch };

      let coin_height = height + 100;
      let coin = Coin { height: coin_height, batches: vec![pending] };

      Ok(vec![Some(coin)])
    })
    .unwrap();

  let _handle = jsonrpsee_http_server::HttpServerBuilder::default()
    .build("127.0.0.1:5134")
    .await
    .unwrap()
    .start(rpc)
    .unwrap();

  let serai = Serai::new().await;
  let mut batches = serai.batches().await.unwrap();
  loop {
    *next_id.lock().unwrap() = dbg!(batches.next().await.unwrap().unwrap()).event.1 + 1;
    *height.lock().unwrap() = Serai::height().await.unwrap();
  }
}
