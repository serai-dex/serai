use std::sync::{Arc, Mutex};

use futures::StreamExt;

use in_instructions::{InInstruction, Batch, PendingBatch, Coin};

use jsonrpsee_core::server::rpc_module::RpcModule;

use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  let id = Arc::new(Mutex::new(0));

  let mut rpc = RpcModule::new(id.clone());
  rpc
    .register_async_method("processor_coins", |_, id| async move {
      let batch = Batch {
        id: id.lock().unwrap().clone(),
        instructions: vec![InInstruction { destination: [0xff; 32], amount: 1, data: vec![] }],
      };

      let height = Serai::height().await.unwrap();
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
    dbg!(batches.next().await.unwrap().unwrap());
    *id.lock().unwrap() += 1;
  }
}
