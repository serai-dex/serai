use futures::StreamExt;

use in_instructions::{InInstruction, Batch, PendingBatch, Coin};

use jsonrpsee_core::server::rpc_module::RpcModule;

use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  Serai::new().await;

  let mut rpc = RpcModule::new(());
  rpc
    .register_async_method("processor_coins", |_, _| async move {
      let batch = Batch {
        id: 0,
        instructions: vec![InInstruction { destination: [0xff; 32], amount: 1, data: vec![] }],
      };

      let height = Serai::height().await.unwrap();
      let pending = PendingBatch { reported_at: height, batch };

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

  let mut batches = Serai::batches().await.unwrap();
  loop {
    dbg!(batches.next().await.unwrap().unwrap());
  }
}
