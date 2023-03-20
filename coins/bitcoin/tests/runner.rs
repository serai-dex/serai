use bitcoin_serai::rpc::Rpc;

use tokio::sync::Mutex;

lazy_static::lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[allow(dead_code)]
pub(crate) async fn rpc() -> Rpc {
  let rpc = Rpc::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await.unwrap();

  // If this node has already been interacted with, clear its chain
  if rpc.get_latest_block_number().await.unwrap() > 0 {
    rpc
      .rpc_call(
        "invalidateblock",
        serde_json::json!([hex::encode(rpc.get_block_hash(1).await.unwrap())]),
      )
      .await
      .unwrap()
  }

  rpc
}

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.lock().await;
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}
