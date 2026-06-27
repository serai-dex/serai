// We compile this as a module, yet Rust will also compile it as a standalone 'test', hence this
#![allow(dead_code)]

use std::sync::LazyLock;

use bitcoin_serai::rpc::Rpc;

use tokio::sync::Mutex;

pub(crate) static SEQUENTIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub(crate) async fn rpc() -> Rpc {
  let rpc = Rpc::new("http://serai:seraidex@127.0.0.1:8332".to_owned()).await.unwrap();

  // If this node has already been interacted with, clear its chain
  if rpc.get_latest_block_number().await.unwrap() > 0 {
    rpc
      .call::<()>(
        "invalidateblock",
        &format!(
          r#"["{}"]"#,
          bitcoin::consensus::encode::serialize_hex(&{
            let mut hash = rpc.get_block_hash(1).await.unwrap();
            hash.reverse();
            hash
          })
        ),
      )
      .await
      .unwrap();
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
