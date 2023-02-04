pub(crate) mod util;

mod key_gen;
pub(crate) use key_gen::test_key_gen;

mod scan;
pub(crate) use scan::test_scan;

mod signer;
pub(crate) use signer::test_signer;

mod send;
pub(crate) use send::test_send;

#[macro_export]
macro_rules! sequential {
  () => {
    lazy_static::lazy_static! {
      static ref SEQUENTIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
    }
  };
}

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = SEQUENTIAL.lock().await;
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

mod literal;
