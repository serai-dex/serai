pub(crate) mod util;

mod key_gen;
pub(crate) use key_gen::test_key_gen;

mod scanner;
pub(crate) use scanner::test_scanner;

mod signer;
pub(crate) use signer::{sign, test_signer};

mod wallet;
pub(crate) use wallet::test_wallet;

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

#[macro_export]
macro_rules! test_coin {
  ($coin: ident, $scanner: ident, $signer: ident, $wallet: ident) => {
    use $crate::tests::{test_scanner, test_signer, test_wallet};

    sequential!();

    async_sequential! {
      async fn $scanner() {
        test_scanner($coin().await).await;
      }
    }

    async_sequential! {
      async fn $signer() {
        test_signer($coin().await).await;
      }
    }

    async_sequential! {
      async fn $wallet() {
        test_wallet($coin().await).await;
      }
    }
  };
}

mod literal;
