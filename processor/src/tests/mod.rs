mod key_gen;
pub(crate) use key_gen::test_key_gen;

mod scanner;
pub(crate) use scanner::{test_scanner, test_no_deadlock_in_multisig_completed};

mod signer;
pub(crate) use signer::{sign, test_signer};

mod substrate_signer;

mod wallet;
pub(crate) use wallet::test_wallet;

mod addresses;
pub(crate) use addresses::test_addresses;

// Effective Once
lazy_static::lazy_static! {
  static ref INIT_LOGGER: () = env_logger::init();
}

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
        *$crate::tests::INIT_LOGGER;
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
macro_rules! test_network {
  (
    $N: ident,
    $network: ident,
    $key_gen: ident,
    $scanner: ident,
    $signer: ident,
    $wallet: ident,
    $addresses: ident,
    $no_deadlock_in_multisig_completed: ident,
  ) => {
    use $crate::tests::{
      test_key_gen, test_scanner, test_no_deadlock_in_multisig_completed, test_signer, test_wallet,
      test_addresses,
    };

    // This doesn't interact with a node and accordingly doesn't need to be run sequentially
    #[tokio::test]
    async fn $key_gen() {
      test_key_gen::<$N>().await;
    }

    sequential!();

    async_sequential! {
      async fn $scanner() {
        test_scanner($network().await).await;
      }
    }

    async_sequential! {
      async fn $signer() {
        test_signer($network().await).await;
      }
    }

    async_sequential! {
      async fn $wallet() {
        test_wallet($network().await).await;
      }
    }

    async_sequential! {
      async fn $addresses() {
        test_addresses($network().await).await;
      }
    }

    async_sequential! {
      async fn $no_deadlock_in_multisig_completed() {
        test_no_deadlock_in_multisig_completed($network().await).await;
      }
    }
  };
}

mod literal;
