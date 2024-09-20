// TODO

use std::sync::OnceLock;

mod key_gen;

mod scanner;

mod signer;
pub(crate) use signer::sign;

mod cosigner;
mod batch_signer;

mod wallet;

mod addresses;

// Effective Once
static INIT_LOGGER_CELL: OnceLock<()> = OnceLock::new();
fn init_logger() {
  *INIT_LOGGER_CELL.get_or_init(env_logger::init)
}

#[macro_export]
macro_rules! test_network {
  (
    $N: ty,
    $docker: ident,
    $network: ident,
    $key_gen: ident,
    $scanner: ident,
    $no_deadlock_in_multisig_completed: ident,
    $signer: ident,
    $wallet: ident,
  ) => {
    use core::{pin::Pin, future::Future};
    use $crate::tests::{
      init_logger,
      key_gen::test_key_gen,
      scanner::{test_scanner, test_no_deadlock_in_multisig_completed},
      signer::test_signer,
      wallet::test_wallet,
    };

    // This doesn't interact with a node and accordingly doesn't need to be spawn one
    #[tokio::test]
    async fn $key_gen() {
      init_logger();
      test_key_gen::<$N>();
    }

    #[test]
    fn $scanner() {
      init_logger();
      let docker = $docker();
      docker.run(|ops| async move {
        let new_network = $network(&ops).await;
        test_scanner(new_network).await;
      });
    }

    #[test]
    fn $no_deadlock_in_multisig_completed() {
      init_logger();
      let docker = $docker();
      docker.run(|ops| async move {
        let new_network = $network(&ops).await;
        test_no_deadlock_in_multisig_completed(new_network).await;
      });
    }

    #[test]
    fn $signer() {
      init_logger();
      let docker = $docker();
      docker.run(|ops| async move {
        let new_network = $network(&ops).await;
        test_signer(new_network).await;
      });
    }

    #[test]
    fn $wallet() {
      init_logger();
      let docker = $docker();
      docker.run(|ops| async move {
        let new_network = $network(&ops).await;
        test_wallet(new_network).await;
      });
    }
  };
}

#[macro_export]
macro_rules! test_utxo_network {
  (
    $N: ty,
    $docker: ident,
    $network: ident,
    $key_gen: ident,
    $scanner: ident,
    $no_deadlock_in_multisig_completed: ident,
    $signer: ident,
    $wallet: ident,
    $addresses: ident,
  ) => {
    use $crate::tests::addresses::test_addresses;

    test_network!(
      $N,
      $docker,
      $network,
      $key_gen,
      $scanner,
      $no_deadlock_in_multisig_completed,
      $signer,
      $wallet,
    );

    #[test]
    fn $addresses() {
      init_logger();
      let docker = $docker();
      docker.run(|ops| async move {
        let new_network = $network(&ops).await;
        test_addresses(new_network).await;
      });
    }
  };
}

mod literal;
