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
macro_rules! test_network {
  (
    $N: ident,
    $docker: ident,
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

    // This doesn't interact with a node and accordingly doesn't need to be run
    #[tokio::test]
    async fn $key_gen() {
      test_key_gen::<$N>().await;
    }

    #[test]
    fn $scanner() {
      let docker = $docker();
      docker.run(|ops| async move {
        test_scanner($network(&ops).await).await;
      });
    }

    #[test]
    fn $signer() {
      let docker = $docker();
      docker.run(|ops| async move {
        test_signer($network(&ops).await).await;
      });
    }

    #[test]
    fn $wallet() {
      let docker = $docker();
      docker.run(|ops| async move {
        test_wallet($network(&ops).await).await;
      });
    }

    #[test]
    fn $addresses() {
      let docker = $docker();
      docker.run(|ops| async move {
        test_addresses($network(&ops).await).await;
      });
    }

    #[test]
    fn $no_deadlock_in_multisig_completed() {
      let docker = $docker();
      docker.run(|ops| async move {
        test_no_deadlock_in_multisig_completed($network(&ops).await).await;
      });
    }
  };
}

mod literal;
