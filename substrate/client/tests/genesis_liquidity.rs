use serai_client::Serai;

mod common;
use common::genesis_liquidity::test_genesis_liquidity;

serai_test_fast_epoch!(
  genesis_liquidity: (|serai: Serai| async move {
    test_genesis_liquidity(serai).await;
  })
);
