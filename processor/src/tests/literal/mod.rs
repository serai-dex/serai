mod key_gen;

mod bitcoin {
  use crate::coin::Bitcoin;

  async fn bitcoin() -> Bitcoin {
    let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await;
    bitcoin.fresh_chain().await;
    bitcoin
  }

  test_coin!(bitcoin, bitcoin_scanner, bitcoin_signer, bitcoin_wallet);
}

mod monero {
  use crate::coin::{Coin, Monero};

  async fn monero() -> Monero {
    let monero = Monero::new("http://127.0.0.1:18081".to_string()).await;
    while monero.get_latest_block_number().await.unwrap() < 150 {
      monero.mine_block().await;
    }
    monero
  }

  test_coin!(monero, monero_scanner, monero_signer, monero_wallet);
}
