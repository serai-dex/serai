#[cfg(feature = "bitcoin")]
mod bitcoin {
  use crate::coins::Bitcoin;

  async fn bitcoin() -> Bitcoin {
    let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string());
    bitcoin.fresh_chain().await;
    bitcoin
  }

  test_coin!(Bitcoin, bitcoin, bitcoin_key_gen, bitcoin_scanner, bitcoin_signer, bitcoin_wallet);
}

#[cfg(feature = "monero")]
mod monero {
  use crate::coins::{Coin, Monero};

  async fn monero() -> Monero {
    let monero = Monero::new("http://127.0.0.1:18081".to_string());
    while monero.get_latest_block_number().await.unwrap() < 150 {
      monero.mine_block().await;
    }
    monero
  }

  test_coin!(Monero, monero, monero_key_gen, monero_scanner, monero_signer, monero_wallet);
}
