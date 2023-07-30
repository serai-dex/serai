#[cfg(feature = "bitcoin")]
mod bitcoin {
  use crate::networks::Bitcoin;

  async fn bitcoin() -> Bitcoin {
    let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await;
    bitcoin.fresh_chain().await;
    bitcoin
  }

  test_network!(
    Bitcoin,
    bitcoin,
    bitcoin_key_gen,
    bitcoin_scanner,
    bitcoin_signer,
    bitcoin_wallet,
    bitcoin_addresses,
  );
}

#[cfg(feature = "monero")]
mod monero {
  use crate::networks::{Network, Monero};

  async fn monero() -> Monero {
    let monero = Monero::new("http://127.0.0.1:18081".to_string());
    while monero.get_latest_block_number().await.unwrap() < 150 {
      monero.mine_block().await;
    }
    monero
  }

  test_network!(
    Monero,
    monero,
    monero_key_gen,
    monero_scanner,
    monero_signer,
    monero_wallet,
    monero_addresses,
  );
}
