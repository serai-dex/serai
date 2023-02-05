use crate::{
  coin::Bitcoin,
  tests::{test_scanner, test_signer},
};

sequential!();

async fn bitcoin() -> Bitcoin {
  let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await;
  bitcoin.fresh_chain().await;
  bitcoin
}

async_sequential! {
  async fn bitcoin_scanner() {
    test_scanner(bitcoin().await).await;
  }
}

async_sequential! {
  async fn bitcoin_signer() {
    test_signer(bitcoin().await).await;
  }
}
