use crate::{
  coin::Bitcoin,
  tests::{test_scan, test_signer},
};

sequential!();

async fn bitcoin() -> Bitcoin {
  let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await;
  bitcoin.fresh_chain().await;
  bitcoin
}

async_sequential! {
  async fn bitcoin_scan() {
    test_scan(bitcoin().await).await;
  }
}

async_sequential! {
  async fn bitcoin_signer() {
    test_signer(bitcoin().await).await;
  }
}
