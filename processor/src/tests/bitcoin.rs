use crate::{
  coin::{Coin, Bitcoin},
  tests::test_send,
};

#[tokio::test]
async fn bitcoin() {
  let bitcoin = Bitcoin::new("http://serai:seraidex@127.0.0.1:18443".to_string()).await;
  bitcoin.fresh_chain().await;
  let fee = bitcoin.get_fee().await;
  test_send(bitcoin, fee).await;
}
