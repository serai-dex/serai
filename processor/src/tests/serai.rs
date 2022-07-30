use futures::StreamExt;
use crate::serai::Serai;

#[tokio::test]
async fn get_events() {
  let serai = Serai::new().await;
  let mut batches = serai.batches().await.unwrap();
  loop {
    let event = dbg!(batches.next().await.unwrap().unwrap());
  }
}
