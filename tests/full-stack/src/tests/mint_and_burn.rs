use std::{sync::Mutex, time::Duration};

use crate::tests::*;

#[tokio::test]
async fn mint_and_burn_test() {
  let _one_at_a_time = ONE_AT_A_TIME.get_or_init(|| Mutex::new(())).lock();
  let (handles, test) = new_test();

  test
    .run_async(|_ops| async move {
      tokio::time::sleep(Duration::from_secs(300)).await;
    })
    .await;
}
