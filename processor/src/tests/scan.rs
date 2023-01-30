use core::time::Duration;

use rand_core::OsRng;

use tokio::time::timeout;

use crate::{
  coin::{Block, Coin},
  scanner::{ScannerOrder, ScannerEvent, Scanner},
  tests::util::db::ScannerMemDb,
};

pub async fn test_scan<C: Coin>(coin: C) {
  let keys = frost::tests::key_gen::<_, C::Curve>(&mut OsRng);

  // Mine blocks so there's a confirmed block
  coin.mine_block().await;

  let mut scanner = Scanner::new(coin.clone(), ScannerMemDb::new());
  scanner
    .orders
    .send(ScannerOrder::RotateKey {
      activation_number: coin.get_latest_block_number().await.unwrap(),
      key: keys[&1].group_key(),
    })
    .unwrap();

  coin.test_send(C::address(keys[&1].group_key())).await;

  let block = match timeout(Duration::from_secs(5), scanner.events.recv()).await.unwrap().unwrap() {
    ScannerEvent::Block(number, id) => {
      assert_eq!(coin.get_block(number).await.unwrap().id(), id);
      number
    }
    _ => panic!("unexpected event"),
  };

  // TODO: Check the output integrity
  let _output = timeout(Duration::from_secs(5), scanner.events.recv()).await.unwrap().unwrap();

  // TODO: Kill this Scanner, recreate it off the current DB, and verify it re-emits the above
  // events
  scanner.orders.send(ScannerOrder::AckBlock(keys[&1].group_key(), block)).unwrap();

  // There should be no more events
  assert!(timeout(Duration::from_secs(5), scanner.events.recv()).await.is_err());

  // TODO: Recreate the scanner and verify it still doesn't emit events
}
