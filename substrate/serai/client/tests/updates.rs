use core::time::Duration;

use tokio::time::sleep;

use serai_runtime::in_instructions::{Batch, Update};

use jsonrpsee_server::RpcModule;

use serai_client::{
  primitives::{BlockNumber, BlockHash, SeraiAddress, BITCOIN},
  in_instructions::{primitives::InInstruction, InInstructionsEvent},
  Serai,
};

mod runner;
use runner::URL;

serai_test!(
  async fn publish_update() {
    let mut rpc = RpcModule::new(());
    rpc
      .register_async_method("processor_coinUpdates", |_, _| async move {
        let batch = Batch {
          id: BlockHash([0xaa; 32]),
          instructions: vec![InInstruction::Transfer(SeraiAddress::from_raw([0xff; 32]))],
        };

        Ok(vec![Some(Update { block_number: BlockNumber(123), batches: vec![batch] })])
      })
      .unwrap();

    let _handle = jsonrpsee_server::ServerBuilder::default()
      .build("127.0.0.1:5134")
      .await
      .unwrap()
      .start(rpc)
      .unwrap();

    let serai = Serai::new(URL).await.unwrap();
    loop {
      let latest = serai.get_latest_block_hash().await.unwrap();
      let batches = serai.get_batch_events(latest).await.unwrap();
      if let Some(batch) = batches.get(0) {
        match batch {
          InInstructionsEvent::Batch { coin, id } => {
            assert_eq!(coin, &BITCOIN);
            assert_eq!(id, &BlockHash([0xaa; 32]));
            assert_eq!(
              serai.get_coin_block_number(BITCOIN, latest).await.unwrap(),
              BlockNumber(123)
            );
            return;
          }
          _ => panic!("get_batches returned non-batch"),
        }
      }
      sleep(Duration::from_millis(50)).await;
    }
  }
);
