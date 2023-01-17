use core::time::Duration;

use tokio::time::sleep;

use serai_runtime::in_instructions::{Batch, Update};

use jsonrpsee_server::RpcModule;

use serai_client::{
  primitives::{BlockNumber, NativeAddress, Coin},
  in_instructions::{
    primitives::{ExternalAddress, Target, InInstruction},
    InInstructionsEvent,
  },
  Serai,
};

mod runner;

serai_test!(
  async fn publish_update() {
    let mut rpc = RpcModule::new(());
    rpc
      .register_async_method("processor_coinUpdates", |_, _| async move {
        let batch = Batch {
          id: 0,
          instructions: vec![InInstruction {
            origin: ExternalAddress::new(b"external".to_vec()).unwrap(),
            target: Target::Address(NativeAddress::from_raw([0xff; 32])),
          }],
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

    let serai = Serai::new().await.unwrap();
    assert_eq!(
      serai.get_next_batch_id(Coin(0), serai.get_latest_block_hash().await.unwrap()).await.unwrap(),
      0
    );

    loop {
      let latest = serai.get_latest_block_hash().await.unwrap();
      let batches = serai.get_batch_events(latest).await.unwrap();
      if let Some(batch) = batches.get(0) {
        match batch {
          InInstructionsEvent::Batch { .. } => {
            assert_eq!(
              serai.get_coin_block_number(Coin(0), latest).await.unwrap(),
              BlockNumber(123)
            );
            assert_eq!(serai.get_next_batch_id(Coin(0), latest).await.unwrap(), 1);
            return;
          }
          _ => panic!("get_batches returned non-batch"),
        }
      }
      sleep(Duration::from_millis(50)).await;
    }
  }
);
