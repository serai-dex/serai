use core::time::Duration;

use tokio::time::sleep;

use serai_runtime::in_instructions::{Batch, Update};

use jsonrpsee_server::RpcModule;

use serai_client::{
  primitives::{BITCOIN, BlockNumber, BlockHash, SeraiAddress, Amount, Balance},
  tokens::TokensEvent,
  in_instructions::{primitives::InInstruction, InInstructionsEvent},
  Serai,
};

mod runner;
use runner::URL;

serai_test!(
  async fn publish_update() {
    let fake_block_hash = BlockHash([0xaa; 32]);
    let fake_block_number = BlockNumber(123);
    let address = SeraiAddress::from_raw([0xff; 32]);
    let amount = Amount(100);

    let fake_block_number_clone = fake_block_number;
    let address_clone = address;
    let mut rpc = RpcModule::new(());
    rpc
      .register_async_method("processor_coinUpdates", move |_, _| async move {
        let batch = Batch {
          id: BlockHash([0xaa; 32]),
          instructions: vec![InInstruction::Transfer(address_clone)],
        };

        Ok(vec![Some(Update { block_number: fake_block_number_clone, batches: vec![batch] })])
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
            assert_eq!(id, &fake_block_hash);
            assert_eq!(
              serai.get_coin_block_number(BITCOIN, latest).await.unwrap(),
              fake_block_number
            );

            assert_eq!(
              serai.get_mint_events(latest).await.unwrap(),
              vec![TokensEvent::Mint { address, balance: Balance { coin: BITCOIN, amount } }]
            );
            assert_eq!(serai.get_token_supply(latest, BITCOIN).await.unwrap(), amount);
            assert_eq!(serai.get_token_balance(latest, BITCOIN, address).await.unwrap(), amount);
            return;
          }
          _ => panic!("get_batches returned non-batch"),
        }
      }
      sleep(Duration::from_millis(50)).await;
    }
  }
);
