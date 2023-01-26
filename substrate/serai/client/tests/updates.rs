use serai_runtime::in_instructions::{Batch, Update};

use serai_client::{
  primitives::{BITCOIN, BlockNumber, BlockHash, SeraiAddress, Amount, WithAmount, Balance},
  tokens::TokensEvent,
  in_instructions::{primitives::InInstruction, InInstructionsEvent},
  Serai,
};

mod runner;
use runner::{provide_updates, URL};

serai_test!(
  async fn publish_updates() {
    let coin = BITCOIN;
    let id = BlockHash([0xaa; 32]);
    let block_number = BlockNumber(123);

    let address = SeraiAddress::new([0xff; 32]);
    let amount = Amount(101);

    let batch = Batch {
      id,
      instructions: vec![WithAmount { data: InInstruction::Transfer(address), amount }],
    };
    let update = Update { block_number, batches: vec![batch] };
    let block = provide_updates(vec![Some(update)]).await;

    let serai = Serai::new(URL).await.unwrap();
    let batches = serai.get_batch_events(block).await.unwrap();
    assert_eq!(batches, vec![InInstructionsEvent::Batch { coin, id }]);
    assert_eq!(serai.get_coin_block_number(coin, block).await.unwrap(), block_number);

    assert_eq!(
      serai.get_mint_events(block).await.unwrap(),
      vec![TokensEvent::Mint { address, balance: Balance { coin, amount } }]
    );
    assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), amount);
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), amount);
  }
);
