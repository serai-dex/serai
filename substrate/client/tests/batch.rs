use rand_core::{RngCore, OsRng};

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use serai_client::{
  primitives::{Amount, NetworkId, Coin, Balance, BlockHash, SeraiAddress},
  in_instructions::{
    primitives::{InInstruction, InInstructionWithBalance, Batch},
    InInstructionsEvent,
  },
  coins::CoinsEvent,
  Serai,
};

mod common;
use common::{serai, in_instructions::provide_batch};

serai_test!(
  async fn publish_batch() {
    let network = NetworkId::Bitcoin;
    let id = 0;

    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);

    let mut address = SeraiAddress::new([0; 32]);
    OsRng.fill_bytes(&mut address.0);

    let coin = Coin::Bitcoin;
    let amount = Amount(OsRng.next_u64().saturating_add(1));
    let balance = Balance { coin, amount };

    let batch = Batch {
      network,
      id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Transfer(address),
        balance,
      }],
    };

    let block = provide_batch(batch.clone()).await;

    let serai = serai().await;
    let serai = serai.as_of(block);
    {
      let serai = serai.in_instructions();
      assert_eq!(serai.latest_block_for_network(network).await.unwrap(), Some(block_hash));
      let batches = serai.batch_events().await.unwrap();
      assert_eq!(
        batches,
        vec![InInstructionsEvent::Batch {
          network,
          id,
          block: block_hash,
          instructions_hash: Blake2b::<U32>::digest(batch.instructions.encode()).into(),
        }]
      );
    }

    let serai = serai.coins();
    assert_eq!(serai.mint_events().await.unwrap(), vec![CoinsEvent::Mint { address, balance }],);
    assert_eq!(serai.coin_supply(coin).await.unwrap(), amount);
    assert_eq!(serai.coin_balance(coin, address).await.unwrap(), amount);
  }
);
