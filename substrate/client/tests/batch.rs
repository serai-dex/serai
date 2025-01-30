use rand_core::{RngCore, OsRng};

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use serai_client::{
  primitives::{BlockHash, NetworkId, ExternalCoin, Amount, ExternalBalance, SeraiAddress},
  coins::CoinsEvent,
  validator_sets::primitives::Session,
  in_instructions::{
    primitives::{InInstruction, InInstructionWithBalance, Batch},
    InInstructionsEvent,
  },
  Serai,
};

mod common;
use common::in_instructions::provide_batch;

serai_test!(
  publish_batch: (|serai: Serai| async move {
    let id = 0;

    let mut address = SeraiAddress::new([0; 32]);
    OsRng.fill_bytes(&mut address.0);

    let coin = ExternalCoin::Bitcoin;
    let network = coin.network();
    let amount = Amount(OsRng.next_u64().saturating_add(1));
    let balance = ExternalBalance { coin, amount };

    let mut external_network_block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut external_network_block_hash.0);

    let batch = Batch {
      network,
      id,
      external_network_block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Transfer(address),
        balance,
      }],
    };

    let block = provide_batch(&serai, batch.clone()).await;

    let serai = serai.as_of(block);
    {
      let serai = serai.in_instructions();
      let batches = serai.batch_events().await.unwrap();
      assert_eq!(
        batches,
        vec![InInstructionsEvent::Batch {
          network,
          publishing_session: Session(0),
          id,
          external_network_block_hash,
          in_instructions_hash: Blake2b::<U32>::digest(batch.instructions.encode()).into(),
          in_instruction_results: bitvec::bitvec![u8, bitvec::order::Lsb0; 1; 1],
        }]
      );
    }

    let serai = serai.coins();
    assert_eq!(
      serai.mint_events().await.unwrap(),
      vec![CoinsEvent::Mint { to: address, balance: balance.into() }]
    );
    assert_eq!(serai.coin_supply(coin.into()).await.unwrap(), amount);
    assert_eq!(serai.coin_balance(coin.into(), address).await.unwrap(), amount);
  })
);
