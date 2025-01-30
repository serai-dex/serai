use rand_core::{RngCore, OsRng};

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use sp_core::Pair;

use serai_client::{
  primitives::{
    BlockHash, ExternalNetworkId, ExternalCoin, Amount, ExternalBalance, SeraiAddress, ExternalAddress,
    insecure_pair_from_name,
  },
  coins::{
    primitives::{OutInstruction, OutInstructionWithBalance},
    CoinsEvent,
  },
  validator_sets::primitives::Session,
  in_instructions::{
    InInstructionsEvent,
    primitives::{InInstruction, InInstructionWithBalance, Batch},
  },
  Serai, SeraiCoins,
};

mod common;
use common::{tx::publish_tx, in_instructions::provide_batch};

serai_test!(
  burn: (|serai: Serai| async move {
    let id = 0;
    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);

    let pair = insecure_pair_from_name("Dave");
    let public = pair.public();
    let address = SeraiAddress::from(public);

    let coin = ExternalCoin::Bitcoin;
    let network = coin.network();
    let amount = Amount(OsRng.next_u64().saturating_add(1));
    let balance = ExternalBalance { coin, amount };

    let batch = Batch {
      network,
      id,
      external_network_block_hash: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Transfer(address),
        balance,
      }],
    };

    let block = provide_batch(&serai, batch.clone()).await;

    let instruction = {
      let serai = serai.as_of(block);
      let batches = serai.in_instructions().batch_events().await.unwrap();
      assert_eq!(
        batches,
        vec![InInstructionsEvent::Batch {
          network,
          publishing_session: Session(0),
          id,
          external_network_block_hash: block_hash,
          in_instructions_hash: Blake2b::<U32>::digest(batch.instructions.encode()).into(),
          in_instruction_results: bitvec::bitvec![u8, bitvec::order::Lsb0; 1; 1],
        }]
      );

    assert_eq!(
      serai.coins().mint_events().await.unwrap(),
      vec![CoinsEvent::Mint { to: address, balance: balance.into() }]
    );
    assert_eq!(serai.coins().coin_supply(coin.into()).await.unwrap(), amount);
    assert_eq!(serai.coins().coin_balance(coin.into(), address).await.unwrap(), amount);

      // Now burn it
      let mut rand_bytes = vec![0; 32];
      OsRng.fill_bytes(&mut rand_bytes);
      let external_address = ExternalAddress::new(rand_bytes).unwrap();

      OutInstructionWithBalance {
        balance,
        instruction: OutInstruction { address: external_address },
      }
    };

    let block = publish_tx(
      &serai,
      &serai.sign(&pair, SeraiCoins::burn_with_instruction(instruction.clone()), 0, 0),
    )
    .await;

    let serai = serai.as_of(block);
    let serai = serai.coins();
    let events = serai.burn_with_instruction_events().await.unwrap();
    assert_eq!(events, vec![CoinsEvent::BurnWithInstruction { from: address, instruction }]);
    assert_eq!(serai.coin_supply(coin.into()).await.unwrap(), Amount(0));
    assert_eq!(serai.coin_balance(coin.into(), address).await.unwrap(), Amount(0));
  })
);
