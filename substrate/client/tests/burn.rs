use rand_core::{RngCore, OsRng};

use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use sp_core::Pair;

use serai_client::{
  subxt::config::extrinsic_params::BaseExtrinsicParamsBuilder,
  primitives::{
    Amount, NetworkId, Coin, Balance, BlockHash, SeraiAddress, Data, ExternalAddress,
    insecure_pair_from_name,
  },
  in_instructions::{
    InInstructionsEvent,
    primitives::{InInstruction, InInstructionWithBalance, Batch},
  },
  tokens::{primitives::OutInstruction, TokensEvent},
  PairSigner, Serai,
};

mod common;
use common::{serai, tx::publish_tx, in_instructions::provide_batch};

serai_test!(
  async fn burn() {
    let network = NetworkId::Bitcoin;
    let id = 0;

    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);

    let pair = insecure_pair_from_name("Dave");
    let public = pair.public();
    let address = SeraiAddress::from(public);

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
    let batches = serai.get_batch_events(block).await.unwrap();
    assert_eq!(
      batches,
      vec![InInstructionsEvent::Batch {
        network,
        id,
        block: block_hash,
        instructions_hash: Blake2b::<U32>::digest(batch.instructions.encode()).into(),
      }]
    );

    assert_eq!(
      serai.get_mint_events(block).await.unwrap(),
      vec![TokensEvent::Mint { address, balance }]
    );
    assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), amount);
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), amount);

    // Now burn it
    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let external_address = ExternalAddress::new(rand_bytes).unwrap();

    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let data = Data::new(rand_bytes).unwrap();

    let out = OutInstruction { address: external_address, data: Some(data) };
    let block = publish_tx(
      &serai
        .sign(
          &PairSigner::new(pair),
          &Serai::burn(balance, out.clone()),
          0,
          BaseExtrinsicParamsBuilder::new(),
        )
        .unwrap(),
    )
    .await;

    let events = serai.get_burn_events(block).await.unwrap();
    assert_eq!(events, vec![TokensEvent::Burn { address, balance, instruction: out }]);
    assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), Amount(0));
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), Amount(0));
  }
);
