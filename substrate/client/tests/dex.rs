use rand_core::{RngCore, OsRng};

use sp_core::{Pair as PairTrait, bounded_vec::BoundedVec};
use serai_runtime::in_instructions::primitives::{DexCall, IN_INSTRUCTION_EXECUTOR};

use serai_client::{
  primitives::{
    Amount, NetworkId, Coin, Balance, BlockHash, SeraiAddress, insecure_pair_from_name,
  },
  in_instructions::{
    InInstructionsEvent,
    primitives::{InInstruction, InInstructionWithBalance, Batch},
  },
  dex::DexEvent,
  Serai,
};

mod common;
use common::{
  serai,
  in_instructions::provide_batch,
  dex::{create_pool as common_create_pool, add_liquidity as common_add_liquidity},
};

serai_test!(
  async fn add_liquidity_in_instructions() {
    let network = NetworkId::Bitcoin;
    let id = 0;

    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);

    let pair = insecure_pair_from_name("Ferdie");
    let public = pair.public();
    let address = SeraiAddress::from(public);

    let coin = Coin::Bitcoin;
    // NOTICE: make sure add liq is adds more than  half of this.
    // since our add liq will try to swap half of this for SRI.
    let amount = Amount(50_000000000000);
    let balance = Balance { coin, amount };

    let serai = serai().await;

    // create a pool first so that we can add liquidity to it
    // create_pool(coin, "Ferdie").await;

    // add liquidity to it, so that Dex::AddLiquidity works since
    // it actually swaps the half of the coins for SRI and then
    // add the liquidity.
    // add_liquidity(coin, network).await;

    let batch = Batch {
      network,
      id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Dex(DexCall::AddLiquidity(address)),
        balance,
      }],
    };

    let block = provide_batch(batch).await;
    let batches = serai.get_batch_events(block).await.unwrap();
    assert_eq!(batches, vec![InInstructionsEvent::Batch { network, id, block: block_hash }]);

    // TODO: get dex swap event for half of the balance
    // TODO: get dex add_liquidity event
    // let path = BoundedVec::truncate_from(vec![coin, Coin::Serai]);
    // assert_eq!(
    //   serai.dex_events(block).await.unwrap(),
    //   vec![
    //     DexEvent::SwapExecuted {
    //       who: IN_INSTRUCTION_EXECUTOR.into(),
    //       send_to: IN_INSTRUCTION_EXECUTOR.into(),
    //       path,
    //       amount_in: balance.amount.0 / 2,
    //       amount_out: balance.amount.0 / 2
    //     },
    //     DexEvent::LiquidityAdded { who: (), mint_to: (), pool_id: (), amount1_provided: (), amount2_provided: (), lp_token: (), lp_token_minted: () }
    //   ]
    // );

    let events = serai.dex_events(block).await.unwrap();
    println!("events: {:?}", events);

    // TODO: get the minted lp token and check for balance of lp token on the address
    // assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), amount);
  }

  async fn create_pool() {
    let coin = Coin::Bitcoin;
    let pair = insecure_pair_from_name("Ferdie");

    let block = common_create_pool(coin, pair.clone()).await;

    let serai = serai().await;
    let events = serai.dex_events(block).await.unwrap();

    assert_eq!(
      events,
      vec![DexEvent::PoolCreated {
        creator: pair.public().into(),
        pool_id: (Coin::Serai, coin),
        lp_token: 0 // first lp token that is created in the chain
      }]
    );
  }

  async fn add_liquidity() {
    // TODO: these tests test the happy path only
    // we should also test the unhappy paths
    // should try to add liquidity before creating the pool etc..
    // for that to happen publish_tx() should return error as well.
    // or would that be testing the substrate instead of our code?

    let coin = Coin::Monero;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;

    // TODO: transfer sriXMR in the account so that we can add liq.

    // make the pool first so that we can add liquidity to it.
    // common_create_pool(coin, pair.clone()).await;

    let block =
      common_add_liquidity(coin, Amount(50_000000000000), Amount(50_000000000000), 1, pair.clone())
        .await;
    let events = serai.dex_events(block).await.unwrap();
    println!("Events From add_liq: {:?}", events);
  }
);
