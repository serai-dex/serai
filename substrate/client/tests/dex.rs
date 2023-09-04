use rand_core::{RngCore, OsRng};

use sp_core::{Pair as PairTrait, bounded_vec::BoundedVec};
use serai_runtime::in_instructions::primitives::DexCall;

use serai_client::{
  primitives::{
    Amount, NetworkId, Coin, Balance, BlockHash, insecure_pair_from_name, ExternalAddress
  },
  in_instructions::primitives::{InInstruction, InInstructionWithBalance, Batch, IN_INSTRUCTION_EXECUTOR},
  dex::DexEvent,
  Serai,
};

mod common;
use common::{
  serai,
  in_instructions::{provide_batch, mint_coin},
  dex::{create_pool as common_create_pool, add_liquidity as common_add_liquidity, swap as common_swap},
};

serai_test!(
  async fn add_liquidity_in_instructions() {
    let coin = Coin::Bitcoin;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;
    let mut batch_id = 0;

    // make the pool first so that we can add liquidity to it.
    common_create_pool(coin, 0, pair.clone()).await;

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      Balance { coin, amount: Amount(100_000000000000) },
      NetworkId::Bitcoin,
      batch_id,
      pair.clone().public().into()
    ).await;
    batch_id += 1;

    // add liquidity
    common_add_liquidity(coin, Amount(50_000000000000), Amount(50_000000000000), 1, pair.clone()).await;

    // now that we have our liquid Btc/SRI pool, we can try add
    // more liquidity to it
    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);
    let batch = Batch {
      network: NetworkId::Bitcoin,
      id: batch_id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Dex(DexCall::AddLiquidity(pair.public().into())),
        balance: Balance { coin: Coin::Bitcoin, amount: Amount(20_000000000000) },
      }],
    };

    let block = provide_batch(batch).await;
    let mut events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::LiquidityAdded { .. }));

    // we should have only 1 liq added event.
    assert_eq!(events.len(), 1);

    assert_eq!(events, vec![DexEvent::LiquidityAdded {
      who: IN_INSTRUCTION_EXECUTOR.into(),
      mint_to: pair.public(),
      pool_id: (Coin::Serai, Coin::Bitcoin),
      amount1_provided: 6947918403646,
      amount2_provided: 10_000000000000, // half of sended amount
      lp_token: 0,
      lp_token_minted: 8333333333332
    }]);

    // TODO: get the minted lp token and check for balance of lp token on the address?
  }

  async fn swap_in_instructions() {
    let coin1 = Coin::Monero;
    let coin2 = Coin::Ether;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;
    let mut batch_id = 0;

    // create pools
    common_create_pool(coin1, 0, pair.clone()).await;
    common_create_pool(coin2, 1, pair.clone()).await;

    // mint coins
    mint_coin(
      Balance { coin: coin1, amount: Amount(100_000000000000) },
      NetworkId::Monero,
      batch_id,
      pair.clone().public().into()
    ).await;
    batch_id += 1;
    mint_coin(
      Balance { coin: coin2, amount: Amount(100_000000000000) },
      NetworkId::Ethereum,
      0,
      pair.clone().public().into()
    ).await;

    // add liquidity to pools
    common_add_liquidity(coin1, Amount(50_000000000000), Amount(50_000000000000), 2, pair.clone()).await;
    common_add_liquidity(coin2, Amount(50_000000000000), Amount(50_000000000000), 3, pair.clone()).await;

    // make an address to send the eth to
    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let external_address = ExternalAddress::new(rand_bytes).unwrap();

    // now that we have our pools, we can try to swap
    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);
    let batch = Batch {
      network: NetworkId::Monero,
      id: batch_id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Dex(DexCall::Swap(coin2, external_address, Amount(1))),
        balance: Balance { coin: coin1, amount: Amount(20_000000000000) },
      }],
    };

    let block = provide_batch(batch).await;
    let mut events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::SwapExecuted { .. }));

    // we should have only 1 swap event.
    assert_eq!(events.len(), 1);

    let path = BoundedVec::truncate_from(vec![coin1, Coin::Serai, coin2]);
    assert_eq!(events, vec![DexEvent::SwapExecuted {
      who: IN_INSTRUCTION_EXECUTOR.into(),
      send_to:  IN_INSTRUCTION_EXECUTOR.into(),
      path,
      amount_in: 20_000000000000,
      amount_out: 11066655622377
    }]);

    // TODO: check balances?
  }

  async fn create_pool() {
    let coin = Coin::Bitcoin;
    let pair = insecure_pair_from_name("Ferdie");

    let block = common_create_pool(coin, 0, pair.clone()).await;

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
    let coin = Coin::Monero;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;

    // make the pool first so that we can add liquidity to it.
    common_create_pool(coin, 0, pair.clone()).await;

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      Balance { coin, amount: Amount(100_000000000000) },
      NetworkId::Monero,
      0,
      pair.clone().public().into()
    ).await;

    // add liquidity
    let coin_amount = Amount(50_000000000000);
    let sri_amount = Amount(50_000000000000);
    let block =
      common_add_liquidity(coin, coin_amount, sri_amount, 1, pair.clone())
        .await;

    // get only the add liq events
    let mut events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::LiquidityAdded { .. }));

    // we should have only 1 liq added event.
    assert_eq!(events.len(), 1);

    assert_eq!(events, vec![DexEvent::LiquidityAdded {
      who: pair.public(),
      mint_to: pair.public(),
      pool_id: (Coin::Serai, Coin::Monero),
      amount1_provided: coin_amount.0,
      amount2_provided: sri_amount.0,
      lp_token: 0,
      // TODO: how to calculate this? just looks like 50 - 0.00000001.
      // Why that fraction was subtracted?
      lp_token_minted: 49_999999990000
    }]);
  }

  // Tests coin -> SRI and SRI -> coin
  // swaps.
  async fn swap_coin_to_sri() {
    let coin = Coin::Ether;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;

    // make the pool first so that we can add liquidity to it.
    common_create_pool(coin, 0, pair.clone()).await;

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      Balance { coin, amount: Amount(100_000000000000) },
      NetworkId::Ethereum,
      0,
      pair.clone().public().into()
    ).await;

    // add liquidity
    common_add_liquidity(coin, Amount(50_000000000000), Amount(50_000000000000), 1, pair.clone()).await;

    // now that we have our liquid pool, swap some coin to SRI.
    let mut amount_in = Amount(25_000000000000);
    let mut block = common_swap(coin, Coin::Serai, amount_in, Amount(1), 2, pair.clone()).await;

    // get only the swap events
    let mut events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::SwapExecuted { .. }));

    // we should have only 1 swap event.
    assert_eq!(events.len(), 1);

    let mut path = BoundedVec::truncate_from(vec![coin, Coin::Serai]);
    assert_eq!(events, vec![DexEvent::SwapExecuted {
      who: pair.clone().public(),
      send_to: pair.public(),
      path,
      amount_in: amount_in.0,
      // TODO: again how to know this? This number is taken from the event itself.
      // The pool had 1:1 liquidity but seems like it favored SRI to be more
      // expensive?
      amount_out: 16633299966633
    }]);

    // now swap some SRI to coin
    amount_in = Amount(10_000000000000);
    block = common_swap(Coin::Serai, coin, amount_in, Amount(1), 3, pair.clone()).await;

    // get only the swap events
    events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::SwapExecuted { .. }));

    // we should have only 1 swap event.
    assert_eq!(events.len(), 1);

    path = BoundedVec::truncate_from(vec![Coin::Serai, coin]);
    assert_eq!(events, vec![DexEvent::SwapExecuted {
      who: pair.clone().public(),
      send_to: pair.public(),
      path,
      amount_in: amount_in.0,
      // TODO: again this?
      amount_out: 17254428681101
    }]);

    // TODO: check the balance of the account?
  }

  async fn swap_coin_to_coin() {
    let coin1 = Coin::Monero;
    let coin2 = Coin::Dai;
    let pair = insecure_pair_from_name("Ferdie");
    let serai = serai().await;

    // create pools
    common_create_pool(coin1, 0, pair.clone()).await;
    common_create_pool(coin2, 1, pair.clone()).await;

    // mint coins
    mint_coin(
      Balance { coin: coin1, amount: Amount(100_000000000000) },
      NetworkId::Monero,
      0,
      pair.clone().public().into()
    ).await;
    mint_coin(
      Balance { coin: coin2, amount: Amount(100_000000000000) },
      NetworkId::Ethereum,
      0,
      pair.clone().public().into()
    ).await;

    // add liquidity to pools
    common_add_liquidity(coin1, Amount(50_000000000000), Amount(50_000000000000), 2, pair.clone()).await;
    common_add_liquidity(coin2, Amount(50_000000000000), Amount(50_000000000000), 3, pair.clone()).await;

    // swap coin1 -> coin2
    let amount_in = Amount(25_000000000000);
    let block = common_swap(coin1, coin2, amount_in, Amount(1), 4, pair.clone()).await;

    // get only the swap events
    let mut events = serai.dex_events(block).await.unwrap();
    events.retain(|e|  matches!(e, DexEvent::SwapExecuted { .. }));

    // we should have only 1 swap event.
    assert_eq!(events.len(), 1);

    let path = BoundedVec::truncate_from(vec![coin1, Coin::Serai, coin2]);
    assert_eq!(events, vec![DexEvent::SwapExecuted {
      who: pair.clone().public(),
      send_to: pair.public(),
      path,
      amount_in: amount_in.0,
      // TODO: again this?
      amount_out: 12453103964435
    }]);
  }
);
