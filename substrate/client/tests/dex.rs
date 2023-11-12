use rand_core::{RngCore, OsRng};
use scale::Encode;

use sp_core::{Pair as PairTrait, bounded_vec::BoundedVec, hashing::blake2_256};

use serai_runtime::in_instructions::primitives::DexCall;

use serai_client::{
  primitives::{
    Amount, NetworkId, Coin, Balance, BlockHash, insecure_pair_from_name, ExternalAddress,
    SeraiAddress, PublicKey,
  },
  in_instructions::primitives::{
    InInstruction, InInstructionWithBalance, Batch, IN_INSTRUCTION_EXECUTOR, OutAddress,
  },
  dex::DexEvent,
  Serai,
};

mod common;
use common::{
  in_instructions::{provide_batch, mint_coin},
  dex::{add_liquidity as common_add_liquidity, swap as common_swap},
};

// TODO: Calculate all constants in the following tests
// TODO: Check LP token, coin balances
// TODO: Modularize common code
// TODO: Check Transfer events
serai_test!(
  create_pool: (|serai: Serai| async move {
    let block = serai.block_by_number(0).await.unwrap().unwrap().hash();
    let events = serai.as_of(block).dex().all_events().await.unwrap();

    assert_eq!(
      events,
      vec![
        DexEvent::PoolCreated {
          pool_id: Coin::Bitcoin,
          pool_account: PublicKey::from_raw(blake2_256(&Coin::Bitcoin.encode())),
          lp_token: Coin::Bitcoin,
        },
        DexEvent::PoolCreated {
          pool_id: Coin::Ether,
          pool_account: PublicKey::from_raw(blake2_256(&Coin::Ether.encode())),
          lp_token: Coin::Ether,
        },
        DexEvent::PoolCreated {
          pool_id: Coin::Dai,
          pool_account: PublicKey::from_raw(blake2_256(&Coin::Dai.encode())),
          lp_token: Coin::Dai,
        },
        DexEvent::PoolCreated {
          pool_id: Coin::Monero,
          pool_account: PublicKey::from_raw(blake2_256(&Coin::Monero.encode())),
          lp_token: Coin::Monero,
        },
      ]
    );
  })

  add_liquidity: (|serai: Serai| async move {
    let coin = Coin::Monero;
    let pair = insecure_pair_from_name("Ferdie");

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      Balance { coin, amount: Amount(100_000_000_000_000) },
      NetworkId::Monero,
      0,
      pair.clone().public().into(),
    )
    .await;

    // add liquidity
    let coin_amount = Amount(50_000_000_000_000);
    let sri_amount = Amount(50_000_000_000_000);
    let block = common_add_liquidity(&serai,
      coin,
      coin_amount,
      sri_amount,
      0,
      pair.clone()
    ).await;
    // get only the add liq events
    let mut events = serai.as_of(block).dex().all_events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::LiquidityAdded { .. }));

    assert_eq!(
      events,
      vec![DexEvent::LiquidityAdded {
        who: pair.public(),
        mint_to: pair.public(),
        pool_id: Coin::Monero,
        coin_amount: coin_amount.0,
        sri_amount: sri_amount.0,
        lp_token: Coin::Monero,
        lp_token_minted: 49_999999990000
      }]
    );
  })

  // Tests coin -> SRI and SRI -> coin swaps.
  swap_coin_to_sri: (|serai: Serai| async move {
    let coin = Coin::Ether;
    let pair = insecure_pair_from_name("Ferdie");

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      Balance { coin, amount: Amount(100_000_000_000_000) },
      NetworkId::Ethereum,
      0,
      pair.clone().public().into(),
    )
    .await;

    // add liquidity
    common_add_liquidity(&serai,
      coin,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      0,
      pair.clone()
    ).await;

    // now that we have our liquid pool, swap some coin to SRI.
    let mut amount_in = Amount(25_000_000_000_000);
    let mut block = common_swap(&serai, coin, Coin::Serai, amount_in, Amount(1), 1, pair.clone())
      .await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().all_events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    let mut path = BoundedVec::try_from(vec![coin, Coin::Serai]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public(),
        send_to: pair.public(),
        path,
        amount_in: amount_in.0,
        amount_out: 16633299966633
      }]
    );

    // now swap some SRI to coin
    amount_in = Amount(10_000_000_000_000);
    block = common_swap(&serai, Coin::Serai, coin, amount_in, Amount(1), 2, pair.clone()).await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().all_events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    path = BoundedVec::try_from(vec![Coin::Serai, coin]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public(),
        send_to: pair.public(),
        path,
        amount_in: amount_in.0,
        amount_out: 17254428681101
      }]
    );
  })

  swap_coin_to_coin: (|serai: Serai| async move {
    let coin1 = Coin::Monero;
    let coin2 = Coin::Dai;
    let pair = insecure_pair_from_name("Ferdie");

    // mint coins
    mint_coin(
      &serai,
      Balance { coin: coin1, amount: Amount(100_000_000_000_000) },
      NetworkId::Monero,
      0,
      pair.clone().public().into(),
    )
    .await;
    mint_coin(
      &serai,
      Balance { coin: coin2, amount: Amount(100_000_000_000_000) },
      NetworkId::Ethereum,
      0,
      pair.clone().public().into(),
    )
    .await;

    // add liquidity to pools
    common_add_liquidity(&serai,
      coin1,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      0,
      pair.clone()
    ).await;
    common_add_liquidity(&serai,
      coin2,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      1,
      pair.clone()
    ).await;

    // swap coin1 -> coin2
    let amount_in = Amount(25_000_000_000_000);
    let block = common_swap(&serai, coin1, coin2, amount_in, Amount(1), 2, pair.clone()).await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().all_events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    let path = BoundedVec::try_from(vec![coin1, Coin::Serai, coin2]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public(),
        send_to: pair.public(),
        path,
        amount_in: amount_in.0,
        amount_out: 12453103964435,
      }]
    );
  })

  add_liquidity_in_instructions: (|serai: Serai| async move {
    let coin = Coin::Bitcoin;
    let pair = insecure_pair_from_name("Ferdie");
    let mut batch_id = 0;

    // mint sriBTC in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      Balance { coin, amount: Amount(100_000_000_000_000) },
      NetworkId::Bitcoin,
      batch_id,
      pair.clone().public().into(),
    )
    .await;
    batch_id += 1;

    // add liquidity
    common_add_liquidity(&serai,
      coin,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      0,
      pair.clone()
    ).await;

    // now that we have our liquid SRI/BTC pool, we can add more liquidity to it via an
    // InInstruction
    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);
    let batch = Batch {
      network: NetworkId::Bitcoin,
      id: batch_id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Dex(DexCall::SwapAndAddLiquidity(pair.public().into())),
        balance: Balance { coin: Coin::Bitcoin, amount: Amount(20_000_000_000_000) },
      }],
    };

    let block = provide_batch(&serai, batch).await;
    let mut events = serai.as_of(block).dex().all_events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::LiquidityAdded { .. }));
    assert_eq!(
      events,
      vec![DexEvent::LiquidityAdded {
        who: IN_INSTRUCTION_EXECUTOR.into(),
        mint_to: pair.public(),
        pool_id: Coin::Bitcoin,
        coin_amount: 10_000_000_000_000, // half of sent amount
        sri_amount: 6_947_918_403_646,
        lp_token: Coin::Bitcoin,
        lp_token_minted: 8333333333332
      }]
    );
  })

  swap_in_instructions: (|serai: Serai| async move {
    let coin1 = Coin::Monero;
    let coin2 = Coin::Ether;
    let pair = insecure_pair_from_name("Ferdie");
    let mut coin1_batch_id = 0;
    let mut coin2_batch_id = 0;

    // mint coins
    mint_coin(
      &serai,
      Balance { coin: coin1, amount: Amount(100_000_000_000_000) },
      NetworkId::Monero,
      coin1_batch_id,
      pair.clone().public().into(),
    )
    .await;
    coin1_batch_id += 1;
    mint_coin(
      &serai,
      Balance { coin: coin2, amount: Amount(100_000_000_000_000) },
      NetworkId::Ethereum,
      coin2_batch_id,
      pair.clone().public().into(),
    )
    .await;
    coin2_batch_id += 1;

    // add liquidity to pools
    common_add_liquidity(&serai,
      coin1,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      0,
      pair.clone()
    ).await;
    common_add_liquidity(&serai,
      coin2,
      Amount(50_000_000_000_000),
      Amount(50_000_000_000_000),
      1,
      pair.clone()
    ).await;

    // rand address bytes
    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);

    // XMR -> ETH
    {
      // make an out address
      let out_address = OutAddress::External(ExternalAddress::new(rand_bytes.clone()).unwrap());

      // amount is the min out amount
      let out_balance = Balance { coin: coin2, amount: Amount(1) };

      // now that we have our pools, we can try to swap
      let mut block_hash = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block_hash.0);
      let batch = Batch {
        network: NetworkId::Monero,
        id: coin1_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address)),
          balance: Balance { coin: coin1, amount: Amount(20_000_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      coin1_batch_id += 1;
      let mut events = serai.as_of(block).dex().all_events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin1, Coin::Serai, coin2]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR.into(),
          send_to: IN_INSTRUCTION_EXECUTOR.into(),
          path,
          amount_in: 20_000_000_000_000,
          amount_out: 11066655622377
        }]
      );
    }

    // ETH -> sriXMR
    {
      // make an out address
      let out_address =
        OutAddress::Serai(SeraiAddress::new(rand_bytes.clone().try_into().unwrap()));

      // amount is the min out amount
      let out_balance = Balance { coin: coin1, amount: Amount(1) };

      // now that we have our pools, we can try to swap
      let mut block_hash = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block_hash.0);
      let batch = Batch {
        network: NetworkId::Ethereum,
        id: coin2_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address.clone())),
          balance: Balance { coin: coin2, amount: Amount(20_000_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      let mut events = serai.as_of(block).dex().all_events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin2, Coin::Serai, coin1]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR.into(),
          send_to: out_address.as_native().unwrap().into(),
          path,
          amount_in: 20_000_000_000_000,
          amount_out: 26440798801319
        }]
      );
    }

    // XMR -> SRI
    {
      // make an out address
      let out_address = OutAddress::Serai(SeraiAddress::new(rand_bytes.try_into().unwrap()));

      // amount is the min out amount
      let out_balance = Balance { coin: Coin::Serai, amount: Amount(1) };

      // now that we have our pools, we can try to swap
      let mut block_hash = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block_hash.0);
      let batch = Batch {
        network: NetworkId::Monero,
        id: coin1_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address.clone())),
          balance: Balance { coin: coin1, amount: Amount(10_000_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      let mut events = serai.as_of(block).dex().all_events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin1, Coin::Serai]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR.into(),
          send_to: out_address.as_native().unwrap().into(),
          path,
          amount_in: 10_000_000_000_000,
          amount_out: 10711005507065
        }]
      );
    }
  })
);
