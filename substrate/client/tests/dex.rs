use rand_core::{RngCore, OsRng};

use sp_core::{Pair as PairTrait, bounded_vec::BoundedVec};

use serai_abi::in_instructions::primitives::DexCall;

use serai_client::{
  primitives::{
    Amount, Coin, Balance, BlockHash, insecure_pair_from_name, ExternalAddress, SeraiAddress,
    ExternalCoin, ExternalBalance,
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
  add_liquidity: (|serai: Serai| async move {
    let coin = ExternalCoin::Monero;
    let pair = insecure_pair_from_name("Ferdie");

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      ExternalBalance { coin, amount: Amount(100_000_000_000_000) },
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
    let mut events = serai.as_of(block).dex().events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::LiquidityAdded { .. }));

    assert_eq!(
      events,
      vec![DexEvent::LiquidityAdded {
        who: pair.public().into(),
        mint_to: pair.public().into(),
        pool_id: coin,
        coin_amount: coin_amount.0,
        sri_amount: sri_amount.0,
        lp_token_minted: 49_999999990000
      }]
    );
  })

  // Tests coin -> SRI and SRI -> coin swaps.
  swap_coin_to_sri: (|serai: Serai| async move {
    let coin = ExternalCoin::Ether;
    let pair = insecure_pair_from_name("Ferdie");

    // mint sriXMR in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      ExternalBalance { coin, amount: Amount(100_000_000_000_000) },
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
    let mut block = common_swap(
      &serai,
      coin.into(),
      Coin::Serai,
      amount_in,
      Amount(1),
      1,
      pair.clone())
      .await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    let mut path = BoundedVec::try_from(vec![coin.into(), Coin::Serai]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public().into(),
        send_to: pair.public().into(),
        path,
        amount_in: amount_in.0,
        amount_out: 16611018363939
      }]
    );

    // now swap some SRI to coin
    amount_in = Amount(10_000_000_000_000);
    block = common_swap(
      &serai,
      Coin::Serai,
      coin.into(),
      amount_in,
      Amount(1),
      2,
      pair.clone()
    ).await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    path = BoundedVec::try_from(vec![Coin::Serai, coin.into()]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public().into(),
        send_to: pair.public().into(),
        path,
        amount_in: amount_in.0,
        amount_out: 17207430166736
      }]
    );
  })

  swap_coin_to_coin: (|serai: Serai| async move {
    let coin1 = ExternalCoin::Monero;
    let coin2 = ExternalCoin::Dai;
    let pair = insecure_pair_from_name("Ferdie");

    // mint coins
    mint_coin(
      &serai,
      ExternalBalance { coin: coin1, amount: Amount(100_000_000_000_000) },
      0,
      pair.clone().public().into(),
    )
    .await;
    mint_coin(
      &serai,
      ExternalBalance { coin: coin2, amount: Amount(100_000_000_000_000) },
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
    let block = common_swap(
      &serai,
      coin1.into(),
      coin2.into(),
      amount_in,
      Amount(1),
      2,
      pair.clone()
    ).await;

    // get only the swap events
    let mut events = serai.as_of(block).dex().events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

    let path = BoundedVec::try_from(vec![coin1.into(), Coin::Serai, coin2.into()]).unwrap();
    assert_eq!(
      events,
      vec![DexEvent::SwapExecuted {
        who: pair.clone().public().into(),
        send_to: pair.public().into(),
        path,
        amount_in: amount_in.0,
        amount_out: 12421816676180,
      }]
    );
  })

  add_liquidity_in_instructions: (|serai: Serai| async move {
    let coin = ExternalCoin::Bitcoin;
    let pair = insecure_pair_from_name("Ferdie");
    let mut batch_id = 0;

    // mint sriBTC in the account so that we can add liq.
    // Ferdie account is already pre-funded with SRI.
    mint_coin(
      &serai,
      ExternalBalance { coin, amount: Amount(100_000_000_000_000) },
      batch_id,
      pair.clone().public().into(),
    )
    .await;
    batch_id += 1;

    // add liquidity
    common_add_liquidity(&serai,
      coin,
      Amount(5_000_000_000_000),
      Amount(500_000_000_000),
      0,
      pair.clone()
    ).await;

    // now that we have our liquid SRI/BTC pool, we can add more liquidity to it via an
    // InInstruction
    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);
    let batch = Batch {
      network: coin.network(),
      id: batch_id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Dex(DexCall::SwapAndAddLiquidity(pair.public().into())),
        balance: ExternalBalance { coin, amount: Amount(20_000_000_000_000) },
      }],
    };

    let block = provide_batch(&serai, batch).await;
    let mut events = serai.as_of(block).dex().events().await.unwrap();
    events.retain(|e| matches!(e, DexEvent::LiquidityAdded { .. }));
    assert_eq!(
      events,
      vec![DexEvent::LiquidityAdded {
        who: IN_INSTRUCTION_EXECUTOR,
        mint_to: pair.public().into(),
        pool_id: coin,
        coin_amount: 10_000_000_000_000, // half of sent amount
        sri_amount: 111631562261,
        lp_token_minted: 1055499886564
      }]
    );
  })

  swap_in_instructions: (|serai: Serai| async move {
    let coin1 = ExternalCoin::Monero;
    let coin2 = ExternalCoin::Ether;
    let pair = insecure_pair_from_name("Ferdie");
    let mut coin1_batch_id = 0;
    let mut coin2_batch_id = 0;

    // mint coins
    mint_coin(
      &serai,
      ExternalBalance { coin: coin1, amount: Amount(10_000_000_000_000_000) },
      coin1_batch_id,
      pair.clone().public().into(),
    )
    .await;
    coin1_batch_id += 1;
    mint_coin(
      &serai,
      ExternalBalance { coin: coin2, amount: Amount(100_000_000_000_000) },
      coin2_batch_id,
      pair.clone().public().into(),
    )
    .await;
    coin2_batch_id += 1;

    // add liquidity to pools
    common_add_liquidity(&serai,
      coin1,
      Amount(5_000_000_000_000_000), // monero has 12 decimals
      Amount(50_000_000_000),
      0,
      pair.clone()
    ).await;
    common_add_liquidity(&serai,
      coin2,
      Amount(5_000_000_000_000), // ether still has 8 in our codebase
      Amount(500_000_000_000),
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
      let out_balance = Balance { coin: coin2.into(), amount: Amount(1) };

      // now that we have our pools, we can try to swap
      let mut block_hash = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block_hash.0);
      let batch = Batch {
        network: coin1.network(),
        id: coin1_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address)),
          balance: ExternalBalance { coin: coin1, amount: Amount(200_000_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      coin1_batch_id += 1;
      let mut events = serai.as_of(block).dex().events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin1.into(), Coin::Serai, coin2.into()]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR,
          send_to: IN_INSTRUCTION_EXECUTOR,
          path,
          amount_in: 200_000_000_000_000,
          amount_out: 18970355346
        }]
      );
    }

    // ETH -> sriXMR
    {
      // make an out address
      let out_address =
        OutAddress::Serai(SeraiAddress::new(rand_bytes.clone().try_into().unwrap()));

      // amount is the min out amount
      let out_balance = Balance { coin: coin1.into(), amount: Amount(1) };

      // now that we have our pools, we can try to swap
      let mut block_hash = BlockHash([0; 32]);
      OsRng.fill_bytes(&mut block_hash.0);
      let batch = Batch {
        network: coin2.network(),
        id: coin2_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address.clone())),
          balance: ExternalBalance { coin: coin2, amount: Amount(200_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      let mut events = serai.as_of(block).dex().events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin2.into(), Coin::Serai, coin1.into()]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR,
          send_to: out_address.as_native().unwrap(),
          path,
          amount_in: 200_000_000_000,
          amount_out: 1482888317565764
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
        network: coin1.network(),
        id: coin1_batch_id,
        block: block_hash,
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(out_balance, out_address.clone())),
          balance: ExternalBalance { coin: coin1, amount: Amount(100_000_000_000_000) },
        }],
      };

      let block = provide_batch(&serai, batch).await;
      let mut events = serai.as_of(block).dex().events().await.unwrap();
      events.retain(|e| matches!(e, DexEvent::SwapExecuted { .. }));

      let path = BoundedVec::try_from(vec![coin1.into(), Coin::Serai]).unwrap();
      assert_eq!(
        events,
        vec![DexEvent::SwapExecuted {
          who: IN_INSTRUCTION_EXECUTOR,
          send_to: out_address.as_native().unwrap(),
          path,
          amount_in: 100_000_000_000_000,
          amount_out: 1755477054
        }]
      );
    }
  })
);
