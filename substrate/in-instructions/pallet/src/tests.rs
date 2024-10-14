use super::*;
use crate::mock::*;

use emissions_pallet::primitives::POL_ACCOUNT;
use genesis_liquidity_pallet::primitives::INITIAL_GENESIS_LP_SHARES;
use scale::Encode;

use frame_support::{pallet_prelude::InvalidTransaction, traits::OnFinalize};
use frame_system::RawOrigin;

use sp_core::{sr25519::Public, Pair};
use sp_runtime::{traits::ValidateUnsigned, transaction_validity::TransactionSource, BoundedVec};

use validator_sets::{Pallet as ValidatorSets, primitives::KeyPair};
use coins::primitives::{OutInstruction, OutInstructionWithBalance};
use genesis_liquidity::primitives::GENESIS_LIQUIDITY_ACCOUNT;

fn set_keys_for_session(key: Public) {
  for n in EXTERNAL_NETWORKS {
    ValidatorSets::<Test>::set_keys(
      RawOrigin::None.into(),
      n,
      BoundedVec::new(),
      KeyPair(key, vec![].try_into().unwrap()),
      Signature([0u8; 64]),
    )
    .unwrap();
  }
}

fn get_events() -> Vec<Event<Test>> {
  let events = System::events()
    .iter()
    .filter_map(|event| {
      if let RuntimeEvent::InInstructions(e) = &event.event {
        Some(e.clone())
      } else {
        None
      }
    })
    .collect::<Vec<_>>();

  System::reset_events();
  events
}

fn make_liquid_pool(coin: ExternalCoin, amount: u64) {
  // mint coins so that we can add liquidity
  let account = insecure_pair_from_name("make-pool-account").public();
  Coins::mint(account, ExternalBalance { coin, amount: Amount(amount) }.into()).unwrap();
  Coins::mint(account, Balance { coin: Coin::Serai, amount: Amount(amount) }).unwrap();

  // make some liquid pool
  Dex::add_liquidity(RawOrigin::Signed(account).into(), coin, amount, amount, 1, 1, account)
    .unwrap();
}

#[test]
fn validate_batch() {
  new_test_ext().execute_with(|| {
    let pair = insecure_pair_from_name("Alice");
    set_keys_for_session(pair.public());

    let mut batch_size = 0;
    let mut batch = Batch {
      network: ExternalNetworkId::Monero,
      id: 1,
      block: BlockHash([0u8; 32]),
      instructions: vec![],
    };

    // batch size bigger than MAX_BATCH_SIZE should fail
    while batch_size <= MAX_BATCH_SIZE + 1000 {
      batch.instructions.push(InInstructionWithBalance {
        instruction: InInstruction::Transfer(SeraiAddress::new([0u8; 32])),
        balance: ExternalBalance { coin: ExternalCoin::Monero, amount: Amount(1) },
      });
      batch_size = batch.encode().len();
    }

    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature: Signature([0u8; 64]) },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::ExhaustsResources.into()
    );

    // reduce the batch size into allowed size
    while batch_size > MAX_BATCH_SIZE {
      batch.instructions.pop();
      batch_size = batch.encode().len();
    }

    // 0 signature should be invalid
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature: Signature([0u8; 64]) },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::BadProof.into()
    );

    // submit a valid signature
    let signature = pair.sign(&batch_message(&batch));

    // network shouldn't be halted
    InInstructions::halt(ExternalNetworkId::Monero).unwrap();
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Custom(1).into() // network halted error
    );

    // submit from an un-halted network
    batch.network = ExternalNetworkId::Bitcoin;
    let signature = pair.sign(&batch_message(&batch));

    // can't submit in the first block(Block 0)
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature: signature.clone() },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Future.into()
    );

    // update block number
    System::set_block_number(1);

    // first batch id should be 0
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature: signature.clone() },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Future.into()
    );

    // update batch id
    batch.id = 0;
    let signature = pair.sign(&batch_message(&batch));

    // can't have more than 1 batch per block
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature: signature.clone() },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Future.into()
    );

    // update block number
    System::set_block_number(2);

    // network and the instruction coins should match
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Custom(2).into() // network and instruction coins doesn't match error
    );

    // update block number & batch
    System::set_block_number(3);
    for ins in &mut batch.instructions {
      ins.balance.coin = ExternalCoin::Bitcoin;
    }
    let signature = pair.sign(&batch_message(&batch));

    // batch id can't be equal or less than previous id
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Stale.into()
    );

    // update block number & batch
    System::set_block_number(4);
    batch.id += 2;
    let signature = pair.sign(&batch_message(&batch));

    // batch id can't be incremented more than once per batch
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature },
    };
    assert_eq!(
      InInstructions::validate_unsigned(TransactionSource::External, &call),
      InvalidTransaction::Future.into()
    );

    // update block number & batch
    System::set_block_number(5);
    batch.id = (batch.id - 2) + 1;
    let signature = pair.sign(&batch_message(&batch));

    // it should now pass
    let call = pallet::Call::<Test>::execute_batch {
      batch: SignedBatch { batch: batch.clone(), signature },
    };
    InInstructions::validate_unsigned(TransactionSource::External, &call).unwrap();
  });
}

#[test]
fn transfer_instruction() {
  new_test_ext().execute_with(|| {
    let coin = ExternalCoin::Bitcoin;
    let amount = Amount(2 * 10u64.pow(coin.decimals()));
    let account = insecure_pair_from_name("random1").public();
    let batch = SignedBatch {
      batch: Batch {
        network: coin.network(),
        id: 0,
        block: BlockHash([0u8; 32]),
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Transfer(account.into()),
          balance: ExternalBalance { coin, amount },
        }],
      },
      signature: Signature([0u8; 64]),
    };
    InInstructions::execute_batch(RawOrigin::None.into(), batch).unwrap();

    // check that account has the coins
    assert_eq!(Coins::balance(account, coin.into()), amount);
  })
}

#[test]
fn dex_instruction_add_liquidity() {
  new_test_ext().execute_with(|| {
    let coin = ExternalCoin::Ether;
    let amount = Amount(2 * 10u64.pow(coin.decimals()));
    let account = insecure_pair_from_name("random1").public();

    let batch = SignedBatch {
      batch: Batch {
        network: coin.network(),
        id: 0,
        block: BlockHash([0u8; 32]),
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::SwapAndAddLiquidity(account.into())),
          balance: ExternalBalance { coin, amount },
        }],
      },
      signature: Signature([0u8; 64]),
    };

    // we should have a liquid pool before we can swap
    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();

    // check that the instruction is failed
    assert_eq!(
      get_events()
        .into_iter()
        .filter(|event| matches!(event, in_instructions::Event::<Test>::InstructionFailure { .. }))
        .collect::<Vec<_>>(),
      vec![in_instructions::Event::<Test>::InstructionFailure {
        network: batch.batch.network,
        id: batch.batch.id,
        index: 0
      }]
    );

    let original_coin_amount = 5 * 10u64.pow(coin.decimals());
    make_liquid_pool(coin, original_coin_amount);

    // this should now be successful
    InInstructions::execute_batch(RawOrigin::None.into(), batch).unwrap();

    // check that the instruction was successful
    assert_eq!(
      get_events()
        .into_iter()
        .filter(|event| matches!(event, in_instructions::Event::<Test>::InstructionFailure { .. }))
        .collect::<Vec<_>>(),
      vec![]
    );

    // check that we now have a Ether pool with correct liquidity
    // we can't know the actual SRI amount since we don't know the result of the swap.
    // Moreover, knowing exactly how much isn't the responsibility of InInstruction pallet,
    // it is responsibility of the Dex pallet.
    let (coin_amount, _serai_amount) = Dex::get_reserves(&coin.into(), &Coin::Serai).unwrap();
    assert_eq!(coin_amount, original_coin_amount + amount.0);

    // assert that the account got the liquidity tokens, again we don't how much and
    // it isn't this pallets responsibility.
    assert!(LiquidityTokens::balance(account, coin.into()).0 > 0);

    // check that in ins account doesn't have the coins
    assert_eq!(Coins::balance(IN_INSTRUCTION_EXECUTOR.into(), coin.into()), Amount(0));
    assert_eq!(Coins::balance(IN_INSTRUCTION_EXECUTOR.into(), Coin::Serai), Amount(0));
  })
}

#[test]
fn dex_instruction_swap() {
  new_test_ext().execute_with(|| {
    let coin = ExternalCoin::Bitcoin;
    let amount = Amount(2 * 10u64.pow(coin.decimals()));
    let account = insecure_pair_from_name("random1").public();

    // make a pool so that can actually swap
    make_liquid_pool(coin, 5 * 10u64.pow(coin.decimals()));

    let mut batch = SignedBatch {
      batch: Batch {
        network: coin.network(),
        id: 0,
        block: BlockHash([0u8; 32]),
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::Dex(DexCall::Swap(
            Balance { coin: Coin::Serai, amount: Amount(1) },
            OutAddress::External(ExternalAddress::new([0u8; 64].to_vec()).unwrap()),
          )),
          balance: ExternalBalance { coin, amount },
        }],
      },
      signature: Signature([0u8; 64]),
    };

    // we can't send SRI to external address
    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();

    // check that the instruction was failed
    assert_eq!(
      get_events()
        .into_iter()
        .filter(|event| matches!(event, in_instructions::Event::<Test>::InstructionFailure { .. }))
        .collect::<Vec<_>>(),
      vec![in_instructions::Event::<Test>::InstructionFailure {
        network: batch.batch.network,
        id: batch.batch.id,
        index: 0
      }]
    );

    // make it internal address
    batch.batch.instructions[0].instruction = InInstruction::Dex(DexCall::Swap(
      Balance { coin: Coin::Serai, amount: Amount(1) },
      OutAddress::Serai(account.into()),
    ));

    // check that swap is successful this time
    assert_eq!(Coins::balance(account, Coin::Serai), Amount(0));
    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();
    assert!(Coins::balance(account, Coin::Serai).0 > 0);

    // make another pool for external coin
    let coin2 = ExternalCoin::Monero;
    make_liquid_pool(coin2, 5 * 10u64.pow(coin.decimals()));

    // update the batch
    let out_addr = ExternalAddress::new([0u8; 64].to_vec()).unwrap();
    batch.batch.instructions[0].instruction = InInstruction::Dex(DexCall::Swap(
      Balance { coin: ExternalCoin::Monero.into(), amount: Amount(1) },
      OutAddress::External(out_addr.clone()),
    ));
    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();

    // check that we got out instruction
    let events = System::events()
      .iter()
      .filter_map(|event| {
        if let RuntimeEvent::Coins(e) = &event.event {
          if matches!(e, coins::Event::<Test>::BurnWithInstruction { .. }) {
            Some(e.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .collect::<Vec<_>>();

    assert_eq!(
      events,
      vec![coins::Event::<Test>::BurnWithInstruction {
        from: IN_INSTRUCTION_EXECUTOR.into(),
        instruction: OutInstructionWithBalance {
          instruction: OutInstruction { address: out_addr, data: None },
          balance: ExternalBalance { coin: coin2, amount: Amount(68228493) }
        }
      }]
    )
  })
}

#[test]
fn genesis_liquidity_instruction() {
  new_test_ext().execute_with(|| {
    let coin = ExternalCoin::Bitcoin;
    let amount = Amount(2 * 10u64.pow(coin.decimals()));
    let account = insecure_pair_from_name("random1").public();

    let batch = SignedBatch {
      batch: Batch {
        network: coin.network(),
        id: 0,
        block: BlockHash([0u8; 32]),
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::GenesisLiquidity(account.into()),
          balance: ExternalBalance { coin, amount },
        }],
      },
      signature: Signature([0u8; 64]),
    };

    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();

    // check that genesis liq account got the coins
    assert_eq!(Coins::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin.into()), amount);

    // check that it registered the liquidity for the account
    // detailed tests about the amounts has to be done in GenesisLiquidity pallet tests.
    let liquidity_amount = GenesisLiquidity::liquidity(coin, account).unwrap();
    assert_eq!(liquidity_amount.coins, amount.0);
    assert_eq!(liquidity_amount.shares, INITIAL_GENESIS_LP_SHARES);

    let supply = GenesisLiquidity::supply(coin).unwrap();
    assert_eq!(supply.coins, amount.0);
    assert_eq!(supply.shares, INITIAL_GENESIS_LP_SHARES);
  })
}

#[test]
fn swap_to_staked_sri_instruction() {
  new_test_ext().execute_with(|| {
    let coin = ExternalCoin::Monero;
    let key_share =
      ValidatorSets::<Test>::allocation_per_key_share(NetworkId::from(coin.network())).unwrap();
    let amount = Amount(2 * key_share.0);
    let account = insecure_pair_from_name("random1").public();

    // make a pool so that can actually swap
    make_liquid_pool(coin, 5 * 10u64.pow(coin.decimals()));

    // set the keys to set the TAS for the network
    ValidatorSets::<Test>::set_keys(
      RawOrigin::None.into(),
      coin.network(),
      Vec::new().try_into().unwrap(),
      KeyPair(insecure_pair_from_name("random-key").public(), Vec::new().try_into().unwrap()),
      Signature([0u8; 64]),
    )
    .unwrap();

    // make sure account doesn't already have lTs or allocation
    let current_liq_tokens = LiquidityTokens::balance(POL_ACCOUNT.into(), coin.into()).0;
    assert_eq!(current_liq_tokens, 0);
    assert_eq!(ValidatorSets::<Test>::allocation((NetworkId::from(coin.network()), account)), None);

    // we need this so that value for the coin exist
    Dex::on_finalize(0);
    System::set_block_number(1); // we need this for the spot price

    let batch = SignedBatch {
      batch: Batch {
        network: coin.network(),
        id: 0,
        block: BlockHash([0u8; 32]),
        instructions: vec![InInstructionWithBalance {
          instruction: InInstruction::SwapToStakedSRI(account.into(), coin.network().into()),
          balance: ExternalBalance { coin, amount },
        }],
      },
      signature: Signature([0u8; 64]),
    };

    InInstructions::execute_batch(RawOrigin::None.into(), batch.clone()).unwrap();

    // assert that we added liq from POL account
    assert!(LiquidityTokens::balance(POL_ACCOUNT.into(), coin.into()).0 > current_liq_tokens);

    // assert that user allocated SRI for the network
    let value = Dex::spot_price_for_block(0, coin).unwrap();
    let sri_amount = Amount(
      u64::try_from(
        u128::from(amount.0)
          .checked_mul(u128::from(value.0))
          .unwrap()
          .checked_div(u128::from(10u64.pow(coin.decimals())))
          .unwrap(),
      )
      .unwrap(),
    );
    assert_eq!(
      ValidatorSets::<Test>::allocation((NetworkId::from(coin.network()), account)).unwrap(),
      sri_amount
    );
  })
}
