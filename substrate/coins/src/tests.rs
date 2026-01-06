use sp_core::{Pair as _, sr25519::Pair};
use frame_system::RawOrigin;

use serai_abi::{
  primitives::{coin::*, balance::*, address::*, instructions::*},
  TransactionContext as _,
};

use crate::mock::*;

pub type CoinsEvent = serai_abi::coins::Event;

#[test]
fn mint() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // minting u64::MAX should work
    let coin = Coin::Serai;
    let to = SeraiAddress::from(Pair::generate().0.public());
    let balance = Balance { coin, amount: Amount(u64::MAX) };

    Coins::mint(to, balance).unwrap();
    assert_eq!(Coins::balance(to, coin), balance.amount);

    // minting more should fail
    assert!(Coins::mint(to, Balance { coin, amount: Amount(1) }).is_err());

    // supply now should be equal to sum of the accounts balance sum
    assert_eq!(Coins::supply(coin), balance.amount);

    // test events
    let mint_events = Core::events()
      .iter()
      .flat_map(IntoIterator::into_iter)
      .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
      .filter_map(|event| {
        if let serai_abi::Event::Coins(e) = &event {
          matches!(e, CoinsEvent::Mint { .. }).then(|| e.clone())
        } else {
          None
        }
      })
      .collect::<Vec<_>>();

    assert_eq!(mint_events, vec![CoinsEvent::Mint { to, coins: balance }]);
  });
}

#[test]
fn burn_with_instruction() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // mint some coin
    let coin = Coin::External(ExternalCoin::Bitcoin);
    let to = SeraiAddress::from(Pair::generate().0.public());
    let balance = Balance { coin, amount: Amount(10 * 10u64.pow(coin.decimals())) };

    Coins::mint(to, balance).unwrap();
    assert_eq!(Coins::balance(to, coin), balance.amount);
    assert_eq!(Coins::supply(coin), balance.amount);

    let from = to;

    // we shouldn't be able to burn more than what we have
    let mut instruction = OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(ExternalAddress::try_from(vec![]).unwrap()),
      balance: ExternalBalance {
        coin: coin.try_into().unwrap(),
        amount: (balance.amount + Amount(1)).unwrap(),
      },
    };
    assert!(
      Coins::burn_with_instruction(RawOrigin::Signed(from).into(), instruction.clone()).is_err()
    );

    // it should now work
    instruction.balance.amount = balance.amount;
    Coins::burn_with_instruction(RawOrigin::Signed(from).into(), instruction.clone()).unwrap();

    // balance & supply now should be back to 0
    assert_eq!(Coins::balance(from, coin), Amount(0));
    assert_eq!(Coins::supply(coin), Amount(0));

    let burn_events = Core::events()
      .iter()
      .flat_map(IntoIterator::into_iter)
      .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
      .filter_map(|event| {
        if let serai_abi::Event::Coins(e) = &event {
          matches!(e, CoinsEvent::BurnWithInstruction { .. }).then(|| e.clone())
        } else {
          None
        }
      })
      .collect::<Vec<_>>();

    assert_eq!(burn_events, vec![CoinsEvent::BurnWithInstruction { from, instruction }]);
  });
}

#[test]
fn transfer() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // mint some coin
    let coin = Coin::External(ExternalCoin::Bitcoin);
    let from = SeraiAddress::from(Pair::generate().0.public());
    let balance = Balance { coin, amount: Amount(10 * 10u64.pow(coin.decimals())) };

    Coins::mint(from, balance).unwrap();
    assert_eq!(Coins::balance(from, coin), balance.amount);
    assert_eq!(Coins::supply(coin), balance.amount);

    // we can't send more than what we have
    let to = SeraiAddress::from(Pair::generate().0.public());
    assert!(Coins::transfer(
      RawOrigin::Signed(from).into(),
      to,
      Balance { coin, amount: (balance.amount + Amount(1)).unwrap() }
    )
    .is_err());

    // we can send it all
    Coins::transfer(RawOrigin::Signed(from).into(), to, balance).unwrap();

    // check the balances
    assert_eq!(Coins::balance(from, coin), Amount(0));
    assert_eq!(Coins::balance(to, coin), balance.amount);

    // supply shouldn't change
    assert_eq!(Coins::supply(coin), balance.amount);
  });
}
