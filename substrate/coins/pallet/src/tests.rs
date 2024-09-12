use crate::{mock::*, primitives::*};

use frame_system::RawOrigin;
use sp_core::Pair;

use serai_primitives::*;

pub type CoinsEvent = crate::Event<Test, ()>;

#[test]
fn mint() {
  new_test_ext().execute_with(|| {
    // minting u64::MAX should work
    let coin = Coin::Serai;
    let to = insecure_pair_from_name("random1").public();
    let balance = Balance { coin, amount: Amount(u64::MAX) };

    Coins::mint(to, balance).unwrap();
    assert_eq!(Coins::balance(to, coin), balance.amount);

    // minting more should fail
    assert!(Coins::mint(to, Balance { coin, amount: Amount(1) }).is_err());

    // supply now should be equal to sum of the accounts balance sum
    assert_eq!(Coins::supply(coin), balance.amount.0);

    // test events
    let mint_events = System::events()
      .iter()
      .filter_map(|event| {
        if let RuntimeEvent::Coins(e) = &event.event {
          if matches!(e, CoinsEvent::Mint { .. }) {
            Some(e.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .collect::<Vec<_>>();

    assert_eq!(mint_events, vec![CoinsEvent::Mint { to, balance }]);
  })
}

#[test]
fn burn_with_instruction() {
  new_test_ext().execute_with(|| {
    // mint some coin
    let coin = Coin::Bitcoin;
    let to = insecure_pair_from_name("random1").public();
    let balance = Balance { coin, amount: Amount(10 * 10u64.pow(coin.decimals())) };

    Coins::mint(to, balance).unwrap();
    assert_eq!(Coins::balance(to, coin), balance.amount);
    assert_eq!(Coins::supply(coin), balance.amount.0);

    // we shouldn't be able to burn more than what we have
    let mut instruction = OutInstructionWithBalance {
      instruction: OutInstruction { address: ExternalAddress::new(vec![]).unwrap(), data: None },
      balance: Balance { coin, amount: Amount(balance.amount.0 + 1) },
    };
    assert!(
      Coins::burn_with_instruction(RawOrigin::Signed(to).into(), instruction.clone()).is_err()
    );

    // it should now work
    instruction.balance.amount = balance.amount;
    Coins::burn_with_instruction(RawOrigin::Signed(to).into(), instruction.clone()).unwrap();

    // balance & supply now should be back to 0
    assert_eq!(Coins::balance(to, coin), Amount(0));
    assert_eq!(Coins::supply(coin), 0);

    let burn_events = System::events()
      .iter()
      .filter_map(|event| {
        if let RuntimeEvent::Coins(e) = &event.event {
          if matches!(e, CoinsEvent::BurnWithInstruction { .. }) {
            Some(e.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .collect::<Vec<_>>();

    assert_eq!(burn_events, vec![CoinsEvent::BurnWithInstruction { from: to, instruction }]);
  })
}

#[test]
fn transfer() {
  new_test_ext().execute_with(|| {
    // mint some coin
    let coin = Coin::Bitcoin;
    let from = insecure_pair_from_name("random1").public();
    let balance = Balance { coin, amount: Amount(10 * 10u64.pow(coin.decimals())) };

    Coins::mint(from, balance).unwrap();
    assert_eq!(Coins::balance(from, coin), balance.amount);
    assert_eq!(Coins::supply(coin), balance.amount.0);

    // we can't send more than what we have
    let to = insecure_pair_from_name("random2").public();
    assert!(Coins::transfer(
      RawOrigin::Signed(from).into(),
      to,
      Balance { coin, amount: Amount(balance.amount.0 + 1) }
    )
    .is_err());

    // we can send it all
    Coins::transfer(RawOrigin::Signed(from).into(), to, balance).unwrap();

    // check the balances
    assert_eq!(Coins::balance(from, coin), Amount(0));
    assert_eq!(Coins::balance(to, coin), balance.amount);

    // supply shouldn't change
    assert_eq!(Coins::supply(coin), balance.amount.0);
  })
}
