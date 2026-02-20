use serai_abi::primitives::dex::{Premise, Reserves};

use super::*;

#[test]
fn swap() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    let sri_coin = Coin::Serai;
    let ext_coin_a = ExternalCoin::Bitcoin;
    let ext_coin_b = ExternalCoin::Ether;

    // Initialize the pools
    let mut expected_events = vec![];
    for ext_coin in [ext_coin_a, ext_coin_b] {
      let init = SeraiAddress::from(Pair::generate().0.public());

      let sri_amount = Amount(100_000);
      let balance = Balance { coin: sri_coin, amount: sri_amount };

      let ext_amount = Amount(200_000);
      let ext_balance = ExternalBalance { coin: ext_coin, amount: ext_amount };

      Coins::mint(init, balance).unwrap();
      Coins::mint(init, ext_balance.into()).unwrap();

      Dex::add_liquidity(Some(init).into(), ext_coin, sri_amount, ext_amount, Amount(0), Amount(0))
        .unwrap();
      expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityAddition {
        recipient: init,
        liquidity_tokens: ExternalBalance {
          coin: ext_coin,
          amount: LiquidityTokens::supply(ext_coin),
        },
        sri_amount,
        external_coin_amount: ext_amount,
      }));
    }

    // Test a swap to/from SRI
    for swap_for in [false, true] {
      for (in_coin, out_coin) in
        [(Coin::External(ext_coin_a), Coin::Serai), (Coin::Serai, Coin::External(ext_coin_b))]
      {
        let alice = SeraiAddress::from(Pair::generate().0.public());
        let input = Balance { coin: in_coin, amount: Amount(10_000) };
        Coins::mint(alice, input).unwrap();

        let ((Coin::External(ext_coin), _) | (_, Coin::External(ext_coin))) = (in_coin, out_coin)
        else {
          unreachable!()
        };

        let pool = serai_abi::dex::address(ext_coin);

        let route = Premise::route(in_coin, out_coin).unwrap();
        assert_eq!(route.len(), 1);
        let output = route[0]
          .quote_for_in(
            Reserves {
              sri: Coins::balance(pool, Coin::Serai),
              external_coin: Coins::balance(pool, ext_coin),
            },
            input.amount,
          )
          .unwrap();
        let output = Balance { coin: out_coin, amount: output };

        let pool_in = Coins::balance(pool, in_coin);
        let pool_out = Coins::balance(pool, out_coin);

        let existing_events = Core::events().iter().flat_map(IntoIterator::into_iter).count();

        if swap_for {
          Dex::swap_for(
            Some(alice).into(),
            output,
            Balance { coin: in_coin, amount: Amount(u64::MAX) },
          )
          .unwrap();
        } else {
          Dex::swap(Some(alice).into(), input, Balance { coin: out_coin, amount: Amount(0) })
            .unwrap();
        }

        assert_eq!(Coins::balance(alice, in_coin), Amount(0));
        assert_eq!(Coins::balance(alice, out_coin), output.amount);
        assert_eq!(Coins::balance(pool, in_coin), (pool_in + input.amount).unwrap());
        assert_eq!(Coins::balance(pool, out_coin), (pool_out - output.amount).unwrap());

        let events = Core::events()
          .iter()
          .flat_map(IntoIterator::into_iter)
          .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
          .collect::<Vec<_>>();

        let mut transfers = vec![
          Event::Coins(serai_abi::coins::Event::Transfer { from: alice, to: pool, coins: input }),
          Event::Coins(serai_abi::coins::Event::Burn {
            from: pool,
            coins: Balance { coin: Coin::Serai, amount: Amount(0) },
          }),
          Event::Coins(serai_abi::coins::Event::Transfer { from: pool, to: alice, coins: output }),
        ];
        if swap_for {
          transfers.reverse();
        }
        let mut expected_events = transfers;
        expected_events.push(Event::Dex(serai_abi::dex::Event::Swap {
          from: alice,
          deltas: vec![input, output],
        }));

        assert_eq!(&events[existing_events ..], &expected_events);
      }
    }

    // Test a swap to/from two external coins
    for swap_for in [false, true] {
      let alice = SeraiAddress::from(Pair::generate().0.public());
      let input = Balance { coin: ext_coin_a.into(), amount: Amount(10_000) };
      Coins::mint(alice, input).unwrap();

      let pool_a = serai_abi::dex::address(ext_coin_a);
      let pool_a_in = Coins::balance(pool_a, ext_coin_a);
      let pool_a_out = Coins::balance(pool_a, sri_coin);

      let pool_b = serai_abi::dex::address(ext_coin_b);
      let pool_b_in = Coins::balance(pool_b, sri_coin);
      let pool_b_out = Coins::balance(pool_b, ext_coin_b);

      let route = Premise::route(Coin::from(ext_coin_a), Coin::from(ext_coin_b)).unwrap();
      assert_eq!(route.len(), 2);
      let sri_delta = route[0]
        .quote_for_in(
          Reserves {
            sri: Coins::balance(pool_a, Coin::Serai),
            external_coin: Coins::balance(pool_a, ext_coin_a),
          },
          input.amount,
        )
        .unwrap();
      let sri_delta = Balance { coin: sri_coin, amount: sri_delta };
      let output = route[1]
        .quote_for_in(
          Reserves {
            sri: Coins::balance(pool_b, Coin::Serai),
            external_coin: Coins::balance(pool_b, ext_coin_b),
          },
          sri_delta.amount,
        )
        .unwrap();
      let output = Balance { coin: ext_coin_b.into(), amount: output };

      let existing_events = Core::events().iter().flat_map(IntoIterator::into_iter).count();

      if swap_for {
        Dex::swap_for(
          Some(alice).into(),
          output,
          Balance { coin: ext_coin_a.into(), amount: Amount(u64::MAX) },
        )
        .unwrap();
      } else {
        Dex::swap(
          Some(alice).into(),
          input,
          Balance { coin: ext_coin_b.into(), amount: Amount(0) },
        )
        .unwrap();
      }

      assert_eq!(Coins::balance(alice, ext_coin_a), Amount(0));
      assert_eq!(Coins::balance(pool_a, ext_coin_a), (pool_a_in + input.amount).unwrap());
      assert_eq!(Coins::balance(pool_a, sri_coin), (pool_a_out - sri_delta.amount).unwrap());
      assert_eq!(Coins::balance(pool_b, sri_coin), (pool_b_in + sri_delta.amount).unwrap());
      assert_eq!(Coins::balance(pool_b, ext_coin_b), (pool_b_out - output.amount).unwrap());
      assert_eq!(Coins::balance(alice, ext_coin_b), output.amount);

      let events = Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .collect::<Vec<_>>();

      let mut transfers = vec![
        Event::Coins(serai_abi::coins::Event::Transfer { from: alice, to: pool_a, coins: input }),
        Event::Coins(serai_abi::coins::Event::Burn {
          from: pool_a,
          coins: Balance { coin: Coin::Serai, amount: Amount(0) },
        }),
        Event::Coins(serai_abi::coins::Event::Transfer {
          from: pool_a,
          to: pool_b,
          coins: sri_delta,
        }),
        Event::Coins(serai_abi::coins::Event::Burn {
          from: pool_b,
          coins: Balance { coin: Coin::Serai, amount: Amount(0) },
        }),
        Event::Coins(serai_abi::coins::Event::Transfer { from: pool_b, to: alice, coins: output }),
      ];
      if swap_for {
        transfers.reverse();
      }
      let mut expected_events = transfers;
      expected_events.push(Event::Dex(serai_abi::dex::Event::Swap {
        from: alice,
        deltas: vec![input, sri_delta, output],
      }));

      assert_eq!(&events[existing_events ..], &expected_events,);
    }

    // Test a improperly defined swap causes an error
    for coin in Coin::all() {
      assert_eq!(
        Dex::swap(
          Some(SeraiAddress([0; 32])).into(),
          Balance { coin, amount: Amount(0) },
          Balance { coin, amount: Amount(0) }
        )
        .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::FromToSelf)
      );
    }
  });
}

#[test]
fn swap_fee() {
  let sri_coin = Coin::Serai;
  let ext_coin = ExternalCoin::Monero;

  for swap_for in [false, true] {
    for (in_coin, out_coin) in
      [(Coin::External(ext_coin), Coin::Serai), (Coin::Serai, Coin::External(ext_coin))]
    {
      new_test_ext().execute_with(|| {
        Core::start_transaction(0);

        // Initialize the pool
        let mut expected_events = vec![];
        let init = SeraiAddress::from(Pair::generate().0.public());

        let sri_amount = Amount(1_000_000_000);
        let balance = Balance { coin: sri_coin, amount: sri_amount };

        let ext_amount = Amount(9_000_000_000);
        let ext_balance = ExternalBalance { coin: ext_coin, amount: ext_amount };

        Coins::mint(init, balance).unwrap();
        Coins::mint(init, ext_balance.into()).unwrap();

        Dex::add_liquidity(
          Some(init).into(),
          ext_coin,
          sri_amount,
          ext_amount,
          Amount(0),
          Amount(0),
        )
        .unwrap();
        expected_events.push(Event::Dex(serai_abi::dex::Event::LiquidityAddition {
          recipient: init,
          liquidity_tokens: ExternalBalance {
            coin: ext_coin,
            amount: LiquidityTokens::supply(ext_coin),
          },
          sri_amount,
          external_coin_amount: ext_amount,
        }));

        let alice = SeraiAddress::from(Pair::generate().0.public());
        let mut input = Balance { coin: in_coin, amount: Amount(100_000) };
        Coins::mint(alice, input).unwrap();

        let ((Coin::External(ext_coin), _) | (_, Coin::External(ext_coin))) = (in_coin, out_coin)
        else {
          unreachable!()
        };

        let pool = serai_abi::dex::address(ext_coin);

        let route = Premise::route(in_coin, out_coin).unwrap();
        assert_eq!(route.len(), 1);
        let output = route[0]
          .quote_for_in(
            Reserves {
              sri: Coins::balance(pool, Coin::Serai),
              external_coin: Coins::balance(pool, ext_coin),
            },
            input.amount,
          )
          .unwrap();
        let mut output = Balance { coin: out_coin, amount: output };

        let fee = Amount(output.amount.0.div_ceil(10));
        let fee_burnt = Amount(
          (if in_coin == Coin::Serai { input.amount.0 } else { output.amount.0 })
            .div_ceil(10)
            .div_ceil(2),
        );
        output.amount.0 -= fee.0;

        let pool_in = Coins::balance(pool, in_coin);
        let pool_out = Coins::balance(pool, out_coin);

        let existing_events = Core::events().iter().flat_map(IntoIterator::into_iter).count();

        if swap_for {
          Dex::swap_for(
            Some(alice).into(),
            output,
            Balance { coin: in_coin, amount: Amount(u64::MAX) },
          )
          .unwrap();
        } else {
          Dex::swap(Some(alice).into(), input, Balance { coin: out_coin, amount: Amount(0) })
            .unwrap();
        }

        if swap_for {
          assert_eq!(Coins::balance(alice, out_coin), output.amount);
        } else {
          assert_eq!(Coins::balance(alice, in_coin), Amount(0));
        }
        // Allow rounding errors of less than one one-thousandth
        assert!(Coins::balance(alice, in_coin) < Amount(input.amount.0 / 1000));
        assert!(
          (Coins::balance(alice, out_coin) - Amount(output.amount.0)).unwrap() <
            Amount(input.amount.0 / 1000)
        );
        assert!(
          (((pool_in + input.amount).unwrap() -
            (if in_coin == Coin::Serai { fee_burnt } else { Amount(0) }))
          .unwrap() -
            Coins::balance(pool, in_coin))
          .unwrap() <
            Amount(input.amount.0 / 1000)
        );
        assert!(
          (((pool_out - output.amount).unwrap() -
            (if out_coin == Coin::Serai { fee_burnt } else { Amount(0) }))
          .unwrap() -
            Coins::balance(pool, out_coin))
          .unwrap() <
            Amount(output.amount.0 / 1000)
        );

        // Correct the `input` and `output`
        input.amount.0 -= Coins::balance(alice, in_coin).0;
        output.amount.0 = Coins::balance(alice, out_coin).0;

        let events = Core::events()
          .iter()
          .flat_map(IntoIterator::into_iter)
          .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
          .collect::<Vec<_>>();

        let mut transfers = vec![
          Event::Coins(serai_abi::coins::Event::Transfer { from: alice, to: pool, coins: input }),
          Event::Coins(serai_abi::coins::Event::Burn {
            from: pool,
            coins: Balance { coin: Coin::Serai, amount: fee_burnt },
          }),
          Event::Coins(serai_abi::coins::Event::Transfer { from: pool, to: alice, coins: output }),
        ];
        if swap_for {
          transfers.reverse();
        }
        let mut expected_events = transfers;
        expected_events.push(Event::Dex(serai_abi::dex::Event::Swap {
          from: alice,
          deltas: vec![input, output],
        }));

        assert_eq!(&events[existing_events ..], &expected_events);

        assert_eq!(Dex::take_burnt_fees(ext_coin), u128::from(fee_burnt.0));
        assert_eq!(Dex::take_burnt_fees(ext_coin), 0);
      });
    }
  }
}
