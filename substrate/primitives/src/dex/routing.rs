use alloc::{vec, vec::Vec};

use crate::coin::Coin;

use super::Premise;

impl Premise {
  /// Establish the premise of a swap.
  ///
  /// This will return `None` if not exactly one coin is `Coin::Serai`.
  pub fn establish(coin_in: Coin, coin_out: Coin) -> Option<Self> {
    if !((coin_in == Coin::Serai) ^ (coin_out == Coin::Serai)) {
      None?;
    }

    Some(match coin_in {
      Coin::Serai => match coin_out {
        Coin::Serai => unreachable!("prior checked exactly one was `Coin::Serai`"),
        Coin::External(coin) => Premise::FromSerai { to: coin },
      },
      Coin::External(coin) => Premise::ToSerai { from: coin },
    })
  }

  /// Establish the route for a swap.
  ///
  /// This will return `None` if the coin from is the coin to.
  pub fn route(coin_in: Coin, coin_out: Coin) -> Option<Vec<Self>> {
    if coin_in == coin_out {
      None?;
    }
    Some(if (coin_in == Coin::Serai) ^ (coin_out == Coin::Serai) {
      vec![Self::establish(coin_in, coin_out).expect("sri ^ sri")]
    } else {
      // Since they aren't both `Coin::Serai`, and not just one is, neither are
      vec![
        Self::establish(coin_in, Coin::Serai).expect("sri ^ sri #1"),
        Self::establish(Coin::Serai, coin_out).expect("sri ^ sri #2"),
      ]
    })
  }
}

#[test]
fn routing() {
  // serai & serai
  assert!(Premise::establish(Coin::Serai, Coin::Serai).is_none());

  // serai ^ serai
  for coin in Coin::all() {
    if coin == Coin::Serai {
      continue;
    }

    let sri_in = Premise::establish(Coin::Serai, coin).unwrap();
    assert_eq!(sri_in.r#in(), Coin::Serai);
    assert_eq!(sri_in.out(), coin);
    assert_eq!(Coin::External(sri_in.external_coin()), coin);

    let sri_out = Premise::establish(coin, Coin::Serai).unwrap();
    assert_eq!(sri_out.r#in(), coin);
    assert_eq!(sri_out.out(), Coin::Serai);
    assert_eq!(Coin::External(sri_out.external_coin()), coin);
  }

  for coin_in in Coin::all() {
    for coin_out in Coin::all() {
      // !(serai | serai)
      if (coin_in != Coin::Serai) && (coin_out != Coin::Serai) {
        assert!(Premise::establish(coin_in, coin_out).is_none());
      }

      // Routing from in to out
      if coin_in == coin_out {
        assert!(Premise::route(coin_in, coin_out).is_none());
        continue;
      }

      // Since these are different coins, we should be able to create a route
      let route = Premise::route(coin_in, coin_out).unwrap();
      if coin_in == Coin::Serai {
        assert_eq!(route, vec![Premise::establish(Coin::Serai, coin_out).unwrap()]);
      } else if coin_out == Coin::Serai {
        assert_eq!(route, vec![Premise::establish(coin_in, Coin::Serai).unwrap()]);
      } else {
        assert_eq!(
          route,
          vec![
            Premise::establish(coin_in, Coin::Serai).unwrap(),
            Premise::establish(Coin::Serai, coin_out).unwrap()
          ]
        );
      }
    }
  }
}
