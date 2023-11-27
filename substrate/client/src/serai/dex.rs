use sp_core::bounded_vec::BoundedVec;
use serai_runtime::{
  primitives::{SeraiAddress, Amount, Coin},
  dex, Runtime,
};

use crate::{SeraiError, TemporalSerai};

pub type DexEvent = dex::Event<Runtime>;

#[derive(Clone, Copy)]
pub struct SeraiDex<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiDex<'a> {
  pub async fn events(&self) -> Result<Vec<DexEvent>, SeraiError> {
    self
      .0
      .events(
        |event| {
          if let serai_runtime::RuntimeEvent::Dex(event) = event {
            Some(event)
          } else {
            None
          }
        },
      )
      .await
  }

  pub fn add_liquidity(
    coin: Coin,
    coin_amount: Amount,
    sri_amount: Amount,
    min_coin_amount: Amount,
    min_sri_amount: Amount,
    address: SeraiAddress,
  ) -> serai_runtime::RuntimeCall {
    serai_runtime::RuntimeCall::Dex(dex::Call::<Runtime>::add_liquidity {
      coin,
      coin_desired: coin_amount.0,
      sri_desired: sri_amount.0,
      coin_min: min_coin_amount.0,
      sri_min: min_sri_amount.0,
      mint_to: address.into(),
    })
  }

  pub fn swap(
    from_coin: Coin,
    to_coin: Coin,
    amount_in: Amount,
    amount_out_min: Amount,
    address: SeraiAddress,
  ) -> serai_runtime::RuntimeCall {
    let path = if to_coin.is_native() {
      BoundedVec::try_from(vec![from_coin, Coin::Serai]).unwrap()
    } else if from_coin.is_native() {
      BoundedVec::try_from(vec![Coin::Serai, to_coin]).unwrap()
    } else {
      BoundedVec::try_from(vec![from_coin, Coin::Serai, to_coin]).unwrap()
    };

    serai_runtime::RuntimeCall::Dex(dex::Call::<Runtime>::swap_exact_tokens_for_tokens {
      path,
      amount_in: amount_in.0,
      amount_out_min: amount_out_min.0,
      send_to: address.into(),
    })
  }
}
