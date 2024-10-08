use sp_core::bounded_vec::BoundedVec;
use serai_abi::primitives::{Amount, Coin, ExternalCoin, SeraiAddress};

use crate::{SeraiError, TemporalSerai};

pub type DexEvent = serai_abi::dex::Event;

const PALLET: &str = "Dex";

#[derive(Clone, Copy)]
pub struct SeraiDex<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiDex<'a> {
  pub async fn events(&self) -> Result<Vec<DexEvent>, SeraiError> {
    self
      .0
      .events(
        |event| if let serai_abi::Event::Dex(event) = event { Some(event.clone()) } else { None },
      )
      .await
  }

  pub fn add_liquidity(
    coin: ExternalCoin,
    coin_amount: Amount,
    sri_amount: Amount,
    min_coin_amount: Amount,
    min_sri_amount: Amount,
    address: SeraiAddress,
  ) -> serai_abi::Call {
    serai_abi::Call::Dex(serai_abi::dex::Call::add_liquidity {
      coin,
      coin_desired: coin_amount.0,
      sri_desired: sri_amount.0,
      coin_min: min_coin_amount.0,
      sri_min: min_sri_amount.0,
      mint_to: address,
    })
  }

  pub fn swap(
    from_coin: Coin,
    to_coin: Coin,
    amount_in: Amount,
    amount_out_min: Amount,
    address: SeraiAddress,
  ) -> serai_abi::Call {
    let path = if to_coin.is_native() {
      BoundedVec::try_from(vec![from_coin, Coin::Serai]).unwrap()
    } else if from_coin.is_native() {
      BoundedVec::try_from(vec![Coin::Serai, to_coin]).unwrap()
    } else {
      BoundedVec::try_from(vec![from_coin, Coin::Serai, to_coin]).unwrap()
    };

    serai_abi::Call::Dex(serai_abi::dex::Call::swap_exact_tokens_for_tokens {
      path,
      amount_in: amount_in.0,
      amount_out_min: amount_out_min.0,
      send_to: address,
    })
  }

  /// Returns the reserves of `coin:SRI` pool.
  pub async fn get_reserves(
    &self,
    coin: ExternalCoin,
  ) -> Result<Option<(Amount, Amount)>, SeraiError> {
    self.0.runtime_api("DexApi_get_reserves", (Coin::from(coin), Coin::Serai)).await
  }

  pub async fn oracle_value(&self, coin: ExternalCoin) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "SecurityOracleValue", coin).await
  }
}
