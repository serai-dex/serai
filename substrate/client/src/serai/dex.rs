use sp_core::bounded_vec::BoundedVec;
use serai_abi::primitives::{SeraiAddress, Amount, Coin};

use scale::{decode_from_bytes, Encode};

use crate::{Serai, SeraiError, TemporalSerai};

pub type DexEvent = serai_abi::dex::Event;

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
    coin: Coin,
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
  pub async fn get_reserves(&self, coin: Coin) -> Result<Option<(Amount, Amount)>, SeraiError> {
    let reserves = self
      .0
      .serai
      .call(
        "state_call",
        ["DexApi_get_reserves".to_string(), hex::encode((coin, Coin::Serai).encode())],
      )
      .await?;
    let bytes = Serai::hex_decode(reserves)?;
    let result = decode_from_bytes::<Option<(u64, u64)>>(bytes.into())
      .map_err(|e| SeraiError::ErrorInResponse(e.to_string()))?;
    Ok(result.map(|amounts| (Amount(amounts.0), Amount(amounts.1))))
  }
}
