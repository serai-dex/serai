use serai_runtime::{
  dex, Dex, Runtime,
  primitives::{Coin, SeraiAddress, Amount},
};

use subxt::tx::Payload;

use crate::{Serai, SeraiError, Composite, scale_composite};

pub type DexEvent = dex::Event<Runtime>;

const PALLET: &str = "Dex";

impl Serai {
  pub async fn dex_events(&self, block: [u8; 32]) -> Result<Vec<DexEvent>, SeraiError> {
    self
      .events::<Dex, _>(block, |event| {
        matches!(
          event,
          DexEvent::PoolCreated { .. } |
            DexEvent::LiquidityAdded { .. } |
            DexEvent::SwapExecuted { .. } |
            DexEvent::LiquidityRemoved { .. } |
            DexEvent::Transfer { .. }
        )
      })
      .await
  }

  pub fn create_pool(coin: Coin) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "create_pool",
      scale_composite(dex::Call::<Runtime>::create_pool { asset1: coin, asset2: Coin::Serai }),
    )
  }

  pub fn add_liquidity(
    coin: Coin,
    coin_amount: Amount,
    sri_amount: Amount,
    min_coin_amount: Amount,
    min_sri_amount: Amount,
    address: SeraiAddress,
  ) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "add_liquidity",
      scale_composite(dex::Call::<Runtime>::add_liquidity {
        asset1: coin,
        asset2: Coin::Serai,
        amount1_desired: coin_amount.0,
        amount2_desired: sri_amount.0,
        amount1_min: min_coin_amount.0,
        amount2_min: min_sri_amount.0,
        mint_to: address.into(),
      }),
    )
  }
}
