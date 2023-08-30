use serai_runtime::{
  dex, Dex, Runtime,
  primitives::{Coin, SubstrateAmount, SeraiAddress},
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

  pub fn create_pool(asset: Coin) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "create_pool",
      scale_composite(dex::Call::<Runtime>::create_pool { asset1: asset, asset2: Coin::Serai }),
    )
  }

  pub fn add_liquidity(
    asset: Coin,
    asset_amount: SubstrateAmount,
    sri_amount: SubstrateAmount,
    min_asset_amount: SubstrateAmount,
    min_sri_amount: SubstrateAmount,
    address: SeraiAddress,
  ) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "add_liquidity",
      scale_composite(dex::Call::<Runtime>::add_liquidity {
        asset1: asset,
        asset2: Coin::Serai,
        amount1_desired: asset_amount,
        amount2_desired: sri_amount,
        amount1_min: min_asset_amount,
        amount2_min: min_sri_amount,
        mint_to: address.into(),
      }),
    )
  }
}
