use pallet_assets::{AssetDetails, AssetAccount};

use serai_runtime::{
  primitives::{SeraiAddress, SubstrateAmount, Amount, Coin},
  tokens, Tokens, Runtime,
};
pub use tokens::primitives;

use crate::{Serai, SeraiError, scale_value};

// const PALLET: &str = "Tokens";

pub type TokensEvent = tokens::Event<Runtime>;

impl Serai {
  pub async fn get_mint_events(&self, block: [u8; 32]) -> Result<Vec<TokensEvent>, SeraiError> {
    self.events::<Tokens, _>(block, |event| matches!(event, TokensEvent::Mint { .. })).await
  }

  pub async fn get_token_supply(&self, block: [u8; 32], coin: Coin) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .storage::<AssetDetails<SubstrateAmount, SeraiAddress, SubstrateAmount>>(
          "Assets",
          "Asset",
          Some(vec![scale_value(coin)]),
          block,
        )
        .await?
        .map(|token| token.supply)
        .unwrap_or(0),
    ))
  }

  pub async fn get_token_balance(
    &self,
    block: [u8; 32],
    coin: Coin,
    address: SeraiAddress,
  ) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .storage::<AssetAccount<SubstrateAmount, SubstrateAmount, ()>>(
          "Assets",
          "Account",
          // For some reason, scale_value address converts it to a string
          // This preserves the intended [u8; 32] API
          Some(vec![scale_value(coin), scale_value(address.0)]),
          block,
        )
        .await?
        .map(|account| account.balance)
        .unwrap_or(0),
    ))
  }
}
