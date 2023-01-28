use serai_runtime::{
  primitives::{SeraiAddress, SubstrateAmount, Amount, Coin, Balance},
  assets::{AssetDetails, AssetAccount},
  tokens, Tokens, Runtime,
};
pub use tokens::primitives;
use primitives::OutInstruction;

use subxt::tx::{self, DynamicTxPayload};

use crate::{Serai, SeraiError, scale_value, scale_composite};

const PALLET: &str = "Tokens";

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
          Some(vec![scale_value(coin), scale_value(address)]),
          block,
        )
        .await?
        .map(|account| account.balance)
        .unwrap_or(0),
    ))
  }

  pub fn burn(balance: Balance, instruction: OutInstruction) -> DynamicTxPayload<'static> {
    tx::dynamic(
      PALLET,
      "burn",
      scale_composite(tokens::Call::<Runtime>::burn { balance, instruction }),
    )
  }

  pub async fn get_burn_events(&self, block: [u8; 32]) -> Result<Vec<TokensEvent>, SeraiError> {
    self.events::<Tokens, _>(block, |event| matches!(event, TokensEvent::Burn { .. })).await
  }
}
