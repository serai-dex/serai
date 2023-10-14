use sp_core::sr25519::Public;
use serai_runtime::{
  primitives::{SeraiAddress, SubstrateAmount, Amount, Coin, Balance},
  assets::{AssetDetails, AssetAccount},
  tokens, Tokens, Runtime,
};
pub use tokens::primitives;
use primitives::OutInstruction;

use subxt::tx::Payload;

use crate::{TemporalSerai, SeraiError, Composite, scale_value, scale_composite};

const PALLET: &str = "Tokens";

pub type TokensEvent = tokens::Event<Runtime>;

#[derive(Clone, Copy)]
pub struct SeraiCoins<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiCoins<'a> {
  pub fn into_inner(self) -> TemporalSerai<'a> {
    self.0
  }

  pub async fn mint_events(&self) -> Result<Vec<TokensEvent>, SeraiError> {
    self.0.events::<Tokens, _>(|event| matches!(event, TokensEvent::Mint { .. })).await
  }

  pub async fn burn_events(&self) -> Result<Vec<TokensEvent>, SeraiError> {
    self.0.events::<Tokens, _>(|event| matches!(event, TokensEvent::Burn { .. })).await
  }

  pub async fn sri_balance(&self, address: SeraiAddress) -> Result<u64, SeraiError> {
    let data: Option<
      serai_runtime::system::AccountInfo<u32, serai_runtime::balances::AccountData<u64>>,
    > = self.0.storage("System", "Account", Some(vec![scale_value(address)])).await?;
    Ok(data.map(|data| data.data.free).unwrap_or(0))
  }

  pub async fn token_supply(&self, coin: Coin) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<AssetDetails<SubstrateAmount, SeraiAddress, SubstrateAmount>>(
          "Assets",
          "Asset",
          Some(vec![scale_value(coin)]),
        )
        .await?
        .map(|token| token.supply)
        .unwrap_or(0),
    ))
  }

  pub async fn token_balance(
    &self,
    coin: Coin,
    address: SeraiAddress,
  ) -> Result<Amount, SeraiError> {
    Ok(Amount(
      self
        .0
        .storage::<AssetAccount<SubstrateAmount, SubstrateAmount, (), Public>>(
          "Assets",
          "Account",
          Some(vec![scale_value(coin), scale_value(address)]),
        )
        .await?
        .map(|account| account.balance())
        .unwrap_or(0),
    ))
  }

  pub fn transfer_sri(to: SeraiAddress, amount: Amount) -> Payload<Composite<()>> {
    Payload::new(
      "Balances",
      // TODO: Use transfer_allow_death?
      // TODO: Replace the Balances pallet with something much simpler
      "transfer",
      scale_composite(serai_runtime::balances::Call::<Runtime>::transfer {
        dest: to,
        value: amount.0,
      }),
    )
  }

  pub fn burn(balance: Balance, instruction: OutInstruction) -> Payload<Composite<()>> {
    Payload::new(
      PALLET,
      "burn",
      scale_composite(tokens::Call::<Runtime>::burn { balance, instruction }),
    )
  }
}
