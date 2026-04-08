use serai_abi::primitives::coin::ExternalCoin;

use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method(
    "liquidity-tokens/balance",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };

      #[derive(sp_core::serde::Deserialize)]
      #[serde(crate = "sp_core::serde")]
      struct Address {
        address: String,
      }
      let Ok(address) = params.parse::<Address>() else {
        Err(Error::InvalidRequest(r#"missing `string` "address" field"#))?
      };
      let Ok(address) = SeraiAddress::from_str(&address.address) else {
        Err(Error::InvalidRequest(r#"invalid serai address"#))?
      };

      let coin = coin(&params)?;
      let external_coin: ExternalCoin =
        coin.try_into().map_err(|()| Error::InvalidRequest("coin is not external coin"))?;

      let Ok(amount) = client.runtime_api().liquidity_balance(block_hash, address, external_coin)
      else {
        Err(Error::Internal("couldn't fetch liquidity balance for the address"))?
      };
      Ok(amount.0)
    },
  )?;

  module.register_method(
    "liquidity-tokens/supply",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };

      let coin = coin(&params)?;
      let external_coin: ExternalCoin =
        coin.try_into().map_err(|()| Error::InvalidRequest("coin is not external coin"))?;

      let Ok(amount) = client.runtime_api().liquidity_supply(block_hash, external_coin) else {
        Err(Error::Internal("couldn't fetch liquidity supply for the coin"))?
      };
      Ok(amount.0)
    },
  )?;

  Ok(module)
}
