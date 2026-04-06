use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("dex/pool-reserves", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };

    let coin = coin(&params)?;
    let external_coin: ExternalCoin =
      coin.try_into().map_err(|()| Error::InvalidRequest("coin is not external coin"))?;

    let address = serai_abi::dex::address(external_coin);
    let Ok(sri_balance) = client.runtime_api().balance(block_hash, address, Coin::Serai) else {
      Err(Error::Internal("couldn't fetch the sri balance of the pool"))?
    };
    let Ok(external_coin_balance) =
      client.runtime_api().balance(block_hash, address, external_coin.into())
    else {
      Err(Error::Internal("couldn't fetch the external coin balance of the pool"))?
    };

    #[derive(Clone, sp_core::serde::Serialize)]
    #[serde(crate = "sp_core::serde")]
    struct Reserves {
      sri: u64,
      external_coin: u64,
    }

    Ok(Reserves { sri: sri_balance.0, external_coin: external_coin_balance.0 })
  })?;

  Ok(module)
}
