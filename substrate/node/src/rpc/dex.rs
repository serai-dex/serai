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

    let Ok(reserves) = client.runtime_api().pool_reserves(block_hash, external_coin) else {
      Err(Error::Internal("couldn't fetch the reserves for the coin"))?
    };
    Ok(hex::encode(borsh::to_vec(&reserves).unwrap()))
  })?;

  Ok(module)
}
