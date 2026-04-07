use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("coins/balance", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };

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
    let Ok(amount) = client.runtime_api().balance(block_hash, address, coin) else {
      Err(Error::Internal("couldn't fetch balance for the address"))?
    };
    Ok(amount.0)
  })?;

  module.register_method("coins/supply", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };

    let coin = coin(&params)?;
    let Ok(amount) = client.runtime_api().supply(block_hash, coin) else {
      Err(Error::Internal("couldn't fetch the supply for the coin"))?
    };
    Ok(amount.0)
  })?;

  Ok(module)
}
