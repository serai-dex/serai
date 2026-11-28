use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method("core/next-nonce", |params, client, _ext| -> Result<_, Error> {
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

    let Ok(nonce) = client.runtime_api().account_nonce(block_hash, address) else {
      Err(Error::Internal("couldn't fetch the nonce for the address"))?
    };
    Ok(nonce)
  })?;

  module.register_method("core/implicit-context", |_params, client, _ext| -> Result<_, Error> {
    let info = client.info();

    let Ok(protocol_id) = client.runtime_api().protocol_id(info.best_hash) else {
      Err(Error::Internal("couldn't fetch the protocol ID"))?
    };

    let implicit_context =
      serai_abi::ImplicitContext { genesis_block_hash: info.genesis_hash.into(), protocol_id };
    Ok(hex::encode(borsh::to_vec(&implicit_context).unwrap()))
  })?;

  Ok(module)
}
