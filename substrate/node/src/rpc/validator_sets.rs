use super::*;

pub(crate) fn module(
  client: Arc<FullClient>,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let mut module = RpcModule::new(client);

  module.register_method(
    "validator-sets/current_session",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };
      let network = network(&params)?;
      let Ok(session) = client.runtime_api().current_session(block_hash, network) else {
        Err(Error::Internal("couldn't fetch the session for the requested network"))?
      };
      Ok(session.map(|session| session.0))
    },
  )?;

  module.register_method(
    "validator-sets/current_stake",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };
      let network = network(&params)?;
      let Ok(stake) = client.runtime_api().current_stake(block_hash, network) else {
        Err(Error::Internal("couldn't fetch the total allocated stake for the requested network"))?
      };
      Ok(stake.map(|stake| stake.0))
    },
  )?;

  module.register_method("validator-sets/keys", |params, client, _ext| -> Result<_, Error> {
    let Some(block_hash) = block_hash(client, &params)? else { Err(Error::InvalidStateReference)? };
    let set = set(&params)?;
    let Ok(set) = ExternalValidatorSet::try_from(set) else {
      Err(Error::InvalidRequest("requested keys for a non-external validator set"))?
    };
    let Ok(key_pair) = client.runtime_api().keys(block_hash, set) else {
      Err(Error::Internal("couldn't fetch the keys for the requested validator set"))?
    };
    Ok(key_pair.map(|key_pair| hex::encode(borsh::to_vec(&key_pair).unwrap())))
  })?;

  module.register_method(
    "validator-sets/current_validators",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };
      let network = network(&params)?;
      let Ok(validators) = client.runtime_api().current_validators(block_hash, network) else {
        Err(Error::Internal("couldn't fetch the current validators for the requested network"))?
      };
      Ok(
        validators.map(|validators| validators.iter().map(ToString::to_string).collect::<Vec<_>>()),
      )
    },
  )?;

  module.register_method(
    "validator-sets/pending_slash_report",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };
      let Ok(set) = ExternalValidatorSet::try_from(set(&params)?) else {
        Err(Error::InvalidRequest(
          "asking if a non-external validator set has a pending slash report",
        ))?
      };
      client
        .runtime_api()
        .pending_slash_report(block_hash, set)
        .map_err(|_| Error::Internal("couldn't fetch if this set has a pending slash report"))
    },
  )?;

  module.register_method(
    "validator-sets/embedded_elliptic_curve_keys",
    |params, client, _ext| -> Result<_, Error> {
      let Some(block_hash) = block_hash(client, &params)? else {
        Err(Error::InvalidStateReference)?
      };

      #[derive(sp_core::serde::Deserialize)]
      #[serde(crate = "sp_core::serde")]
      struct Validator {
        validator: String,
      }
      let Ok(validator) = params.parse::<Validator>() else {
        Err(Error::InvalidRequest(r#"missing `string` "validator" field"#))?
      };
      let Ok(validator) = SeraiAddress::from_str(&validator.validator) else {
        Err(Error::InvalidRequest(r#"validator had an invalid address"#))?
      };

      let network = network(&params)?;
      let Ok(embedded_elliptic_curve_keys) =
        client.runtime_api().embedded_elliptic_curve_keys(block_hash, validator, network)
      else {
        Err(Error::Internal("couldn't fetch the keys for the requested validator set"))?
      };
      Ok(embedded_elliptic_curve_keys.map(|embedded_elliptic_curve_keys| {
        hex::encode(borsh::to_vec(&embedded_elliptic_curve_keys).unwrap())
      }))
    },
  )?;

  Ok(module)
}
