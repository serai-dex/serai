use jsonrpsee::types::error::ErrorObjectOwned;

use super::*;

pub(super) enum Error {
  Internal(&'static str),
  InvalidRequest(&'static str),
  InvalidStateReference,
  InvalidTransaction(String),
}

impl From<Error> for ErrorObjectOwned {
  fn from(error: Error) -> Self {
    match error {
      Error::Internal(str) => ErrorObjectOwned::owned(-1, str, Option::<()>::None),
      Error::InvalidRequest(str) => ErrorObjectOwned::owned(-2, str, Option::<()>::None),
      Error::InvalidStateReference => ErrorObjectOwned::owned(
        -3,
        "the block used as the reference was not locally held",
        Option::<()>::None,
      ),
      Error::InvalidTransaction(str) => ErrorObjectOwned::owned(
        -4,
        format!("transaction was not accepted to the mempool: {str}"),
        Option::<()>::None,
      ),
    }
  }
}

pub(super) fn block_hash(
  client: &FullClient,
  params: &Params,
) -> Result<Option<<Block as sp_runtime::traits::Block>::Hash>, Error> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct BlockByHash {
    block: String,
  }
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct BlockByNumber {
    block: u64,
  }

  Ok(if let Ok(block_hash) = params.parse::<BlockByHash>() {
    let Some(block_hash) = hex::decode(&block_hash.block).ok().and_then(|bytes| {
      <[u8; 32]>::try_from(bytes.as_slice())
        .map(<Block as sp_runtime::traits::Block>::Hash::from)
        .ok()
    }) else {
      return Err(Error::InvalidRequest("requested block hash wasn't a valid hash"));
    };
    Some(block_hash)
  } else {
    let Ok(block_number) = params.parse::<BlockByNumber>() else {
      return Err(Error::InvalidRequest("requested block wasn't a valid hash nor number"));
    };
    let Ok(block_hash) = client.block_hash(block_number.block) else {
      return Err(Error::Internal("couldn't fetch block hash for block number"));
    };
    block_hash
  })
}

pub(super) fn network_from_str(network: impl AsRef<str>) -> Result<NetworkId, Error> {
  Ok(match network.as_ref().to_lowercase().as_str() {
    "serai" => NetworkId::Serai,
    "bitcoin" => NetworkId::External(ExternalNetworkId::Bitcoin),
    "ethereum" => NetworkId::External(ExternalNetworkId::Ethereum),
    "monero" => NetworkId::External(ExternalNetworkId::Monero),
    _ => Err(Error::InvalidRequest("unrecognized network requested"))?,
  })
}

pub(super) fn network(params: &Params) -> Result<NetworkId, Error> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Network {
    network: String,
  }

  let Ok(network) = params.parse::<Network>() else {
    Err(Error::InvalidRequest(r#"missing `string` "network" field"#))?
  };

  network_from_str(network.network)
}

pub(super) fn set(params: &Params) -> Result<ValidatorSet, Error> {
  #[derive(sp_core::serde::Deserialize)]
  #[serde(crate = "sp_core::serde")]
  struct Set {
    network: String,
    session: u32,
  }

  let Ok(set) = params.parse::<Set>() else {
    Err(Error::InvalidRequest(r#"missing `object` "set" field"#))?
  };

  Ok(ValidatorSet { network: network_from_str(set.network)?, session: Session(set.session) })
}
