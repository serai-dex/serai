use borsh::BorshDeserialize as _;

use serai_abi::primitives::{coin::ExternalCoin, dex::Reserves};

use crate::{RpcError, State, rpc_coin};

impl State<'_> {
  /// Returns reserves for a given pool.
  pub async fn pool_reserves(&self, coin: ExternalCoin) -> Result<Reserves, RpcError> {
    let result = self
      .call::<String>("dex/pool-reserves", &format!(r#", "coin": {} "#, rpc_coin(coin)))
      .await?;
    let bytes = hex::decode(result)
      .map_err(|_| RpcError::ErrorInResponse("node sent invalid hex string".to_owned()))?;
    let reserves = Reserves::try_from_reader(&mut bytes.as_slice())
      .map_err(|_| RpcError::ErrorInResponse("node sent invalid reserves response".to_owned()))?;
    Ok(reserves)
  }
}
