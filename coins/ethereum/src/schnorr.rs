use eyre::{eyre, Result};

use group::ff::PrimeField;

use ethers_providers::{Provider, Http};

use crate::{
  Error,
  crypto::{keccak256, PublicKey, Signature},
};
pub use crate::abi::schnorr::*;

pub async fn call_verify(
  contract: &Schnorr<Provider<Http>>,
  public_key: &PublicKey,
  message: &[u8],
  signature: &Signature,
) -> Result<()> {
  if contract
    .verify(
      public_key.parity,
      public_key.px.to_repr().into(),
      keccak256(message),
      signature.c.to_repr().into(),
      signature.s.to_repr().into(),
    )
    .call()
    .await?
  {
    Ok(())
  } else {
    Err(eyre!(Error::InvalidSignature))
  }
}
