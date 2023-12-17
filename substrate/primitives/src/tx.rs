use scale::Encode;

use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::Verify;

use crate::SeraiAddress;

trait TransactionMember:
  Clone + PartialEq + Eq + core::fmt::Debug + scale::Encode + scale::Decode + scale_info::TypeInfo
{
}
impl<
    T: Clone
      + PartialEq
      + Eq
      + core::fmt::Debug
      + scale::Encode
      + scale::Decode
      + scale_info::TypeInfo,
  > TransactionMember for T
{
}

#[allow(private_bounds)]
#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub struct Transaction<Call: TransactionMember, Extra: TransactionMember> {
  pub call: Call,
  pub signature: Option<(SeraiAddress, Signature, Extra)>,
}

#[cfg(feature = "serde")]
mod _serde {
  use scale::Encode;
  use serde::{ser::*, de::*};
  use super::*;
  impl<Call: TransactionMember, Extra: TransactionMember> Serialize for Transaction<Call, Extra> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
      let encoded = self.encode();
      serializer.serialize_bytes(&encoded)
    }
  }
  #[cfg(feature = "std")]
  impl<'a, Call: TransactionMember, Extra: TransactionMember> Deserialize<'a>
    for Transaction<Call, Extra>
  {
    fn deserialize<D: Deserializer<'a>>(de: D) -> Result<Self, D::Error> {
      let bytes = sp_core::bytes::deserialize(de)?;
      scale::Decode::decode(&mut &bytes[..])
        .map_err(|e| serde::de::Error::custom(format!("invalid transaction: {e}")))
    }
  }
}

impl<Call: TransactionMember, Extra: TransactionMember> sp_runtime::traits::Extrinsic
  for Transaction<Call, Extra>
{
  type Call = Call;
  type SignaturePayload = (SeraiAddress, Signature, Extra);
  fn is_signed(&self) -> Option<bool> {
    Some(self.signature.is_some())
  }
  fn new(call: Call, signature: Option<Self::SignaturePayload>) -> Option<Self> {
    Some(Self { call, signature })
  }
}

impl<Call: TransactionMember, Extra: TransactionMember> frame_support::traits::ExtrinsicCall
  for Transaction<Call, Extra>
{
  fn call(&self) -> &Call {
    &self.call
  }
}

impl<Call: TransactionMember, Extra: TransactionMember> sp_runtime::traits::ExtrinsicMetadata
  for Transaction<Call, Extra>
where
  Extra: sp_runtime::traits::SignedExtension,
{
  type SignedExtensions = Extra;

  const VERSION: u8 = 0;
}

impl<Call: TransactionMember, Extra: TransactionMember> frame_support::dispatch::GetDispatchInfo
  for Transaction<Call, Extra>
where
  Call: frame_support::dispatch::GetDispatchInfo,
{
  fn get_dispatch_info(&self) -> frame_support::dispatch::DispatchInfo {
    self.call.get_dispatch_info()
  }
}

impl<Call: TransactionMember, Extra: TransactionMember> sp_runtime::traits::BlindCheckable
  for Transaction<Call, Extra>
where
  Extra: sp_runtime::traits::SignedExtension,
{
  type Checked = sp_runtime::generic::CheckedExtrinsic<Public, Call, Extra>;

  fn check(
    self,
  ) -> Result<Self::Checked, sp_runtime::transaction_validity::TransactionValidityError> {
    Ok(match self.signature {
      Some((signer, signature, extra)) => {
        if !signature.verify(
          (&self.call, &extra, extra.additional_signed()?).encode().as_slice(),
          &signer.into(),
        ) {
          Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof)?
        }

        sp_runtime::generic::CheckedExtrinsic {
          signed: Some((signer.into(), extra)),
          function: self.call,
        }
      }
      None => sp_runtime::generic::CheckedExtrinsic { signed: None, function: self.call },
    })
  }
}
