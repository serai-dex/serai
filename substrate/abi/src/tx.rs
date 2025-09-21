#![allow(deprecated)]

use scale::Encode;

use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::Verify;

use serai_primitives::SeraiAddress;

use frame_support::dispatch::GetDispatchInfo;

pub trait TransactionMember:
  Clone + PartialEq + Eq + core::fmt::Debug + scale::Encode + scale::Decode
{
}
impl<T: Clone + PartialEq + Eq + core::fmt::Debug + scale::Encode + scale::Decode> TransactionMember
  for T
{
}

type TransactionEncodeAs<'a, Extra> =
  (&'a crate::Call, &'a Option<(SeraiAddress, Signature, Extra)>);
type TransactionDecodeAs<Extra> = (crate::Call, Option<(SeraiAddress, Signature, Extra)>);

// We use our own Transaction struct, over UncheckedExtrinsic, for more control, a bit more
// simplicity, and in order to be immune to https://github.com/paritytech/polkadot-sdk/issues/2947
#[allow(clippy::multiple_bound_locations)]
#[derive(Clone, PartialEq, Eq, Debug, scale::DecodeWithMemTracking)]
pub struct Transaction<
  Call: 'static + TransactionMember + From<crate::Call>,
  Extra: 'static + TransactionMember,
> {
  call: crate::Call,
  mapped_call: Call,
  signature: Option<(SeraiAddress, Signature, Extra)>,
}

impl<Call: 'static + TransactionMember + From<crate::Call>, Extra: 'static + TransactionMember>
  Transaction<Call, Extra>
{
  pub fn new(call: crate::Call, signature: Option<(SeraiAddress, Signature, Extra)>) -> Self {
    Self { call: call.clone(), mapped_call: call.into(), signature }
  }

  pub fn call(&self) -> &crate::Call {
    &self.call
  }
}

impl<Call: 'static + TransactionMember + From<crate::Call>, Extra: 'static + TransactionMember>
  scale::Encode for Transaction<Call, Extra>
{
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    let tx: TransactionEncodeAs<Extra> = (&self.call, &self.signature);
    tx.using_encoded(f)
  }
}
impl<Call: 'static + TransactionMember + From<crate::Call>, Extra: 'static + TransactionMember>
  scale::Decode for Transaction<Call, Extra>
{
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let (call, signature) = TransactionDecodeAs::decode(input)?;
    let mapped_call = Call::from(call.clone());
    Ok(Self { call, mapped_call, signature })
  }
}

#[cfg(feature = "serde")]
mod _serde {
  use scale::Encode;
  use serde::ser::*;
  use super::*;
  impl<Call: 'static + TransactionMember + From<crate::Call>, Extra: 'static + TransactionMember>
    Serialize for Transaction<Call, Extra>
  {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
      let encoded = self.encode();
      serializer.serialize_bytes(&encoded)
    }
  }

  #[cfg(feature = "std")]
  use serde::de::*;
  #[cfg(feature = "std")]
  impl<
      'a,
      Call: 'static + TransactionMember + From<crate::Call>,
      Extra: 'static + TransactionMember,
    > Deserialize<'a> for Transaction<Call, Extra>
  {
    fn deserialize<D: Deserializer<'a>>(de: D) -> Result<Self, D::Error> {
      let bytes = sp_core::bytes::deserialize(de)?;
      <Self as scale::Decode>::decode(&mut &bytes[..])
        .map_err(|e| serde::de::Error::custom(format!("invalid transaction: {e}")))
    }
  }
}

impl<
    Call: 'static + TransactionMember + From<crate::Call> + TryInto<crate::Call>,
    Extra: 'static + TransactionMember,
  > sp_runtime::traits::Extrinsic for Transaction<Call, Extra>
{
  type Call = Call;
  type SignaturePayload = (SeraiAddress, Signature, Extra);
  fn is_signed(&self) -> Option<bool> {
    Some(self.signature.is_some())
  }
  fn new(call: Call, signature: Option<Self::SignaturePayload>) -> Option<Self> {
    Some(Self { call: call.clone().try_into().ok()?, mapped_call: call, signature })
  }
}

impl<
    Call: 'static + TransactionMember + From<crate::Call> + TryInto<crate::Call>,
    Extra: 'static + TransactionMember,
  > frame_support::sp_runtime::traits::ExtrinsicCall for Transaction<Call, Extra>
{
  type Call = Call;
  fn call(&self) -> &Call {
    &self.mapped_call
  }
}

impl<
    Call: 'static + TransactionMember + From<crate::Call> + GetDispatchInfo,
    Extra: 'static + TransactionMember,
  > GetDispatchInfo for Transaction<Call, Extra>
{
  fn get_dispatch_info(&self) -> frame_support::dispatch::DispatchInfo {
    self.mapped_call.get_dispatch_info()
  }
}

use sp_runtime::generic::ExtrinsicFormat;
impl<
    Call: 'static + TransactionMember + From<crate::Call> + sp_runtime::traits::Dispatchable,
    Extra: 'static + TransactionMember + sp_runtime::traits::TransactionExtension<Call>,
  > sp_runtime::traits::BlindCheckable for Transaction<Call, Extra>
{
  type Checked = sp_runtime::generic::CheckedExtrinsic<Public, Call, Extra>;

  fn check(
    self,
  ) -> Result<Self::Checked, sp_runtime::transaction_validity::TransactionValidityError> {
    Ok(match self.signature {
      Some((signer, signature, extra)) => {
        if !signature
          .verify((&self.call, &extra, extra.implicit()?).encode().as_slice(), &signer.into())
        {
          Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof)?
        }

        sp_runtime::generic::CheckedExtrinsic {
          format: ExtrinsicFormat::Signed(signer.into(), extra),
          function: self.mapped_call,
        }
      }
      None => sp_runtime::generic::CheckedExtrinsic {
        format: ExtrinsicFormat::Bare,
        function: self.mapped_call,
      },
    })
  }
}

impl<
    Call: 'static + TransactionMember + From<crate::Call> + TryInto<crate::Call>,
    Extra: 'static + TransactionMember,
  > frame_support::traits::InherentBuilder for Transaction<Call, Extra>
{
  /// Panics if the inherent isn't supported.
  // TODO: Don't panic here
  fn new_inherent(call: Self::Call) -> Self {
    sp_runtime::traits::Extrinsic::new(call, None).expect("trying to build an unsupported inherent")
  }
}
