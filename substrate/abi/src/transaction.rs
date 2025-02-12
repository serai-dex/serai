use core::num::NonZero;
use alloc::{vec, vec::Vec};

use borsh::{io, BorshSerialize, BorshDeserialize};

use serai_primitives::{address::SeraiAddress, crypto::Signature};
use crate::Call;

// use frame_support::dispatch::GetDispatchInfo;

/// An error regarding `SignedCalls`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignedCallsError {
  /// No calls were included.
  NoCalls,
  /// An unsigned call was included.
  IncludedUnsignedCall,
}

/// A `Vec` of signed calls.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCalls(Vec<Call>);
impl TryFrom<Vec<Call>> for SignedCalls {
  type Error = SignedCallsError;
  fn try_from(calls: Vec<Call>) -> Result<Self, Self::Error> {
    if calls.is_empty() {
      Err(SignedCallsError::NoCalls)?;
    }
    for call in &calls {
      if !call.is_signed() {
        Err(SignedCallsError::IncludedUnsignedCall)?;
      }
    }
    Ok(SignedCalls(calls))
  }
}

/// An error regarding `UnsignedCall`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnsignedCallError {
  /// A signed call was specified.
  SignedCall,
}

/// An unsigned call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedCall(Call);
impl TryFrom<Call> for UnsignedCall {
  type Error = UnsignedCallError;
  fn try_from(call: Call) -> Result<Self, Self::Error> {
    if call.is_signed() {
      Err(UnsignedCallError::SignedCall)?;
    }
    Ok(UnsignedCall(call))
  }
}

/// Part of the context used to sign with, from the protocol.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ImplicitContext {
  /// The ID of the the protocol.
  pub protocol_id: [u8; 32],
  /// The genesis hash of the blockchain.
  pub genesis: [u8; 32],
}

/// Part of the context used to sign with, specified within the transaction itself.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ExplicitContext {
  /// The historic block this transaction builds upon.
  ///
  /// This transaction can not be included in a blockchain which does not include this block.
  pub historic_block: [u8; 32],

  /// The block this transaction expires at.
  ///
  /// This transaction can not be included in a block whose number is equal or greater to this
  /// value.
  pub expires_at: Option<NonZero<u64>>,

  /// The signer.
  pub signer: SeraiAddress,

  /// The signer's nonce.
  pub nonce: u32,

  /// The fee paid to the network for inclusion.
  ///
  /// This fee is paid regardless of the success of any of the calls.
  pub fee: u64,
}

/// A signature, with context.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct ContextualizedSignature {
  /// The explicit context.
  explicit_context: ExplicitContext,
  /// The signature.
  signature: Signature,
}

/// The Serai transaction type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction<RuntimeCall: 'static + From<Call> = Call> {
  /// The calls, as defined in Serai's ABI.
  ///
  /// These calls are executed atomically. Either all successfully execute or none do. The
  /// transaction's fee is paid regardless.
  // TODO: Bound
  calls: Vec<Call>,
  /// The calls, as defined by Substrate.
  runtime_calls: Vec<RuntimeCall>,
  /// The signature, if present.
  contextualized_signature: Option<ContextualizedSignature>,
}

impl<RuntimeCall: 'static + From<Call>> BorshSerialize for Transaction<RuntimeCall> {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    // Write the calls
    self.calls.serialize(writer)?;
    // Write the signature, if present. Presence is deterministic to the calls
    if let Some(contextualized_signature) = self.contextualized_signature.as_ref() {
      contextualized_signature.serialize(writer)?;
    }
    Ok(())
  }
}

impl<RuntimeCall: 'static + From<Call>> BorshDeserialize for Transaction<RuntimeCall> {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    // Read the calls
    let calls = Vec::<Call>::deserialize_reader(reader)?;
    // Populate the runtime calls
    let mut runtime_calls = Vec::with_capacity(calls.len());
    for call in calls.iter().cloned() {
      runtime_calls.push(RuntimeCall::from(call));
    }

    // Determine if this is signed or unsigned
    let mut signed = None;
    for call in &calls {
      let call_is_signed = call.is_signed();
      if signed.is_none() {
        signed = Some(call_is_signed)
      };
      if signed != Some(call_is_signed) {
        Err(io::Error::new(io::ErrorKind::Other, "calls were a mixture of signed and unsigned"))?;
      }
    }
    let Some(signed) = signed else {
      Err(io::Error::new(io::ErrorKind::Other, "transaction had no calls"))?
    };

    // Read the signature, if these calls are signed
    let contextualized_signature =
      if signed { Some(<ContextualizedSignature>::deserialize_reader(reader)?) } else { None };

    Ok(Transaction { calls, runtime_calls, contextualized_signature })
  }
}

impl<RuntimeCall: 'static + From<Call>> Transaction<RuntimeCall> {
  /// The message to sign to produce a signature.
  pub fn signature_message(
    calls: &SignedCalls,
    implicit_context: &ImplicitContext,
    explicit_context: &ExplicitContext,
  ) -> Vec<u8> {
    let mut message = Vec::with_capacity(
      (calls.0.len() * 64) +
        core::mem::size_of::<ImplicitContext>() +
        core::mem::size_of::<ExplicitContext>(),
    );
    calls.0.serialize(&mut message).unwrap();
    implicit_context.serialize(&mut message).unwrap();
    explicit_context.serialize(&mut message).unwrap();
    message
  }

  /// A transaction with signed calls.
  pub fn is_signed(
    calls: SignedCalls,
    explicit_context: ExplicitContext,
    signature: Signature,
  ) -> Self {
    let calls = calls.0;
    let mut runtime_calls = Vec::with_capacity(calls.len());
    for call in calls.iter().cloned() {
      runtime_calls.push(call.into());
    }
    Self {
      calls,
      runtime_calls,
      contextualized_signature: Some(ContextualizedSignature { explicit_context, signature }),
    }
  }

  /// A transaction with an unsigned call.
  pub fn unsigned(call: UnsignedCall) -> Self {
    let call = call.0;
    Self {
      calls: vec![call.clone()],
      runtime_calls: vec![call.into()],
      contextualized_signature: None,
    }
  }
}

#[cfg(feature = "substrate")]
mod substrate {
  use super::*;

  impl scale::Encode for Transaction {
    fn encode(&self) -> Vec<u8> {
      borsh::to_vec(self).unwrap()
    }
  }
  impl scale::Decode for Transaction {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
      struct ScaleRead<'a, I: scale::Input>(&'a mut I);
      impl<I: scale::Input> borsh::io::Read for ScaleRead<'_, I> {
        fn read(&mut self, buf: &mut [u8]) -> borsh::io::Result<usize> {
          let remaining_len = self
            .0
            .remaining_len()
            .map_err(|err| borsh::io::Error::new(borsh::io::ErrorKind::Other, err))?;
          // If we're still calling `read`, we try to read at least one more byte
          let to_read = buf.len().min(remaining_len.unwrap_or(1));
          self
            .0
            .read(&mut buf[.. to_read])
            .map_err(|err| borsh::io::Error::new(borsh::io::ErrorKind::Other, err))?;
          Ok(to_read)
        }
      }
      Self::deserialize_reader(&mut ScaleRead(input)).map_err(|err| err.downcast().unwrap())
    }
  }
  impl<RuntimeCall: 'static + From<Call>> sp_runtime::traits::ExtrinsicLike
    for Transaction<RuntimeCall>
  {
    fn is_signed(&self) -> Option<bool> {
      Some(self.calls[0].is_signed())
    }
    fn is_bare(&self) -> bool {
      !self.calls[0].is_signed()
    }
  }
  /*
  impl<
      Call: 'static + TransactionMember + From<Call> + TryInto<Call>,
    > sp_runtime::traits::Extrinsic for Transaction<Call>
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
    > frame_support::traits::ExtrinsicCall for Transaction<Call, Extra>
  {
    fn call(&self) -> &Call {
      &self.mapped_call
    }
  }

  impl<
      Call: 'static + TransactionMember + From<crate::Call>,
    > sp_runtime::traits::ExtrinsicMetadata for Transaction<Call, Extra>
  {
    type SignedExtensions = Extra;

    const VERSION: u8 = 0;
  }

  impl<
      Call: 'static + TransactionMember + From<crate::Call> + GetDispatchInfo,
    > GetDispatchInfo for Transaction<Call, Extra>
  {
    fn get_dispatch_info(&self) -> frame_support::dispatch::DispatchInfo {
      self.mapped_call.get_dispatch_info()
    }
  }

  impl<
      Call: 'static + TransactionMember + From<crate::Call>,
    > sp_runtime::traits::BlindCheckable for Transaction<Call, Extra>
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
            function: self.mapped_call,
          }
        }
        None => sp_runtime::generic::CheckedExtrinsic { signed: None, function: self.mapped_call },
      })
    }
  }
  */
}
