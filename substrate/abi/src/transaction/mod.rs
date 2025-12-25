use alloc::vec::Vec;

use borsh::{io, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
use serai_primitives::{BlockHash, address::SeraiAddress, balance::Amount};
use crate::Call;

mod context;
pub use context::*;

#[cfg(feature = "substrate")]
mod substrate;
#[cfg(feature = "substrate")]
pub use substrate::*;

/// An error regarding `SignedCalls`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignedCallsError {
  /// No calls were included.
  NoCalls,
  /// Too many calls were included.
  TooManyCalls,
  /// An unsigned call was included.
  IncludedUnsignedCall,
}

/// A `Vec` of signed calls.
// We don't implement BorshDeserialize due to to maintained invariants on this struct.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
pub struct SignedCalls(
  #[borsh(serialize_with = "serai_primitives::sp_borsh::borsh_serialize_bounded_vec")]
  BoundedVec<Call, ConstU32<{ Self::MAX_CALLS }>>,
);

impl SignedCalls {
  /// The maximum amount of calls allowed in a transaction.
  const MAX_CALLS: u32 = 8;
}

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
    calls.try_into().map_err(|_| SignedCallsError::TooManyCalls).map(SignedCalls)
  }
}

/// An error regarding `UnsignedCall`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnsignedCallError {
  /// A signed call was specified.
  SignedCall,
}

/// An unsigned call.
// We don't implement BorshDeserialize due to to maintained invariants on this struct.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
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

/// A Serai transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  /// An unsigned transaction.
  Unsigned {
    /// The contained call.
    call: UnsignedCall,
  },
  /// A signed transaction.
  Signed {
    /// The calls.
    ///
    /// These calls are executed atomically. Either all successfully execute or none do. The
    /// transaction's fee is paid regardless.
    calls: SignedCalls,
    /// The signature for this transaction.
    ///
    /// This is not checked on deserializtion and may be invalid.
    contextualized_signature: ContextualizedSignature,
  },
}

impl BorshSerialize for Transaction {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::Unsigned { call } => {
        /*
          `Signed` `Transaction`s encode the length of their `Vec<Call>` here. Since that `Vec` is
          bound to be non-empty, it will never write `0`, enabling `Unsigned` to use it.

          The benefit to these not overlapping is in the ability to determine if the `Transaction`
          has a signature or not. If this wrote a `1`, for the amount of `Call`s present in the
          `Transaction`, that `Call` would have to be introspected for if its signed or not. With
          the usage of `0`, given how low `MAX_CALLS` is, this `Transaction` can technically be
          defined as an enum of
          `0 Call, 1 Call ContextualizedSignature, 2 Call Call ContextualizedSignature ...`, to
          maintain compatbility with the borsh specification without wrapper functions. The checks
          here on `Call` types/quantity could be moved to later validation functions.
        */
        writer.write_all(&[0])?;
        call.serialize(writer)
      }
      Transaction::Signed { calls, contextualized_signature } => {
        serai_primitives::sp_borsh::borsh_serialize_bounded_vec(&calls.0, writer)?;
        contextualized_signature.serialize(writer)
      }
    }
  }
}

impl BorshDeserialize for Transaction {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0xff];
    reader.read_exact(&mut len)?;
    let len = len[0];

    if len == 0 {
      let call = Call::deserialize_reader(reader)?;
      if call.is_signed() {
        #[cfg_attr(feature = "std", expect(clippy::io_other_error))]
        Err(io::Error::new(io::ErrorKind::Other, "call was signed but marked unsigned"))?;
      }
      Ok(Transaction::Unsigned { call: UnsignedCall(call) })
    } else {
      if u32::from(len) > SignedCalls::MAX_CALLS {
        #[cfg_attr(feature = "std", expect(clippy::io_other_error))]
        Err(io::Error::new(io::ErrorKind::Other, "too many calls"))?;
      }
      let mut calls = BoundedVec::with_bounded_capacity(len.into());
      for _ in 0 .. len {
        let call = Call::deserialize_reader(reader)?;
        if !call.is_signed() {
          #[cfg_attr(feature = "std", expect(clippy::io_other_error))]
          Err(io::Error::new(io::ErrorKind::Other, "call was unsigned but included as signed"))?;
        }
        calls.try_push(call).unwrap();
      }
      let contextualized_signature = ContextualizedSignature::deserialize_reader(reader)?;
      Ok(Transaction::Signed { calls: SignedCalls(calls), contextualized_signature })
    }
  }
}

impl Transaction {
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
    calls.serialize(&mut message).unwrap();
    implicit_context.serialize(&mut message).unwrap();
    explicit_context.serialize(&mut message).unwrap();
    message
  }

  /// The unique hash of this transaction.
  ///
  /// No two transactions on the blockchain will share a hash, making this a unique identifier.
  /// For signed transactions, this is due to the `(signer, nonce)` pair present within the
  /// `ExplicitContext`. For unsigned transactions, this is due to inherent properties of their
  /// execution (e.g. only being able to set a `ValidatorSet`'s keys once).
  pub fn hash(&self) -> [u8; 32] {
    sp_core::blake2_256(&match self {
      Transaction::Unsigned { call } => borsh::to_vec(&call).unwrap(),
      Transaction::Signed {
        calls,
        contextualized_signature: ContextualizedSignature { explicit_context, signature: _ },
      } => {
        // We explicitly don't hash the signature, so signatures can be replaced in the future if
        // desired (such as with half-aggregated Schnorr signatures)
        borsh::to_vec(&(calls, explicit_context)).unwrap()
      }
    })
  }
}
