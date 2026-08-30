use alloc::vec::Vec;

use borsh::{io, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
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
///
/// While this object holds the `Call` enumeration whose members may or may not be signed, this
/// container guarantees every call will satisfy `call.is_signed()`. This container also ensures
/// `1 <= len <= Self::MAX_CALLS`.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
pub struct SignedCalls(
  #[borsh(serialize_with = "serai_primitives::sp_borsh::borsh_serialize_bounded_vec")]
  BoundedVec<Call, ConstU32<{ Self::MAX_CALLS }>>,
);

impl SignedCalls {
  /// The maximum amount of signed calls allowed in a transaction.
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

impl BorshDeserialize for SignedCalls {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let calls =
      serai_primitives::sp_borsh::borsh_deserialize_bounded_vec::<_, Call, { Self::MAX_CALLS }>(
        reader,
      )?;
    SignedCalls::try_from(calls.into_inner()).map_err(|e| io::Error::other(alloc::format!("{e:?}")))
  }
}

/// An error regarding `UnsignedCall`.
///
/// While this object holds the `Call` enumeration whose members may or may not be signed, this
/// container guarantees every call will satisfy `!call.is_signed()`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnsignedCallError {
  /// A signed call was specified.
  SignedCall,
}

/// An unsigned call.
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
impl AsRef<Call> for UnsignedCall {
  fn as_ref(&self) -> &Call {
    &self.0
  }
}

impl BorshDeserialize for UnsignedCall {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let call = Call::deserialize_reader(reader)?;
    UnsignedCall::try_from(call).map_err(|e| io::Error::other(alloc::format!("{e:?}")))
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
    /// This is not checked on deserialization and may be invalid.
    contextualized_signature: ContextualizedSignature,
  },
}

impl BorshSerialize for Transaction {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::Unsigned { call } => {
        /*
          `Transaction::Signed` encodes the length of its `Vec<Call>` here. Since that `Vec` is
          bound to be non-empty, it will never write `0`, enabling `Unsigned` to use it as a tag.

          This not only saves a byte but also does still allow defining a Borsh schema for the
          `Transaction` object. Specifically, as an enum,
          - 0: `(Call)`
          - 1: `(Call, ContextualizedSignature)`
          - 2: `(Call, Call, ContextualizedSignature)`
          - 3: ...
          This would require later validation of if the `Call`s were signed or not, of course.
        */
        writer.write_all(&[0])?;
        call.serialize(writer)
      }
      Transaction::Signed { calls, contextualized_signature } => {
        (calls, contextualized_signature).serialize(writer)
      }
    }
  }
}

impl BorshDeserialize for Transaction {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let signed_calls = serai_primitives::sp_borsh::borsh_deserialize_bounded_vec::<
      _,
      Call,
      { SignedCalls::MAX_CALLS },
    >(reader)?;
    if signed_calls.is_empty() {
      return UnsignedCall::deserialize_reader(reader).map(|call| Transaction::Unsigned { call });
    }
    let contextualized_signature = ContextualizedSignature::deserialize_reader(reader)?;
    Ok(Transaction::Signed {
      calls: SignedCalls::try_from(signed_calls.into_inner())
        .map_err(|e| io::Error::other(alloc::format!("{e:?}")))?,
      contextualized_signature,
    })
  }
}

impl Transaction {
  /// The message to sign to produce a signature.
  pub fn signature_message(
    implicit_context: &ImplicitContext,
    calls: &SignedCalls,
    explicit_context: &ExplicitContext,
  ) -> Vec<u8> {
    borsh::to_vec(&(implicit_context, calls, explicit_context)).unwrap()
  }

  /// The unique hash of this transaction.
  ///
  /// No two transactions on the blockchain will share a hash, making this a unique identifier.
  /// For signed transactions, this is due to the `(signer, nonce)` pair present within the
  /// `ExplicitContext`. For unsigned transactions, this is due to inherent properties of their
  /// execution (e.g. only being able to set a `ValidatorSet`'s keys once).
  pub fn hash(&self) -> [u8; 32] {
    let serialization = borsh::to_vec(self).unwrap();
    let mut serialization = serialization.as_slice();
    match self {
      Transaction::Unsigned { .. } => {}
      Transaction::Signed {
        calls: _,
        contextualized_signature: ContextualizedSignature { explicit_context: _, signature },
      } => {
        // We explicitly don't commit to the signature, allowing improving their representation in
        // the future (e.g. with half-aggregation of Schnorr signatures).
        let signature_serialized_len = borsh::object_length(signature).unwrap();
        debug_assert_eq!(
          &serialization[(serialization.len() - signature_serialized_len) ..],
          &borsh::to_vec(signature).unwrap()
        );
        serialization = &serialization[.. (serialization.len() - signature_serialized_len)];
      }
    }
    sp_crypto_hashing::blake2_256(serialization)
  }
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[test]
fn serialize() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};
  use serai_primitives::{
    BlockHash,
    coin::Coin,
    balance::{Amount, Balance},
    crypto::{RistrettoSignature, Signature},
    address::SeraiAddress,
    validator_sets::KeyShares,
  };

  let unsigned_call = {
    let values = serai_primitives::genesis_liquidity::GenesisValues {
      ether: Amount(OsRng.next_u64()),
      dai: Amount(OsRng.next_u64()),
      monero: Amount(OsRng.next_u64()),
    };
    let mut signature_participants = bitvec::vec::BitVec::<_, _>::new();
    #[expect(clippy::range_plus_one)]
    for _ in 0 .. (1 + (OsRng.next_u64() % (KeyShares::MAX_PER_SET_U64 - 1))) {
      signature_participants.push((OsRng.next_u64() % 2) == 1);
    }
    let mut signature = [0; 64];
    OsRng.fill_bytes(&mut signature);
    let signature = RistrettoSignature(signature);
    Call::from(crate::genesis_liquidity::Call::oraclize_values {
      values,
      signature_participants: signature_participants.try_into().unwrap(),
      signature,
    })
  };

  let signed_call = {
    let mut to = [0; 32];
    OsRng.fill_bytes(&mut to);
    let to = SeraiAddress(to);
    let coins = Balance { coin: Coin::Serai, amount: Amount(OsRng.next_u64()) };
    Call::from(crate::coins::Call::transfer { to, coins })
  };

  let explicit_context = {
    let mut historic_block = [0; 32];
    OsRng.fill_bytes(&mut historic_block);
    let historic_block = BlockHash(historic_block);

    let include_by = ((OsRng.next_u64() & 1) == 1).then(|| {
      loop {
        if let Some(include_by) = core::num::NonZero::new(OsRng.next_u64()) {
          break include_by;
        }
      }
    });

    let mut signer = [0; 32];
    OsRng.fill_bytes(&mut signer);
    let signer = SeraiAddress(signer);

    let nonce = OsRng.next_u64() as u32;

    let fee = {
      let coin = {
        let coins = Coin::all().collect::<Vec<_>>();
        coins[(OsRng.next_u64() as usize) % coins.len()]
      };
      let amount = Amount(OsRng.next_u64());
      Balance { coin, amount }
    };

    ExplicitContext { historic_block, include_by, signer, nonce, fee }
  };

  let contextualized_signature = {
    let mut signature = [0; 64];
    OsRng.fill_bytes(&mut signature);
    let signature = Signature::Ristretto(RistrettoSignature(signature));

    ContextualizedSignature { explicit_context: explicit_context.clone(), signature }
  };

  UnsignedCall::try_from(unsigned_call.clone()).unwrap();
  UnsignedCall::try_from(signed_call.clone()).unwrap_err();
  assert_eq!(
    borsh::to_vec(&UnsignedCall::try_from(unsigned_call.clone()).unwrap()).unwrap(),
    borsh::to_vec(&unsigned_call).unwrap()
  );
  UnsignedCall::deserialize_reader(&mut borsh::to_vec(&unsigned_call).unwrap().as_slice()).unwrap();
  UnsignedCall::deserialize_reader(&mut borsh::to_vec(&signed_call).unwrap().as_slice())
    .unwrap_err();
  {
    let transaction =
      Transaction::Unsigned { call: UnsignedCall::try_from(unsigned_call.clone()).unwrap() };
    assert_eq!(
      borsh::to_vec(&transaction).unwrap(),
      borsh::to_vec(&([0u8], &unsigned_call)).unwrap()
    );
    assert_eq!(
      Transaction::deserialize_reader(&mut borsh::to_vec(&transaction).unwrap().as_slice())
        .unwrap(),
      transaction
    );
    assert_eq!(
      transaction.hash(),
      sp_crypto_hashing::blake2_256(&borsh::to_vec(&transaction).unwrap())
    );
  }

  SignedCalls::try_from(vec![]).unwrap_err();
  for i in 1 .. SignedCalls::MAX_CALLS {
    let mut vec = vec![];
    for _ in 0 .. i {
      vec.push(signed_call.clone());
    }
    let calls = SignedCalls::try_from(vec).unwrap();
    assert_eq!(
      SignedCalls::deserialize_reader(&mut borsh::to_vec(&calls).unwrap().as_slice()).unwrap(),
      calls
    );

    let transaction = Transaction::Signed {
      calls: calls.clone(),
      contextualized_signature: contextualized_signature.clone(),
    };
    assert_eq!(
      borsh::to_vec(&transaction).unwrap(),
      borsh::to_vec(&(&calls, &contextualized_signature)).unwrap()
    );
    assert_eq!(
      Transaction::deserialize_reader(&mut borsh::to_vec(&transaction).unwrap().as_slice())
        .unwrap(),
      transaction
    );
    assert_eq!(
      transaction.hash(),
      sp_crypto_hashing::blake2_256(&borsh::to_vec(&(calls, &explicit_context)).unwrap())
    );
  }
  SignedCalls::try_from(vec![unsigned_call]).unwrap_err();
  {
    let mut vec = vec![];
    #[expect(clippy::range_plus_one)]
    for _ in 0 .. (SignedCalls::MAX_CALLS + 1) {
      vec.push(signed_call.clone());
    }
    SignedCalls::try_from(vec).unwrap_err();
  }
}
