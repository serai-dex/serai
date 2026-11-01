use alloc::vec::Vec;
use std::io;

use borsh::{BorshSerialize as _, BorshDeserialize as _};

use tendermint::SlashReason;

use crate::ReadWrite;
use super::{ValidatorSet, AggregateSignature, SignatureScheme};

type Signature = [u8; 64];
type Hash = [u8; 32];

/// A slash for a validator.
///
/// When included in a block, the validator is not excluded from the Tendermint consensus process.
/// The validator's signed transactions WILL NOT be accepted into the mempool anymore however. The
/// application SHOULD also restrict this validator from future participation at the application
/// level.
#[derive(Clone, Debug)]
pub struct Slash {
  pub(super) validator: [u8; 32],
  pub(super) slash_reason: SlashReason<Signature, AggregateSignature, Hash>,
}

impl Slash {
  /// The slashed validator.
  pub fn validator(&self) -> &[u8; 32] {
    &self.validator
  }

  /// Verify a slash.
  pub(crate) fn verify(
    &self,
    genesis: [u8; 32],
    validator_set: &ValidatorSet,
    signature_scheme: &SignatureScheme,
  ) -> Result<(), ::tendermint::InvalidReason> {
    self.slash_reason.verify(genesis, validator_set, signature_scheme, self.validator)
  }
}

impl ReadWrite for Slash {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let validator = <[u8; 32]>::deserialize_reader(&mut reader)?;
    let slash_reason = SlashReason::deserialize_reader(&mut reader)?;
    Ok(Slash { validator, slash_reason })
  }

  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Self { validator, slash_reason } = self;
    validator.serialize(&mut writer)?;
    slash_reason.serialize(&mut writer)
  }

  fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(128);
    self.write(&mut res).expect("`<Vec<u8> as io::Write>` is infallible");
    res
  }
}

impl crate::merkle::Digestible for Slash {
  /// This solely hashes the validator as the semantics of this are independent of the exact reason
  /// why this validator is being slashed.
  fn update(&self, digest: &mut (impl ?Sized + blake2::digest::Update)) {
    digest.update(&self.validator);
  }
}
