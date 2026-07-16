use std::io;

use borsh::{BorshSerialize as _, BorshDeserialize as _};

use blake2::{Digest as _, Blake2s256};

use dalek_ff_group::Ristretto;
use ciphersuite::*;

use tendermint::{SignatureScheme, Block, Blockchain, SlashReason};

use crate::{
  ReadWrite,
  transaction::{Transaction, TransactionKind, TransactionError},
  TendermintBlock,
};

#[derive(Clone, Debug)]
pub struct TendermintTx {
  pub(crate) validator: [u8; 32],
  pub(crate) slash_reason: SlashReason<[u8; 64], Vec<u8>, <TendermintBlock as Block>::Hash>,
}

impl TendermintTx {
  pub fn slashed(&self) -> [u8; 32] {
    self.validator
  }
}

impl ReadWrite for TendermintTx {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let validator = <[u8; 32]>::deserialize_reader(&mut reader)?;
    let slash_reason = SlashReason::deserialize_reader(&mut reader)?;
    Ok(TendermintTx { validator, slash_reason })
  }

  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    let Self { validator, slash_reason } = self;
    validator.serialize(&mut writer)?;
    slash_reason.serialize(&mut writer)
  }
}

impl Transaction for TendermintTx {
  fn kind(&self) -> TransactionKind {
    // There's an assert elsewhere in the codebase expecting this behavior
    // If we do want to add Provided/Signed TendermintTxs, review the implications carefully
    TransactionKind::Unsigned
  }

  fn hash(&self) -> [u8; 32] {
    Blake2s256::digest(self.serialize()).into()
  }

  fn sig_hash(&self, _genesis: [u8; 32]) -> <Ristretto as WrappedGroup>::F {
    panic!("sig_hash called on slash evidence transaction")
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

pub(crate) fn verify_tendermint_tx<
  N: Blockchain<
    Validator = [u8; 32],
    SignatureScheme: SignatureScheme<Signature = [u8; 64], AggregateSignature = Vec<u8>>,
  >,
>(
  tx: &TendermintTx,
  genesis: [u8; 32],
  validator_set: &N::ValidatorSet,
  schema: &N::SignatureScheme,
) -> Result<(), TransactionError> {
  tx.verify()?;

  tx.slash_reason
    .verify(genesis, validator_set, schema, tx.validator)
    .map_err(|_| TransactionError::InvalidContent)
}
