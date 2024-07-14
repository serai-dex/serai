use std::io;

use scale::{Encode, Decode, IoReader};

use blake2::{Digest, Blake2s256};

use ciphersuite::{Ciphersuite, Ristretto};

use crate::{
  transaction::{Transaction, TransactionKind, TransactionError},
  ReadWrite,
};

use tendermint::{
  verify_tendermint_evidence,
  ext::{Network, Commit},
};

pub use tendermint::{Evidence, decode_signed_message};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TendermintTx {
  SlashEvidence(Evidence),
}

impl ReadWrite for TendermintTx {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Evidence::decode(&mut IoReader(reader))
      .map(TendermintTx::SlashEvidence)
      .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid evidence format"))
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      TendermintTx::SlashEvidence(ev) => writer.write_all(&ev.encode()),
    }
  }
}

impl Transaction for TendermintTx {
  fn kind(&self) -> TransactionKind<'_> {
    // There's an assert elsewhere in the codebase expecting this behavior
    // If we do want to add Provided/Signed TendermintTxs, review the implications carefully
    TransactionKind::Unsigned
  }

  fn hash(&self) -> [u8; 32] {
    Blake2s256::digest(self.serialize()).into()
  }

  fn sig_hash(&self, _genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    match self {
      TendermintTx::SlashEvidence(_) => panic!("sig_hash called on slash evidence transaction"),
    }
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

pub(crate) fn verify_tendermint_tx<N: Network>(
  tx: &TendermintTx,
  schema: &N::SignatureScheme,
  commit: impl Fn(u64) -> Option<Commit<N::SignatureScheme>>,
) -> Result<(), TransactionError> {
  tx.verify()?;

  match tx {
    TendermintTx::SlashEvidence(ev) => verify_tendermint_evidence::<N>(ev, schema, commit)
      .map_err(|_| TransactionError::InvalidContent)?,
  }

  Ok(())
}
