use core::ops::Deref;
use std::{io, vec, default::Default};

use scale::Decode;

use zeroize::Zeroizing;

use blake2::{Digest, Blake2s256};

use rand::{RngCore, CryptoRng};

use ciphersuite::{
  group::{
    GroupEncoding,
    ff::Field,
  },
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::{
  transaction::{Transaction, TransactionKind, TransactionError},
  ReadWrite
};

use tendermint::{ext::Network, SignedMessageFor};

/// Data for a signed transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VoteSignature {
  pub signer: <Ristretto as Ciphersuite>::G,
  pub signature: SchnorrSignature<Ristretto>,
}

impl ReadWrite for VoteSignature {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let signer = Ristretto::read_G(reader)?;
    let signature = SchnorrSignature::<Ristretto>::read(reader)?;

    Ok(VoteSignature { signer, signature })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.signer.to_bytes())?;
    self.signature.write(writer)
  }
}

impl Default for VoteSignature {
  fn default() -> Self {
    VoteSignature {
      signer: Ristretto::generator(),
      signature: SchnorrSignature::<Ristretto>::default(),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TendermintTx {
  SlashEvidence(Vec<u8>),
  SlashVote([u8; 32], VoteSignature)
}

impl ReadWrite for TendermintTx {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let mut len = [0; 4];
        reader.read_exact(&mut len)?;
        let mut data = vec![0; usize::try_from(u32::from_le_bytes(len)).unwrap()];
        reader.read_exact(&mut data)?;
        Ok(TendermintTx::SlashEvidence(data))
      }
      1 => {
        let mut id = [0; 32];
        reader.read_exact(&mut id)?;
        let sig = VoteSignature::read(reader)?;
        Ok(TendermintTx::SlashVote(id, sig))
      },
      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      TendermintTx::SlashEvidence(ev) => {
        writer.write_all(&[0])?;
        writer.write_all(&u32::try_from(ev.len()).unwrap().to_le_bytes())?;
        writer.write_all(ev)
      },
      TendermintTx::SlashVote(vote, sig) => {
        writer.write_all(&[1])?;
        writer.write_all(vote)?;
        sig.write(writer)
      }
    }
  }
}

impl Transaction for TendermintTx {
  fn kind(&self) -> TransactionKind<'_> {
    match self {
      TendermintTx::SlashEvidence(_) => TransactionKind::Unsigned,
      TendermintTx::SlashVote(_, _) => TransactionKind::Unsigned
    }
  }

  fn hash(&self) -> [u8; 32] {
    let tx = self.serialize();
    Blake2s256::digest(tx).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    match self {
      TendermintTx::SlashEvidence(_) => {
        // TODO: verify that vec len contains 1 or 2 signedmessage.

        // let size = evidence.0.len();
        // if size <= 0 || size > 2 {
        //   Err(TransactionError::InvalidContent)?;
        // }

        Ok(())
      },
      TendermintTx::SlashVote(_, _) => {
        Ok(())
      }
    }
  }
}

impl TendermintTx {

  // Sign a transaction
  pub fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    genesis: [u8; 32],
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) {
    fn signature(tx: &mut TendermintTx) -> Option<&mut VoteSignature> {
      match tx {
        TendermintTx::SlashVote(_, sig) => {
          Some(sig)
        },
        _ => None
      }
    }

    let sig_hash = self.sig_hash(genesis);
    if let Some(sig) = signature(self) {
      sig.signer = Ristretto::generator() * key.deref();
      sig.signature = SchnorrSignature::<Ristretto>::sign(
        key,
        Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng)),
        sig_hash,
      );
    }
  }
}


fn decode_evidence<N: Network>(ev: &Vec<u8>) -> Result<Vec<SignedMessageFor<N>>, TransactionError> {
  let mut res = vec![];

  // first byte is the length of the message vector
  // how many messages we are supposed to have in the vector.
  let size = u8::from_le_bytes([ev[0]]);
  for _ in 0..size {
    let Ok(msg) = SignedMessageFor::<N>::decode::<&[u8]>(
      &mut &ev[1 ..]
    ) else {
      Err(TransactionError::InvalidContent)?
    };
    res.push(msg);
  }
  Ok(res)
}


// This will only cause mutations when the transaction is valid
pub(crate) fn verify_tendermint_tx<N: Network>(
  tx: &TendermintTx,
  genesis: [u8; 32],
  schema: N::SignatureScheme
) -> Result<(), TransactionError> {

  match tx {
    TendermintTx::SlashEvidence(ev) => {
      let msgs = decode_evidence::<N>(ev)?;
      
      // verify that evidence messages are signed correctly
      for msg in msgs {
        if !msg.verify_signature(&schema) {
          Err(TransactionError::InvalidSignature)?
        }
      }
    },
    TendermintTx::SlashVote(_, sig) => {
      // verify the tx signature
      // TODO: Use Schnorr half-aggregation and a batch verification here 
      if !sig.signature.verify(sig.signer, tx.sig_hash(genesis)) {
        Err(TransactionError::InvalidSignature)?;
      }
    }
  }

  Ok(())
}