use core::ops::Deref;
use std::{io, vec, default::Default, mem::size_of};

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

use tendermint::{
  SignedMessageFor, Data, round::RoundData, time::CanonicalInstant, commit_msg,
  ext::{Network, Commit, RoundNumber, SignatureScheme}
};

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

#[allow(clippy::large_enum_variant)]
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
      TendermintTx::SlashEvidence(..) => TransactionKind::Unsigned,
      TendermintTx::SlashVote(..) => TransactionKind::Unsigned
    }
  }

  fn hash(&self) -> [u8; 32] {
    let tx = self.serialize();
    Blake2s256::digest(tx).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    match self {
      TendermintTx::SlashEvidence(ev) => {
        // TODO: is this check really useful? at the end this can be any number
        // that isn't related to how many SignedMessages we have in the vector.

        // verify that vec len contains 1 or 2 SignedMessage.
        let size = u8::from_le_bytes([ev[0]]);
        if size == 0 || size > 2 {
          Err(TransactionError::InvalidContent)?;
        }

        Ok(())
      },
      TendermintTx::SlashVote(..) => {
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


pub fn decode_evidence<N: Network>(ev: &[u8]) -> Result<Vec<SignedMessageFor<N>>, TransactionError> {
  let mut res = vec![];
  let msg_size = size_of::<SignedMessageFor<N>>();
  
  // first byte is the length of the message vector
  let len = u8::from_le_bytes([ev[0]]);
  let mut start: usize = 1;
  let mut stop = 1 + msg_size;
  for _ in 0..len {
    let Ok(msg) = SignedMessageFor::<N>::decode::<&[u8]>(
      &mut &ev[start..stop]
    ) else {
      Err(TransactionError::InvalidContent)?
    };
    start = stop;
    stop = start + msg_size;
    res.push(msg);
  }
  Ok(res)
}

pub(crate) fn verify_tendermint_tx<N: Network>(
  tx: &TendermintTx,
  genesis: [u8; 32],
  schema: N::SignatureScheme,
  commit: impl Fn (u32) -> Option<Commit<N::SignatureScheme>>
) -> Result<(), TransactionError> {

  tx.verify()?;

  match tx {
    TendermintTx::SlashEvidence(ev) => {
      let msgs = decode_evidence::<N>(ev)?;

      // verify that evidence messages are signed correctly
      for msg in &msgs {
        if !msg.verify_signature(&schema) {
          Err(TransactionError::InvalidSignature)?
        }
      }

      // verify that the evidence is actually malicious
      match msgs.len() {
        1 => {
          // 2 types of evidence can be here
          // 1- invalid commit signature
          // 2- vr number that was greater than the current round
          let msg = &msgs[0].msg;

          // check the vr
          if let Data::Proposal(vr, _) = &msg.data {
            if vr.is_none() || vr.unwrap().0 < msg.round.0 {
              Err(TransactionError::InvalidContent)?
            }
          }

          // check whether the commit was actually invalid
          if let Data::Precommit(Some((id, sig))) = &msg.data {
            let bl_no = u32::try_from(msg.block.0 - 1);
            if bl_no.is_err() {
              Err(TransactionError::InvalidContent)? 
            }

            let prior_commit = commit(bl_no.unwrap());
            if prior_commit.is_none() {
              Err(TransactionError::InvalidContent)? 
            }

            // calculate the end time till the msg round
            let mut last_end_time = CanonicalInstant::new(prior_commit.unwrap().end_time);
            for r in 0 ..= msg.round.0 {
              last_end_time = RoundData::<N>::new(RoundNumber(r), last_end_time).end_time();
            }

            // verify that the commit was actually invalid
            if schema.verify(msg.sender, &commit_msg(last_end_time.canonical(), id.as_ref()), sig) {
              Err(TransactionError::InvalidContent)?
            }
          }

        },
        2 => {
          // 2 types of evidence here
          // 1- multiple distinct messages for the same block + round + step
          // 2- precommitted to multiple blocks
          let first = &msgs[0].msg;
          let second = &msgs[1].msg;

          // conflicting messages must be for the same block
          if first.block != second.block {
            Err(TransactionError::InvalidContent)? 
          }

          // verify it is from the same node
          if first.sender != second.sender {
            Err(TransactionError::InvalidContent)?
          }

          // check whether messages are precommits to different blocks
          if let Data::Precommit(Some((h1, _))) = first.data {
            if let Data::Precommit(Some((h2, _))) = second.data {
              if h1 == h2 {
                Err(TransactionError::InvalidContent)?
              }
            }
          }

          // verify that msgs are for the same round + step but has distinct data
          if first.round != second.round || first.data.step() != second.data.step() || first.data == second.data {
            Err(TransactionError::InvalidContent)?
          }
        },
        _ => {
          Err(TransactionError::InvalidContent)?
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