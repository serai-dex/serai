use core::ops::Deref;
use std::{io, vec, default::Default};

use scale::Decode;

use zeroize::Zeroizing;

use blake2::{Digest, Blake2s256, Blake2b512};

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

/// Data for a signed transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlashVote {
  pub id: [u8; 32],         // vote id(slash event id)
  pub target: [u8; 32],     // who to slash 
  pub sig: VoteSignature    // signature
}

impl ReadWrite for SlashVote {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut id = [0; 32];
    let mut target = [0; 32];
    reader.read_exact(&mut id)?;
    reader.read_exact(&mut target)?;
    let sig = VoteSignature::read(reader)?;

    Ok(SlashVote { id, target, sig })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.id)?;
    writer.write_all(&self.target)?;
    self.sig.write(writer)
  }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TendermintTx {
  SlashEvidence(Vec<u8>),
  // TODO: should the SlashVote.sig be directly in the enum
  // like as in (SlashVote, sig) since the sig is sig of the tx.
  SlashVote(SlashVote)
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
        let vote = SlashVote::read(reader)?;
        Ok(TendermintTx::SlashVote(vote))
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
      TendermintTx::SlashVote(vote) => {
        writer.write_all(&[1])?;
        vote.write(writer)
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
    let mut tx = self.serialize();
    if let TendermintTx::SlashVote(vote) = self {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), vote.sig.signature.serialize());
    }
    Blake2s256::digest(tx).into()
  }

  /// Obtain the challenge for this transaction's signature.
  ///
  /// Do not override this unless you know what you're doing.
  ///
  /// Panics if called on non-signed transactions.
  fn sig_hash(&self, genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    match self {
      TendermintTx::SlashVote(vote) => {
        let signature = &vote.sig.signature;
        <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(
          &Blake2b512::digest(
            [genesis.as_ref(), &self.hash(), signature.R.to_bytes().as_ref()].concat(),
          )
          .into(),
        )
      },
      _ => panic!("sig_hash called on non-signed evidence transaction"),
    }
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

    // return from here for non-signed txs so that
    // rest of the function is cleaner.
    match self {
      TendermintTx::SlashEvidence(_) => return,
      TendermintTx::SlashVote(_)=> {}
    }

    fn signature(tx: &mut TendermintTx) -> Option<&mut VoteSignature> {
      match tx {
        TendermintTx::SlashVote(vote) => {
          Some(&mut vote.sig)
        },
        _ => None
      }
    }

    signature(self).unwrap().signer = Ristretto::generator() * key.deref();
    
    let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));
    signature(self).unwrap().signature.R = <Ristretto as Ciphersuite>::generator() * sig_nonce.deref();

    let sig_hash = self.sig_hash(genesis);

    signature(self).unwrap().signature = SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
  }
}


pub fn decode_evidence<N: Network>(ev: &[u8]) -> Result<Vec<SignedMessageFor<N>>, TransactionError> {
  let mut res = vec![];

  // first byte is the length of the message vector
  let len = u8::from_le_bytes([ev[0]]);
  let mut pos: usize = 1;
  for _ in 0..len {
    // get the msg size
    // make sure we aren't out of range
    let Some(size_bytes) =  ev.get(pos..pos+4) else {
      Err(TransactionError::InvalidContent)?
    };
    let Ok(size) = usize::try_from(u32::from_le_bytes(size_bytes.try_into().unwrap())) else {
      Err(TransactionError::InvalidContent)?
    };
    pos += 4;

    // size might be intentionally bigger then whole slice
    let Some(mut msg_bytes) =  ev.get(pos..pos+size) else {
      Err(TransactionError::InvalidContent)?
    };
    let Ok(msg) = SignedMessageFor::<N>::decode::<&[u8]>(
      &mut msg_bytes
    ) else {
      Err(TransactionError::InvalidContent)?
    };
    pos += size;
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

          match &msg.data {
            Data::Proposal(vr, _) => {
              // check the vr
              if vr.is_none() || vr.unwrap().0 < msg.round.0 {
                Err(TransactionError::InvalidContent)?
              }
            },
            Data::Precommit(Some((id, sig))) => {

              // make sure block no isn't overflowing
              // TODO: is rejecting the evidence right thing to do here?
              // if this is the first block, there is no prior_commit, hence
              // no prior end_time. Is the end_tine is just 0 in that case?
              // on the other hand, are we even able to get precommit slash evidence in the first block?
              if msg.block.0 == 0 {
                Err(TransactionError::InvalidContent)?
              }

              // get the last commit
              let prior_commit = match u32::try_from(msg.block.0 - 1) {
                Ok(n) =>  match commit(n) {
                  Some(c) => c,
                  _ => Err(TransactionError::InvalidContent)? 
                } ,
                _ => Err(TransactionError::InvalidContent)?
              };

              // calculate the end time till the msg round
              let mut last_end_time = CanonicalInstant::new(prior_commit.end_time);
              for r in 0 ..= msg.round.0 {
                last_end_time = RoundData::<N>::new(RoundNumber(r), last_end_time).end_time();
              }

              // verify that the commit was actually invalid
              if schema.verify(msg.sender, &commit_msg(last_end_time.canonical(), id.as_ref()), sig) {
                Err(TransactionError::InvalidContent)?
              }
            },
            _ => Err(TransactionError::InvalidContent)?
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

          // check whether messages are precommits to different blocks.
          // signatures aren't important here because they must be valid anyways.
          // if they weren't, we should have gotten an invalid precommit sig evidence
          // in the first place instead of this.
          if let Data::Precommit(Some((h1, _))) = first.data {
            if let Data::Precommit(Some((h2, _))) = second.data {
              if h1 == h2 {
                Err(TransactionError::InvalidContent)?
              } else {
                return Ok(());
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
    TendermintTx::SlashVote(vote) => {

      // TODO: verify the target is actually one of our validators?
      // this shouldn't be a problem because if the target isn't valid, no one else
      // gonna vote on it. But we still have to think about spam votes.

      // TODO: we should check signer is a participant?

      let sig = &vote.sig;
      // verify the tx signature
      // TODO: Use Schnorr half-aggregation and a batch verification here 
      if !sig.signature.verify(sig.signer, tx.sig_hash(genesis)) {
        Err(TransactionError::InvalidSignature)?;
      }
    }
  }

  Ok(())
}