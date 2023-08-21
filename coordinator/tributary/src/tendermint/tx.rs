use core::ops::Deref;
use std::{io, vec, default::Default};

use scale::Decode;

use zeroize::Zeroizing;

use blake2::{Digest, Blake2s256, Blake2b512};

use rand::{RngCore, CryptoRng};

use ciphersuite::{
  group::{GroupEncoding, ff::Field},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::{
  transaction::{Transaction, TransactionKind, TransactionError},
  ReadWrite,
};

use tendermint::{
  SignedMessageFor, Data,
  round::RoundData,
  time::CanonicalInstant,
  commit_msg,
  ext::{Network, Commit, RoundNumber, SignatureScheme},
};

/// Signing data for a slash vote.
///
/// The traditional Signed uses a nonce, whereas votes aren't required/expected to be ordered.
/// Accordingly, a simple uniqueness check works instead.
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
      signature: SchnorrSignature::<Ristretto>::read(&mut [0; 64].as_slice()).unwrap(),
    }
  }
}

/// A vote to slash a malicious validator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlashVote {
  pub id: [u8; 13],       // vote id(slash event id)
  pub target: [u8; 32],   // who to slash
  pub sig: VoteSignature, // signature
}

impl ReadWrite for SlashVote {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut id = [0; 13];
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
  SlashVote(SlashVote),
}

impl ReadWrite for TendermintTx {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let mut len = [0; 4];
        reader.read_exact(&mut len)?;
        let mut len =
          usize::try_from(u32::from_le_bytes(len)).expect("running on a 16-bit system?");

        let mut data = vec![];

        // Read chunk-by-chunk so a claimed 4 GB length doesn't cause a 4 GB allocation
        // While we could check the length is sane, that'd require we know what a sane length is
        // We'd also have to maintain that length's sanity even as other parts of the codebase,
        // and even entire crates, change
        // This is fine as it'll eventually hit the P2P message size limit, yet doesn't require
        // knowing it nor does it make any assumptions
        const CHUNK_LEN: usize = 1024;
        let mut chunk = [0; CHUNK_LEN];
        while len > 0 {
          let to_read = len.min(CHUNK_LEN);
          data.reserve(to_read);
          reader.read_exact(&mut chunk[.. to_read])?;
          data.extend(&chunk[.. to_read]);
          len -= to_read;
        }
        Ok(TendermintTx::SlashEvidence(data))
      }
      1 => {
        let vote = SlashVote::read(reader)?;
        Ok(TendermintTx::SlashVote(vote))
      }
      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      TendermintTx::SlashEvidence(ev) => {
        writer.write_all(&[0])?;
        writer.write_all(&u32::try_from(ev.len()).unwrap().to_le_bytes())?;
        writer.write_all(ev)
      }
      TendermintTx::SlashVote(vote) => {
        writer.write_all(&[1])?;
        vote.write(writer)
      }
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
    let mut tx = self.serialize();
    if let TendermintTx::SlashVote(vote) = self {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), vote.sig.signature.serialize());
    }
    Blake2s256::digest(tx).into()
  }

  fn sig_hash(&self, genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    match self {
      TendermintTx::SlashEvidence(_) => panic!("sig_hash called on slash evidence transaction"),
      TendermintTx::SlashVote(vote) => {
        let signature = &vote.sig.signature;
        <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(
          &Blake2b512::digest(
            [
              b"Tributary Slash Vote",
              genesis.as_ref(),
              &self.hash(),
              signature.R.to_bytes().as_ref(),
            ]
            .concat(),
          )
          .into(),
        )
      }
    }
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
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
        TendermintTx::SlashVote(vote) => Some(&mut vote.sig),
        _ => None,
      }
    }

    signature(self).unwrap().signer = Ristretto::generator() * key.deref();

    let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));
    signature(self).unwrap().signature.R =
      <Ristretto as Ciphersuite>::generator() * sig_nonce.deref();

    let sig_hash = self.sig_hash(genesis);

    signature(self).unwrap().signature =
      SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
  }
}

pub fn decode_evidence<N: Network>(
  mut ev: &[u8],
) -> Result<(SignedMessageFor<N>, Option<SignedMessageFor<N>>), TransactionError> {
  <(SignedMessageFor<N>, Option<SignedMessageFor<N>>)>::decode(&mut ev).map_err(|_| {
    dbg!("failed to decode");
    TransactionError::InvalidContent
  })
}

// TODO: Move this into tendermint-machine
// TODO: Strongly type Evidence, instead of having two messages and no idea what's supposedly
// wrong with them. Doing so will massively simplify the auditability of this (as this
// re-implements an entire foreign library's checks for malicious behavior).
pub(crate) fn verify_tendermint_tx<N: Network>(
  tx: &TendermintTx,
  genesis: [u8; 32],
  schema: N::SignatureScheme,
  commit: impl Fn(u32) -> Option<Commit<N::SignatureScheme>>,
) -> Result<(), TransactionError> {
  tx.verify()?;

  match tx {
    TendermintTx::SlashEvidence(ev) => {
      let (first, second) = decode_evidence::<N>(ev)?;

      // verify that evidence messages are signed correctly
      if !first.verify_signature(&schema) {
        Err(TransactionError::InvalidSignature)?
      }
      let first = first.msg;

      if let Some(second) = second {
        if !second.verify_signature(&schema) {
          Err(TransactionError::InvalidSignature)?
        }
        let second = second.msg;

        // 2 types of evidence here
        // 1- multiple distinct messages for the same block + round + step
        // 2- precommitted to multiple blocks

        // Make sure they're distinct messages, from the same sender, within the same block
        if (first == second) || (first.sender != second.sender) || (first.block != second.block) {
          Err(TransactionError::InvalidContent)?;
        }

        // Distinct messages within the same step
        if (first.round == second.round) && (first.data.step() == second.data.step()) {
          return Ok(());
        }

        // check whether messages are precommits to different blocks
        // The inner signatures don't need to be verified since the outer signatures were
        // While the inner signatures may be invalid, that would've yielded a invalid precommit
        // signature slash instead of distinct precommit slash
        if let Data::Precommit(Some((h1, _))) = first.data {
          if let Data::Precommit(Some((h2, _))) = second.data {
            if h1 == h2 {
              Err(TransactionError::InvalidContent)?;
            }
            return Ok(());
          }
        }

        // No fault identified
        Err(TransactionError::InvalidContent)?
      }

      // 2 types of evidence can be here
      // 1- invalid commit signature
      // 2- vr number that was greater than or equal to the current round
      match &first.data {
        Data::Proposal(vr, _) => {
          // check the vr
          if vr.is_none() || vr.unwrap().0 < first.round.0 {
            Err(TransactionError::InvalidContent)?
          }
        }
        Data::Precommit(Some((id, sig))) => {
          // TODO: We need to be passed in the genesis time to handle this edge case
          if first.block.0 == 0 {
            todo!("invalid precommit signature on first block")
          }

          // get the last commit
          // TODO: Why do we use u32 when Tendermint uses u64?
          let prior_commit = match u32::try_from(first.block.0 - 1) {
            Ok(n) => match commit(n) {
              Some(c) => c,
              // If we have yet to sync the block in question, we will return InvalidContent based
              // on our own temporal ambiguity
              // This will also cause an InvalidContent for anything using a non-existent block,
              // yet that's valid behavior
              // TODO: Double check the ramifications of this
              _ => Err(TransactionError::InvalidContent)?,
            },
            _ => Err(TransactionError::InvalidContent)?,
          };

          // calculate the end time till the msg round
          let mut last_end_time = CanonicalInstant::new(prior_commit.end_time);
          for r in 0 ..= first.round.0 {
            last_end_time = RoundData::<N>::new(RoundNumber(r), last_end_time).end_time();
          }

          // verify that the commit was actually invalid
          if schema.verify(first.sender, &commit_msg(last_end_time.canonical(), id.as_ref()), sig) {
            Err(TransactionError::InvalidContent)?
          }
        }
        _ => Err(TransactionError::InvalidContent)?,
      }
    }
    TendermintTx::SlashVote(vote) => {
      // TODO: verify the target is actually one of our validators?
      // this shouldn't be a problem because if the target isn't valid, no one else
      // gonna vote on it. But we still have to think about spam votes.

      // TODO: we need to check signer is a participant

      // TODO: Move this into the standalone TendermintTx verify
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
