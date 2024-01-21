use std::io;

use scale::{Encode, Decode, IoReader};

use blake2::{Digest, Blake2s256};

use ciphersuite::{Ciphersuite, Ristretto};

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

pub use tendermint::Evidence;

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

pub fn decode_signed_message<N: Network>(
  mut data: &[u8],
) -> Result<SignedMessageFor<N>, TransactionError> {
  SignedMessageFor::<N>::decode(&mut data).map_err(|_| TransactionError::InvalidContent)
}

fn decode_and_verify_signed_message<N: Network>(
  data: &[u8],
  schema: &N::SignatureScheme,
) -> Result<SignedMessageFor<N>, TransactionError> {
  let msg = decode_signed_message::<N>(data)?;

  // verify that evidence messages are signed correctly
  if !msg.verify_signature(schema) {
    Err(TransactionError::InvalidSignature)?
  }
  Ok(msg)
}

// TODO: Move this into tendermint-machine
// This function takes a TendermintTx, which can't be imported to tendermint create.
pub(crate) fn verify_tendermint_tx<N: Network>(
  tx: &TendermintTx,
  schema: &N::SignatureScheme,
  commit: impl Fn(u64) -> Option<Commit<N::SignatureScheme>>,
) -> Result<(), TransactionError> {
  tx.verify()?;

  match tx {
    TendermintTx::SlashEvidence(ev) => {
      match ev {
        Evidence::ConflictingMessages(first, second) => {
          let first = decode_and_verify_signed_message::<N>(first, schema)?.msg;
          let second = decode_and_verify_signed_message::<N>(second, schema)?.msg;

          // Make sure they're distinct messages, from the same sender, within the same block
          if (first == second) || (first.sender != second.sender) || (first.block != second.block) {
            Err(TransactionError::InvalidContent)?;
          }

          // Distinct messages within the same step
          if !((first.round == second.round) && (first.data.step() == second.data.step())) {
            Err(TransactionError::InvalidContent)?;
          }
        }
        Evidence::ConflictingPrecommit(first, second) => {
          let first = decode_and_verify_signed_message::<N>(first, schema)?.msg;
          let second = decode_and_verify_signed_message::<N>(second, schema)?.msg;

          if (first.sender != second.sender) || (first.block != second.block) {
            Err(TransactionError::InvalidContent)?;
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
        Evidence::InvalidPrecommit(msg) => {
          let msg = decode_and_verify_signed_message::<N>(msg, schema)?.msg;

          let Data::Precommit(Some((id, sig))) = &msg.data else {
            Err(TransactionError::InvalidContent)?
          };
          // TODO: We need to be passed in the genesis time to handle this edge case
          if msg.block.0 == 0 {
            todo!("invalid precommit signature on first block")
          }

          // get the last commit
          let prior_commit = match commit(msg.block.0 - 1) {
            Some(c) => c,
            // If we have yet to sync the block in question, we will return InvalidContent based
            // on our own temporal ambiguity
            // This will also cause an InvalidContent for anything using a non-existent block,
            // yet that's valid behavior
            // TODO: Double check the ramifications of this
            _ => Err(TransactionError::InvalidContent)?,
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
        }
        Evidence::InvalidValidRound(msg) => {
          let msg = decode_and_verify_signed_message::<N>(msg, schema)?.msg;

          let Data::Proposal(Some(vr), _) = &msg.data else {
            Err(TransactionError::InvalidContent)?
          };
          if vr.0 < msg.round.0 {
            Err(TransactionError::InvalidContent)?
          }
        }
      }
    }
  }

  Ok(())
}
