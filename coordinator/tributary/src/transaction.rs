use core::{ops::Deref as _, fmt::Debug};
use std::{collections::HashMap, io};

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use blake2::{digest::typenum::U32, Digest as _, Blake2b};
use ciphersuite::{
  group::{Group as _, GroupEncoding as _},
  *,
};
use dalek_ff_group::Ristretto;
use schnorr::SchnorrSignature;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, validator_sets::KeyShares};
use dkg::Participant;

use messages::{
  sign::VariantSignId, borsh_serialize_participant_map, borsh_deserialize_participant_map,
};

use tributary_sdk::{
  ReadWrite,
  transaction::{
    Signed as TributarySigned, TransactionError, TransactionKind, Transaction as TransactionTrait,
  },
};

use crate::db::Topic;

/// The round this data is for, within a signing protocol.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum SigningProtocolRound {
  /// A preprocess.
  Preprocess,
  /// A signature share.
  Share,
}

impl SigningProtocolRound {
  pub(crate) fn nonce(self) -> u32 {
    match self {
      SigningProtocolRound::Preprocess => 0,
      SigningProtocolRound::Share => 1,
    }
  }
}

/// `tributary::Signed` but without the nonce.
///
/// All of our nonces are deterministic to the type of transaction and fields within.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signed {
  /// The participant index for the tributary protocol.
  pub participant: Participant,
  /// The signer. The public key of a NetworkId::Serai auxiliary key.
  pub(crate) signer: <Ristretto as WrappedGroup>::G,
  /// The signature.
  pub(crate) signature: SchnorrSignature<Ristretto>,
}

impl BorshSerialize for Signed {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> Result<(), io::Error> {
    writer.write_all(self.participant.to_bytes().as_ref())?;
    writer.write_all(self.signer.to_bytes().as_ref())?;
    self.signature.write(writer)
  }
}
impl BorshDeserialize for Signed {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> Result<Self, io::Error> {
    let participant = Participant::deserialize_reader(&mut *reader)?;
    let signer = Ristretto::read_G(&mut *reader)?;
    let signature = SchnorrSignature::read(&mut *reader)?;
    Ok(Self { participant, signer, signature })
  }
}

impl Signed {
  /// Provide a nonce to convert a `Signed` into a `tributary::Signed`.
  pub(crate) fn to_tributary_signed(self, round: SigningProtocolRound) -> TributarySigned {
    TributarySigned { signer: self.signer, nonce: round.nonce(), signature: self.signature }
  }
}

impl Default for Signed {
  fn default() -> Self {
    Self {
      participant: Participant::new(1).unwrap(),
      signer: <Ristretto as WrappedGroup>::G::identity(),
      signature: SchnorrSignature {
        R: <Ristretto as WrappedGroup>::G::identity(),
        s: <Ristretto as WrappedGroup>::F::ZERO,
      },
    }
  }
}

/// The Tributary transaction definition used by Serai.
///
/// Two transactions will be considered equal if equal on every level. This means transactions
/// which aren't equal may share a hash, due to the hash not binding to the signature, yet the
/// equality binding to the signature.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Transaction {
  /// A vote to remove a participant for invalid behavior
  RemoveParticipant {
    /// The participant to remove. Stored as the tributary index of participation.
    participant: Participant,
    /// The transaction's signer and signature
    signed: Signed,
  },

  /// A participation in the DKG
  DkgParticipation {
    /// The serialized participation
    participation: Vec<u8>,
    /// The transaction's signer and signature
    signed: Signed,
  },
  /// The preprocess to confirm the DKG results on-chain
  DkgConfirmationPreprocess {
    /// The attempt number of this signing protocol
    attempt: u64,
    /// The preprocess
    preprocess: [u8; 64],
    /// The transaction's signer and signature
    signed: Signed,
  },
  /// The signature share to confirm the DKG results on-chain
  DkgConfirmationShare {
    /// The attempt number of this signing protocol
    attempt: u64,
    /// The signature share
    share: [u8; 32],
    /// The transaction's signer and signature
    signed: Signed,
  },

  /// Intend to cosign a finalized Substrate block
  ///
  /// When the time comes to start a new cosigning protocol, the most recent Substrate block will
  /// be the one selected to be cosigned.
  Cosign {
    /// The hash of the Substrate block to cosign
    substrate_block_hash: BlockHash,
  },

  /// Note an intended-to-be-cosigned Substrate block as cosigned
  ///
  /// After producing this cosign, we need to start work on the latest intended-to-be cosigned
  /// block. That requires agreement on when this cosign was produced, which we solve by noting
  /// this cosign on-chain.
  ///
  /// We ideally don't have this transaction at all. The coordinator, without access to any of the
  /// key shares, could observe the FROST signing session and determine a successful completion.
  /// Unfortunately, that functionality is not present in modular-frost, so we do need to support
  /// *some* asynchronous flow (where the processor or P2P network informs us of the successful
  /// completion).
  ///
  /// If we use a `Provided` transaction, that requires everyone observe this cosign.
  ///
  /// If we use an `Unsigned` transaction, we can't verify the cosign signature inside
  /// `Transaction::verify` unless we embedded the full `SignedCosign` on-chain. The issue is since
  /// a Tributary is stateless with regards to the on-chain logic, including `Transaction::verify`,
  /// we can't verify the signature against the group's public key unless we also include that (but
  /// then we open a DoS where arbitrary group keys are specified to cause inclusion of arbitrary
  /// blobs on chain).
  ///
  /// If we use a `Signed` transaction, we mitigate the DoS risk by having someone to fatally
  /// slash. We have horrible performance though as for 100 validators, all 100 will publish this
  /// transaction.
  ///
  /// We could use a signed `Unsigned` transaction, where it includes a signer and signature but
  /// isn't technically a Signed transaction. This lets us de-duplicate the transaction premised on
  /// its contents.
  ///
  /// The optimal choice is likely to use a `Provided` transaction. We don't actually need to
  /// observe the produced cosign (which is ephemeral). As long as it's agreed the cosign in
  /// question no longer needs to produced, which would mean the cosigning protocol at-large
  /// cosigning the block in question, it'd be safe to provide this and move on to the next cosign.
  Cosigned {
    /// The hash of the Substrate block which was cosigned
    substrate_block_hash: BlockHash,
  },

  /// Acknowledge a Substrate block
  ///
  /// This is provided after the block has been cosigned.
  ///
  /// With the acknowledgement of a Substrate block, we can recognize all the `VariantSignId`s
  /// resulting from its handling.
  SubstrateBlock {
    /// The hash of the Substrate block
    hash: BlockHash,
  },

  /// Acknowledge a Batch
  ///
  /// Once everyone has acknowledged the Batch, we can begin signing it.
  Batch {
    /// The hash of the Batch's serialization.
    ///
    /// Generally, we refer to a Batch by its ID/the hash of its instructions. Here, we want to
    /// ensure consensus on the Batch, and achieving consensus on its hash is the most effective
    /// way to do that.
    hash: [u8; 32],
  },

  /// Data from a signing protocol.
  Sign {
    /// The ID of the object being signed
    id: VariantSignId,
    /// The attempt number of this signing protocol
    attempt: u64,
    /// The round this data is for, within the signing protocol
    round: SigningProtocolRound,
    /// The data itself
    ///
    /// There will be `n` blobs of data where `n` is the amount of key shares the validator sending
    /// this transaction has.
    #[borsh(
      serialize_with = "borsh_serialize_participant_map",
      deserialize_with = "borsh_deserialize_participant_map"
    )]
    data: HashMap<Participant, Vec<u8>>,
    /// The transaction's signer and signature
    signed: Signed,
  },

  /// The local view of slashes observed by the transaction's sender
  SlashReport {
    /// The slash points accrued by each validator
    slash_points: Vec<u32>,
    /// The transaction's signer and signature
    signed: Signed,
  },
}

impl ReadWrite for Transaction {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    borsh::BorshDeserialize::deserialize_reader(&mut reader)
  }

  fn write(&self, writer: impl io::Write) -> io::Result<()> {
    borsh::to_writer(writer, self)
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind {
    match self {
      Transaction::RemoveParticipant { participant, signed } => TransactionKind::Signed(
        borsh::to_vec(&(b"RemoveParticipant".as_slice(), participant)).unwrap(),
        signed.to_tributary_signed(SigningProtocolRound::Preprocess),
      ),

      Transaction::DkgParticipation { signed, .. } => TransactionKind::Signed(
        borsh::to_vec(b"DkgParticipation".as_slice()).unwrap(),
        signed.to_tributary_signed(SigningProtocolRound::Preprocess),
      ),
      Transaction::DkgConfirmationPreprocess { attempt, signed, .. } => TransactionKind::Signed(
        borsh::to_vec(&(b"DkgConfirmation".as_slice(), attempt)).unwrap(),
        signed.to_tributary_signed(SigningProtocolRound::Preprocess),
      ),
      Transaction::DkgConfirmationShare { attempt, signed, .. } => TransactionKind::Signed(
        borsh::to_vec(&(b"DkgConfirmation".as_slice(), attempt)).unwrap(),
        signed.to_tributary_signed(SigningProtocolRound::Share),
      ),

      Transaction::Cosign { .. } => TransactionKind::Provided("Cosign"),
      Transaction::Cosigned { .. } => TransactionKind::Provided("Cosigned"),
      Transaction::SubstrateBlock { .. } => TransactionKind::Provided("SubstrateBlock"),
      Transaction::Batch { .. } => TransactionKind::Provided("Batch"),

      Transaction::Sign { id, attempt, round, signed, .. } => TransactionKind::Signed(
        borsh::to_vec(&(b"Sign".as_slice(), id, attempt, signed.participant)).unwrap(),
        signed.to_tributary_signed(*round),
      ),

      Transaction::SlashReport { signed, .. } => TransactionKind::Signed(
        borsh::to_vec(b"SlashReport".as_slice()).unwrap(),
        signed.to_tributary_signed(SigningProtocolRound::Preprocess),
      ),
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = ReadWrite::serialize(self);
    if let TransactionKind::Signed(_, signed) = self.kind() {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), signed.signature.serialize());
    }
    Blake2b::<U32>::digest(&tx).into()
  }

  // This is a stateless verification which we use to enforce some size limits.
  fn verify(&self) -> Result<(), TransactionError> {
    #[expect(clippy::match_same_arms)]
    match self {
      // Fixed-length TX
      Transaction::RemoveParticipant { .. } => {}

      // TODO: MAX_DKG_PARTICIPATION_LEN
      Transaction::DkgParticipation { .. } => {}
      // These are fixed-length TXs
      Transaction::DkgConfirmationPreprocess { .. } | Transaction::DkgConfirmationShare { .. } => {}

      // Provided TXs
      Transaction::Cosign { .. } |
      Transaction::Cosigned { .. } |
      Transaction::SubstrateBlock { .. } |
      Transaction::Batch { .. } => {}

      Transaction::Sign { data, .. } => {
        if data.len() > usize::from(KeyShares::MAX_PER_SET) {
          Err(TransactionError::InvalidContent)?;
        }
        // TODO: MAX_SIGN_LEN
      }

      Transaction::SlashReport { slash_points, .. } => {
        if slash_points.len() > usize::from(KeyShares::MAX_PER_SET) {
          Err(TransactionError::InvalidContent)?;
        }
      }
    };
    Ok(())
  }
}

impl Transaction {
  /// Fetch a reference to the signer data if this is a signed transaction.
  pub(crate) fn signed(&self) -> Option<&Signed> {
    match self {
      Transaction::RemoveParticipant { signed, .. } |
      Transaction::DkgParticipation { signed, .. } |
      Transaction::DkgConfirmationPreprocess { signed, .. } |
      Transaction::DkgConfirmationShare { signed, .. } |
      Transaction::Sign { signed, .. } |
      Transaction::SlashReport { signed, .. } => Some(signed),
      Transaction::Cosign { .. } |
      Transaction::Cosigned { .. } |
      Transaction::SubstrateBlock { .. } |
      Transaction::Batch { .. } => None,
    }
  }

  /// The topic in the database for this transaction.
  pub fn topic(&self) -> Option<Topic> {
    #[expect(clippy::match_same_arms)] // This doesn't make semantic sense here
    match self {
      Transaction::RemoveParticipant { participant, .. } => {
        Some(Topic::RemoveParticipant { participant: *participant })
      }

      Transaction::DkgParticipation { .. } => None,
      Transaction::DkgConfirmationPreprocess { attempt, .. } => {
        Some(Topic::DkgConfirmation { attempt: *attempt, round: SigningProtocolRound::Preprocess })
      }
      Transaction::DkgConfirmationShare { attempt, .. } => {
        Some(Topic::DkgConfirmation { attempt: *attempt, round: SigningProtocolRound::Share })
      }

      // Provided TXs
      Transaction::Cosign { .. } |
      Transaction::Cosigned { .. } |
      Transaction::SubstrateBlock { .. } |
      Transaction::Batch { .. } => None,

      Transaction::Sign { id, attempt, round, .. } => {
        Some(Topic::Sign { id: *id, attempt: *attempt, round: *round })
      }

      Transaction::SlashReport { .. } => Some(Topic::SlashReport),
    }
  }

  /// Sign a transaction.
  ///
  /// Panics if signing a transaction whose type isn't `TransactionKind::Signed`.
  pub fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    genesis: [u8; 32],
    key: &Zeroizing<<Ristretto as WrappedGroup>::F>,
  ) {
    fn signed_strict(tx: &mut Transaction) -> &mut Signed {
      #[expect(clippy::match_same_arms)] // This doesn't make semantic sense here
      match tx {
        Transaction::RemoveParticipant { ref mut signed, .. } |
        Transaction::DkgParticipation { ref mut signed, .. } |
        Transaction::DkgConfirmationPreprocess { ref mut signed, .. } => signed,
        Transaction::DkgConfirmationShare { ref mut signed, .. } => signed,

        Transaction::Cosign { .. } => panic!("signing Cosign transaction (provided)"),
        Transaction::Cosigned { .. } => panic!("signing Cosigned transaction (provided)"),
        Transaction::SubstrateBlock { .. } => {
          panic!("signing SubstrateBlock transaction (provided)")
        }
        Transaction::Batch { .. } => panic!("signing Batch transaction (provided)"),

        Transaction::Sign { ref mut signed, .. } => signed,

        Transaction::SlashReport { ref mut signed, .. } => signed,
      }
    }

    // Decide the nonce to sign with
    let sig_nonce = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(rng));

    {
      // Set the signer and the nonce
      let signed = signed_strict(self);
      signed.signer = Ristretto::generator() * key.deref();
      signed.signature.R = <Ristretto as WrappedGroup>::generator() * sig_nonce.deref();
    }

    // Get the signature hash (which now includes `R || A` making it valid as the challenge)
    let sig_hash = self.sig_hash(genesis);

    // Sign the signature
    signed_strict(self).signature = SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
  }
}
