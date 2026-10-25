use core::{ops::Deref as _, fmt::Debug};
use std::io;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use ciphersuite::{group::GroupEncoding as _, WrappedGroup};
use dalek_ff_group::Ristretto;
use schnorr::SchnorrSignature;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, validator_sets::KeyShares, address::SeraiAddress};

use messages::sign::VariantSignId;

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
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Signed {
  /// The signer.
  pub(crate) signer: [u8; 32],
  /// The signature.
  pub(crate) signature: [u8; 64],
}

impl Signed {
  /// Provide a nonce to convert a `Signed` into a `tributary::Signed`.
  pub(crate) fn to_tributary_signed(self, nonce: u32) -> TributarySigned {
    TributarySigned { signer: self.signer, nonce: u64::from(nonce), signature: self.signature }
  }
}

impl Default for Signed {
  fn default() -> Self {
    Self { signer: [0; 32], signature: [0; 64] }
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
    /// The participant to remove
    participant: SeraiAddress,
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
    data: Vec<Vec<u8>>,
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
    Self::deserialize_reader(&mut reader)
  }

  fn write(&self, writer: impl io::Write) -> io::Result<()> {
    borsh::to_writer(writer, self)
  }
}

impl tributary_sdk::merkle::Digestible for Transaction {
  fn update(&self, digest: &mut (impl ?Sized + blake2::digest::Update)) {
    if let TransactionKind::Signed { scope: _, signed: TributarySigned { signature, .. } } =
      self.kind()
    {
      let serialization = ReadWrite::serialize(self);

      // The signature is 64-bytes and always at the end
      /*
        TODO: Move `signed` out of the transaction type. Have the current type be `TransactionCore`
        with `struct Transaction(TransactionCore, Option<Signed>)` replacing it.
      */
      assert_eq!(&serialization[(serialization.len() - 64) ..], &signature);
      let serialization = &serialization[.. (serialization.len() - 64)];

      digest.update(serialization);
    } else {
      // TODO: Remove this intermediary allocation
      digest.update(&ReadWrite::serialize(self));
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind {
    match self {
      Transaction::RemoveParticipant { participant, signed } => TransactionKind::Signed {
        scope: borsh::to_vec(&(b"RemoveParticipant".as_slice(), participant)).unwrap(),
        signed: signed.to_tributary_signed(0),
      },

      Transaction::DkgParticipation { signed, .. } => TransactionKind::Signed {
        scope: borsh::to_vec(b"DkgParticipation".as_slice()).unwrap(),
        signed: signed.to_tributary_signed(0),
      },
      Transaction::DkgConfirmationPreprocess { attempt, signed, .. } => TransactionKind::Signed {
        scope: borsh::to_vec(&(b"DkgConfirmation".as_slice(), attempt)).unwrap(),
        signed: signed.to_tributary_signed(SigningProtocolRound::Preprocess.nonce()),
      },
      Transaction::DkgConfirmationShare { attempt, signed, .. } => TransactionKind::Signed {
        scope: borsh::to_vec(&(b"DkgConfirmation".as_slice(), attempt)).unwrap(),
        signed: signed.to_tributary_signed(SigningProtocolRound::Share.nonce()),
      },

      Transaction::Cosign { .. } => TransactionKind::Provided { scope: "Cosign" },
      Transaction::Cosigned { .. } => TransactionKind::Provided { scope: "Cosigned" },
      Transaction::SubstrateBlock { .. } => TransactionKind::Provided { scope: "SubstrateBlock" },
      Transaction::Batch { .. } => TransactionKind::Provided { scope: "Batch" },

      Transaction::Sign { id, attempt, round, signed, .. } => TransactionKind::Signed {
        scope: borsh::to_vec(&(b"Sign".as_slice(), id, attempt)).unwrap(),
        signed: signed.to_tributary_signed(round.nonce()),
      },

      Transaction::SlashReport { signed, .. } => TransactionKind::Signed {
        scope: borsh::to_vec(b"SlashReport".as_slice()).unwrap(),
        signed: signed.to_tributary_signed(0),
      },
    }
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
          Err(TransactionError::InvalidTransaction)?;
        }
        // TODO: MAX_SIGN_LEN
      }

      Transaction::SlashReport { slash_points, .. } => {
        if slash_points.len() > usize::from(KeyShares::MAX_PER_SET) {
          Err(TransactionError::InvalidTransaction)?;
        }
      }
    };
    Ok(())
  }
}

impl Transaction {
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
    fn signed(tx: &mut Transaction) -> &mut Signed {
      #[expect(clippy::match_same_arms)] // This doesn't make semantic sense here
      match tx {
        Transaction::RemoveParticipant { signed, .. } |
        Transaction::DkgParticipation { signed, .. } |
        Transaction::DkgConfirmationPreprocess { signed, .. } => signed,
        Transaction::DkgConfirmationShare { signed, .. } => signed,

        Transaction::Cosign { .. } => panic!("signing Cosign transaction (provided)"),
        Transaction::Cosigned { .. } => panic!("signing Cosigned transaction (provided)"),
        Transaction::SubstrateBlock { .. } => {
          panic!("signing SubstrateBlock transaction (provided)")
        }
        Transaction::Batch { .. } => panic!("signing Batch transaction (provided)"),

        Transaction::Sign { signed, .. } => signed,

        Transaction::SlashReport { signed, .. } => signed,
      }
    }

    // Decide the nonce to sign with
    let sig_nonce = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(rng));

    {
      // Set the signer and the nonce
      let signed = signed(self);
      signed.signer = (Ristretto::generator() * key.deref()).to_bytes();
      signed.signature[.. 32].copy_from_slice(
        (<Ristretto as WrappedGroup>::generator() * sig_nonce.deref()).to_bytes().as_ref(),
      );
    }

    // Get the signature hash (which now includes `R || A` making it valid as the challenge)
    let signature_challenge = self
      .signature_challenge(genesis)
      .expect("signing a transaction without a signature challenge");

    // Sign the signature
    // TODO: Remove this intermediary allocation
    signed(self).signature =
      SchnorrSignature::<Ristretto>::sign(key, sig_nonce, signature_challenge)
        .serialize()
        .try_into()
        .unwrap();
  }
}
