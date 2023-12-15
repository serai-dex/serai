use core::{ops::Deref, fmt::Debug};
use std::io;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use blake2::{Digest, Blake2s256};
use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;
use frost::Participant;

use scale::{Encode, Decode};
use processor_messages::coordinator::SubstrateSignableId;

use tributary::{
  TRANSACTION_SIZE_LIMIT, ReadWrite,
  transaction::{Signed, TransactionError, TransactionKind, Transaction as TransactionTrait},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode)]
pub enum Label {
  Preprocess,
  Share,
}

impl Label {
  // TODO: Should nonces be u8 thanks to our use of topics?
  pub fn nonce(&self) -> u32 {
    match self {
      Label::Preprocess => 0,
      Label::Share => 1,
    }
  }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignData<Id: Clone + PartialEq + Eq + Debug + Encode + Decode> {
  pub plan: Id,
  pub attempt: u32,
  pub label: Label,

  pub data: Vec<Vec<u8>>,

  pub signed: Signed,
}

impl<Id: Clone + PartialEq + Eq + Debug + Encode + Decode> Debug for SignData<Id> {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("SignData")
      .field("id", &hex::encode(self.plan.encode()))
      .field("attempt", &self.attempt)
      .field("label", &self.label)
      .field("signer", &hex::encode(self.signed.signer.to_bytes()))
      .finish_non_exhaustive()
  }
}

impl<Id: Clone + PartialEq + Eq + Debug + Encode + Decode> SignData<Id> {
  pub(crate) fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let plan = Id::decode(&mut scale::IoReader(&mut *reader))
      .map_err(|_| io::Error::other("invalid plan in SignData"))?;

    let mut attempt = [0; 4];
    reader.read_exact(&mut attempt)?;
    let attempt = u32::from_le_bytes(attempt);

    let mut label = [0; 1];
    reader.read_exact(&mut label)?;
    let label = match label[0] {
      0 => Label::Preprocess,
      1 => Label::Share,
      _ => Err(io::Error::other("invalid label in SignData"))?,
    };

    let data = {
      let mut data_pieces = [0];
      reader.read_exact(&mut data_pieces)?;
      if data_pieces[0] == 0 {
        Err(io::Error::other("zero pieces of data in SignData"))?;
      }
      let mut all_data = vec![];
      for _ in 0 .. data_pieces[0] {
        let mut data_len = [0; 2];
        reader.read_exact(&mut data_len)?;
        let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
        reader.read_exact(&mut data)?;
        all_data.push(data);
      }
      all_data
    };

    let signed = Signed::read_without_nonce(reader, label.nonce())?;

    Ok(SignData { plan, attempt, label, data, signed })
  }

  pub(crate) fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.plan.encode())?;
    writer.write_all(&self.attempt.to_le_bytes())?;
    writer.write_all(&[match self.label {
      Label::Preprocess => 0,
      Label::Share => 1,
    }])?;

    writer.write_all(&[u8::try_from(self.data.len()).unwrap()])?;
    for data in &self.data {
      if data.len() > u16::MAX.into() {
        // Currently, the largest individual preprocess is a Monero transaction
        // It provides 4 commitments per input (128 bytes), a 64-byte proof for them, along with a
        // key image and proof (96 bytes)
        // Even with all of that, we could support 227 inputs in a single TX
        // Monero is limited to ~120 inputs per TX
        //
        // Bitcoin has a much higher input count of 520, yet it only uses 64 bytes per preprocess
        Err(io::Error::other("signing data exceeded 65535 bytes"))?;
      }
      writer.write_all(&u16::try_from(data.len()).unwrap().to_le_bytes())?;
      writer.write_all(data)?;
    }

    self.signed.write_without_nonce(writer)
  }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Transaction {
  RemoveParticipantDueToDkg {
    attempt: u32,
    participant: Participant,
  },

  DkgCommitments {
    attempt: u32,
    commitments: Vec<Vec<u8>>,
    signed: Signed,
  },
  DkgShares {
    attempt: u32,
    // Sending Participant, Receiving Participant, Share
    shares: Vec<Vec<Vec<u8>>>,
    confirmation_nonces: [u8; 64],
    signed: Signed,
  },
  InvalidDkgShare {
    attempt: u32,
    accuser: Participant,
    faulty: Participant,
    blame: Option<Vec<u8>>,
    signed: Signed,
  },
  DkgConfirmed {
    attempt: u32,
    confirmation_share: [u8; 32],
    signed: Signed,
  },

  // Co-sign a Substrate block.
  CosignSubstrateBlock([u8; 32]),

  // When we have synchrony on a batch, we can allow signing it
  // TODO (never?): This is less efficient compared to an ExternalBlock provided transaction,
  // which would be binding over the block hash and automatically achieve synchrony on all
  // relevant batches. ExternalBlock was removed for this due to complexity around the pipeline
  // with the current processor, yet it would still be an improvement.
  Batch {
    block: [u8; 32],
    batch: u32,
  },
  // When a Serai block is finalized, with the contained batches, we can allow the associated plan
  // IDs
  SubstrateBlock(u64),

  SubstrateSign(SignData<SubstrateSignableId>),
  Sign(SignData<[u8; 32]>),
  // This is defined as an Unsigned transaction in order to de-duplicate SignCompleted amongst
  // reporters (who should all report the same thing)
  // We do still track the signer in order to prevent a single signer from publishing arbitrarily
  // many TXs without penalty
  // Here, they're denoted as the first_signer, as only the signer of the first TX to be included
  // with this pairing will be remembered on-chain
  SignCompleted {
    plan: [u8; 32],
    tx_hash: Vec<u8>,
    first_signer: <Ristretto as Ciphersuite>::G,
    signature: SchnorrSignature<Ristretto>,
  },
}

impl Debug for Transaction {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    match self {
      Transaction::RemoveParticipantDueToDkg { attempt, participant } => fmt
        .debug_struct("Transaction::RemoveParticipantDueToDkg")
        .field("participant", participant)
        .field("attempt", attempt)
        .finish(),
      Transaction::DkgCommitments { attempt, commitments: _, signed } => fmt
        .debug_struct("Transaction::DkgCommitments")
        .field("attempt", attempt)
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::DkgShares { attempt, signed, .. } => fmt
        .debug_struct("Transaction::DkgShares")
        .field("attempt", attempt)
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::InvalidDkgShare { attempt, accuser, faulty, .. } => fmt
        .debug_struct("Transaction::InvalidDkgShare")
        .field("attempt", attempt)
        .field("accuser", accuser)
        .field("faulty", faulty)
        .finish_non_exhaustive(),
      Transaction::DkgConfirmed { attempt, confirmation_share: _, signed } => fmt
        .debug_struct("Transaction::DkgConfirmed")
        .field("attempt", attempt)
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::CosignSubstrateBlock(block) => fmt
        .debug_struct("Transaction::CosignSubstrateBlock")
        .field("block", &hex::encode(block))
        .finish(),
      Transaction::Batch { block, batch } => fmt
        .debug_struct("Transaction::Batch")
        .field("block", &hex::encode(block))
        .field("batch", &batch)
        .finish(),
      Transaction::SubstrateBlock(block) => {
        fmt.debug_struct("Transaction::SubstrateBlock").field("block", block).finish()
      }
      Transaction::SubstrateSign(sign_data) => {
        fmt.debug_struct("Transaction::SubstrateSign").field("sign_data", sign_data).finish()
      }
      Transaction::Sign(sign_data) => {
        fmt.debug_struct("Transaction::Sign").field("sign_data", sign_data).finish()
      }
      Transaction::SignCompleted { plan, tx_hash, .. } => fmt
        .debug_struct("Transaction::SignCompleted")
        .field("plan", &hex::encode(plan))
        .field("tx_hash", &hex::encode(tx_hash))
        .finish_non_exhaustive(),
    }
  }
}

impl ReadWrite for Transaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => Ok(Transaction::RemoveParticipantDueToDkg {
        attempt: {
          let mut attempt = [0; 4];
          reader.read_exact(&mut attempt)?;
          u32::from_le_bytes(attempt)
        },
        participant: {
          let mut participant = [0; 2];
          reader.read_exact(&mut participant)?;
          Participant::new(u16::from_le_bytes(participant))
            .ok_or_else(|| io::Error::other("invalid participant in RemoveParticipantDueToDkg"))?
        },
      }),

      1 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let commitments = {
          let mut commitments_len = [0; 1];
          reader.read_exact(&mut commitments_len)?;
          let commitments_len = usize::from(commitments_len[0]);
          if commitments_len == 0 {
            Err(io::Error::other("zero commitments in DkgCommitments"))?;
          }

          let mut each_commitments_len = [0; 2];
          reader.read_exact(&mut each_commitments_len)?;
          let each_commitments_len = usize::from(u16::from_le_bytes(each_commitments_len));
          if (commitments_len * each_commitments_len) > TRANSACTION_SIZE_LIMIT {
            Err(io::Error::other(
              "commitments present in transaction exceeded transaction size limit",
            ))?;
          }
          let mut commitments = vec![vec![]; commitments_len];
          for commitments in &mut commitments {
            *commitments = vec![0; each_commitments_len];
            reader.read_exact(commitments)?;
          }
          commitments
        };

        let signed = Signed::read_without_nonce(reader, 0)?;

        Ok(Transaction::DkgCommitments { attempt, commitments, signed })
      }

      2 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let shares = {
          let mut share_quantity = [0; 1];
          reader.read_exact(&mut share_quantity)?;

          let mut key_share_quantity = [0; 1];
          reader.read_exact(&mut key_share_quantity)?;

          let mut share_len = [0; 2];
          reader.read_exact(&mut share_len)?;
          let share_len = usize::from(u16::from_le_bytes(share_len));

          let mut all_shares = vec![];
          for _ in 0 .. share_quantity[0] {
            let mut shares = vec![];
            for _ in 0 .. key_share_quantity[0] {
              let mut share = vec![0; share_len];
              reader.read_exact(&mut share)?;
              shares.push(share);
            }
            all_shares.push(shares);
          }
          all_shares
        };

        let mut confirmation_nonces = [0; 64];
        reader.read_exact(&mut confirmation_nonces)?;

        let signed = Signed::read_without_nonce(reader, 1)?;

        Ok(Transaction::DkgShares { attempt, shares, confirmation_nonces, signed })
      }

      3 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut accuser = [0; 2];
        reader.read_exact(&mut accuser)?;
        let accuser = Participant::new(u16::from_le_bytes(accuser))
          .ok_or_else(|| io::Error::other("invalid participant in InvalidDkgShare"))?;

        let mut faulty = [0; 2];
        reader.read_exact(&mut faulty)?;
        let faulty = Participant::new(u16::from_le_bytes(faulty))
          .ok_or_else(|| io::Error::other("invalid participant in InvalidDkgShare"))?;

        let mut blame_len = [0; 2];
        reader.read_exact(&mut blame_len)?;
        let mut blame = vec![0; u16::from_le_bytes(blame_len).into()];
        reader.read_exact(&mut blame)?;

        // This shares a nonce with DkgConfirmed as only one is expected
        let signed = Signed::read_without_nonce(reader, 2)?;

        Ok(Transaction::InvalidDkgShare {
          attempt,
          accuser,
          faulty,
          blame: Some(blame).filter(|blame| !blame.is_empty()),
          signed,
        })
      }

      4 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut confirmation_share = [0; 32];
        reader.read_exact(&mut confirmation_share)?;

        let signed = Signed::read_without_nonce(reader, 2)?;

        Ok(Transaction::DkgConfirmed { attempt, confirmation_share, signed })
      }

      5 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        Ok(Transaction::CosignSubstrateBlock(block))
      }

      6 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        let mut batch = [0; 4];
        reader.read_exact(&mut batch)?;
        Ok(Transaction::Batch { block, batch: u32::from_le_bytes(batch) })
      }

      7 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::SubstrateBlock(u64::from_le_bytes(block)))
      }

      8 => SignData::read(reader).map(Transaction::SubstrateSign),
      9 => SignData::read(reader).map(Transaction::Sign),

      10 => {
        let mut plan = [0; 32];
        reader.read_exact(&mut plan)?;

        let mut tx_hash_len = [0];
        reader.read_exact(&mut tx_hash_len)?;
        let mut tx_hash = vec![0; usize::from(tx_hash_len[0])];
        reader.read_exact(&mut tx_hash)?;

        let first_signer = Ristretto::read_G(reader)?;
        let signature = SchnorrSignature::<Ristretto>::read(reader)?;

        Ok(Transaction::SignCompleted { plan, tx_hash, first_signer, signature })
      }

      _ => Err(io::Error::other("invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::RemoveParticipantDueToDkg { attempt, participant } => {
        writer.write_all(&[0])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(&u16::from(*participant).to_le_bytes())
      }

      Transaction::DkgCommitments { attempt, commitments, signed } => {
        writer.write_all(&[1])?;
        writer.write_all(&attempt.to_le_bytes())?;
        if commitments.is_empty() {
          Err(io::Error::other("zero commitments in DkgCommitments"))?
        }
        writer.write_all(&[u8::try_from(commitments.len()).unwrap()])?;
        for commitments_i in commitments {
          if commitments_i.len() != commitments[0].len() {
            Err(io::Error::other("commitments of differing sizes in DkgCommitments"))?
          }
        }
        writer.write_all(&u16::try_from(commitments[0].len()).unwrap().to_le_bytes())?;
        for commitments in commitments {
          writer.write_all(commitments)?;
        }
        signed.write_without_nonce(writer)
      }

      Transaction::DkgShares { attempt, shares, confirmation_nonces, signed } => {
        writer.write_all(&[2])?;
        writer.write_all(&attempt.to_le_bytes())?;

        // `shares` is a Vec which is supposed to map to a HashMap<Pariticpant, Vec<u8>>. Since we
        // bound participants to 150, this conversion is safe if a valid in-memory transaction.
        writer.write_all(&[u8::try_from(shares.len()).unwrap()])?;
        // This assumes at least one share is being sent to another party
        writer.write_all(&[u8::try_from(shares[0].len()).unwrap()])?;
        let share_len = shares[0][0].len();
        // For BLS12-381 G2, this would be:
        // - A 32-byte share
        // - A 96-byte ephemeral key
        // - A 128-byte signature
        // Hence why this has to be u16
        writer.write_all(&u16::try_from(share_len).unwrap().to_le_bytes())?;

        for these_shares in shares {
          assert_eq!(these_shares.len(), shares[0].len(), "amount of sent shares was variable");
          for share in these_shares {
            assert_eq!(share.len(), share_len, "sent shares were of variable length");
            writer.write_all(share)?;
          }
        }

        writer.write_all(confirmation_nonces)?;
        signed.write_without_nonce(writer)
      }

      Transaction::InvalidDkgShare { attempt, accuser, faulty, blame, signed } => {
        writer.write_all(&[3])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(&u16::from(*accuser).to_le_bytes())?;
        writer.write_all(&u16::from(*faulty).to_le_bytes())?;

        // Flattens Some(vec![]) to None on the expectation no actual blame will be 0-length
        assert!(blame.as_ref().map(|blame| blame.len()).unwrap_or(1) != 0);
        let blame_len =
          u16::try_from(blame.as_ref().unwrap_or(&vec![]).len()).expect("blame exceeded 64 KB");
        writer.write_all(&blame_len.to_le_bytes())?;
        writer.write_all(blame.as_ref().unwrap_or(&vec![]))?;

        signed.write_without_nonce(writer)
      }

      Transaction::DkgConfirmed { attempt, confirmation_share, signed } => {
        writer.write_all(&[4])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(confirmation_share)?;
        signed.write_without_nonce(writer)
      }

      Transaction::CosignSubstrateBlock(block) => {
        writer.write_all(&[5])?;
        writer.write_all(block)
      }

      Transaction::Batch { block, batch } => {
        writer.write_all(&[6])?;
        writer.write_all(block)?;
        writer.write_all(&batch.to_le_bytes())
      }

      Transaction::SubstrateBlock(block) => {
        writer.write_all(&[7])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::SubstrateSign(data) => {
        writer.write_all(&[8])?;
        data.write(writer)
      }
      Transaction::Sign(data) => {
        writer.write_all(&[9])?;
        data.write(writer)
      }
      Transaction::SignCompleted { plan, tx_hash, first_signer, signature } => {
        writer.write_all(&[10])?;
        writer.write_all(plan)?;
        writer
          .write_all(&[u8::try_from(tx_hash.len()).expect("tx hash length exceed 255 bytes")])?;
        writer.write_all(tx_hash)?;
        writer.write_all(&first_signer.to_bytes())?;
        signature.write(writer)
      }
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind<'_> {
    match self {
      Transaction::RemoveParticipantDueToDkg { .. } => TransactionKind::Provided("remove"),

      Transaction::DkgCommitments { attempt, commitments: _, signed } => {
        TransactionKind::Signed((b"dkg", attempt).encode(), signed)
      }
      Transaction::DkgShares { attempt, signed, .. } => {
        TransactionKind::Signed((b"dkg", attempt).encode(), signed)
      }
      Transaction::InvalidDkgShare { attempt, signed, .. } => {
        TransactionKind::Signed((b"dkg", attempt).encode(), signed)
      }
      Transaction::DkgConfirmed { attempt, signed, .. } => {
        TransactionKind::Signed((b"dkg", attempt).encode(), signed)
      }

      Transaction::CosignSubstrateBlock(_) => TransactionKind::Provided("cosign"),

      Transaction::Batch { .. } => TransactionKind::Provided("batch"),
      Transaction::SubstrateBlock(_) => TransactionKind::Provided("serai"),

      Transaction::SubstrateSign(data) => {
        TransactionKind::Signed((b"substrate", data.plan, data.attempt).encode(), &data.signed)
      }
      Transaction::Sign(data) => {
        TransactionKind::Signed((b"sign", data.plan, data.attempt).encode(), &data.signed)
      }
      Transaction::SignCompleted { .. } => TransactionKind::Unsigned,
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = self.serialize();
    if let TransactionKind::Signed(_, signed) = self.kind() {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), signed.signature.serialize());
    }
    Blake2s256::digest([b"Coordinator Tributary Transaction".as_slice(), &tx].concat()).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    // TODO: Check SubstrateSign's lengths here

    if let Transaction::SignCompleted { first_signer, signature, .. } = self {
      if !signature.verify(*first_signer, self.sign_completed_challenge()) {
        Err(TransactionError::InvalidContent)?;
      }
    }

    Ok(())
  }
}

impl Transaction {
  // Used to initially construct transactions so we can then get sig hashes and perform signing
  pub fn empty_signed() -> Signed {
    Signed {
      signer: Ristretto::generator(),
      nonce: 0,
      signature: SchnorrSignature::<Ristretto> {
        R: Ristretto::generator(),
        s: <Ristretto as Ciphersuite>::F::ZERO,
      },
    }
  }

  // Sign a transaction
  pub fn sign<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    genesis: [u8; 32],
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) {
    fn signed(tx: &mut Transaction) -> (u32, &mut Signed) {
      let nonce = match tx {
        Transaction::RemoveParticipantDueToDkg { .. } => {
          panic!("signing RemoveParticipantDueToDkg")
        }

        Transaction::DkgCommitments { .. } => 0,
        Transaction::DkgShares { .. } => 1,
        Transaction::InvalidDkgShare { .. } => 2,
        Transaction::DkgConfirmed { .. } => 2,

        Transaction::CosignSubstrateBlock(_) => panic!("signing CosignSubstrateBlock"),

        Transaction::Batch { .. } => panic!("signing Batch"),
        Transaction::SubstrateBlock(_) => panic!("signing SubstrateBlock"),

        Transaction::SubstrateSign(data) => data.label.nonce(),
        Transaction::Sign(data) => data.label.nonce(),
        Transaction::SignCompleted { .. } => panic!("signing SignCompleted"),
      };

      (
        nonce,
        match tx {
          Transaction::RemoveParticipantDueToDkg { .. } => panic!("signing RemoveParticipant"),

          Transaction::DkgCommitments { ref mut signed, .. } => signed,
          Transaction::DkgShares { ref mut signed, .. } => signed,
          Transaction::InvalidDkgShare { ref mut signed, .. } => signed,
          Transaction::DkgConfirmed { ref mut signed, .. } => signed,

          Transaction::CosignSubstrateBlock(_) => panic!("signing CosignSubstrateBlock"),

          Transaction::Batch { .. } => panic!("signing Batch"),
          Transaction::SubstrateBlock(_) => panic!("signing SubstrateBlock"),

          Transaction::SubstrateSign(ref mut data) => &mut data.signed,
          Transaction::Sign(ref mut data) => &mut data.signed,
          Transaction::SignCompleted { .. } => panic!("signing SignCompleted"),
        },
      )
    }

    let (nonce, signed_ref) = signed(self);
    signed_ref.signer = Ristretto::generator() * key.deref();
    signed_ref.nonce = nonce;

    let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));
    signed(self).1.signature.R = <Ristretto as Ciphersuite>::generator() * sig_nonce.deref();
    let sig_hash = self.sig_hash(genesis);
    signed(self).1.signature = SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
  }

  pub fn sign_completed_challenge(&self) -> <Ristretto as Ciphersuite>::F {
    if let Transaction::SignCompleted { plan, tx_hash, first_signer, signature } = self {
      let mut transcript =
        RecommendedTranscript::new(b"Coordinator Tributary Transaction SignCompleted");
      transcript.append_message(b"plan", plan);
      transcript.append_message(b"tx_hash", tx_hash);
      transcript.append_message(b"signer", first_signer.to_bytes());
      transcript.append_message(b"nonce", signature.R.to_bytes());
      Ristretto::hash_to_F(b"SignCompleted signature", &transcript.challenge(b"challenge"))
    } else {
      panic!("sign_completed_challenge called on transaction which wasn't SignCompleted")
    }
  }
}
