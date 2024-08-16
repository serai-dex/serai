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
  RemoveParticipant {
    participant: <Ristretto as Ciphersuite>::G,
    signed: Signed,
  },

  DkgParticipation {
    participation: Vec<u8>,
    signed: Signed,
  },
  DkgConfirmationNonces {
    // The confirmation attempt
    attempt: u32,
    // The nonces for DKG confirmation attempt #attempt
    confirmation_nonces: [u8; 64],
    signed: Signed,
  },
  DkgConfirmationShare {
    // The confirmation attempt
    attempt: u32,
    // The share for DKG confirmation attempt #attempt
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

  SlashReport(Vec<u32>, Signed),
}

impl Debug for Transaction {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    match self {
      Transaction::RemoveParticipant { participant, signed } => fmt
        .debug_struct("Transaction::RemoveParticipant")
        .field("participant", &hex::encode(participant.to_bytes()))
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::DkgParticipation { signed, .. } => fmt
        .debug_struct("Transaction::DkgParticipation")
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::DkgConfirmationNonces { attempt, signed, .. } => fmt
        .debug_struct("Transaction::DkgConfirmationNonces")
        .field("attempt", attempt)
        .field("signer", &hex::encode(signed.signer.to_bytes()))
        .finish_non_exhaustive(),
      Transaction::DkgConfirmationShare { attempt, signed, .. } => fmt
        .debug_struct("Transaction::DkgConfirmationShare")
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
      Transaction::SlashReport(points, signed) => fmt
        .debug_struct("Transaction::SignCompleted")
        .field("points", points)
        .field("signed", signed)
        .finish(),
    }
  }
}

impl ReadWrite for Transaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => Ok(Transaction::RemoveParticipant {
        participant: Ristretto::read_G(reader)?,
        signed: Signed::read_without_nonce(reader, 0)?,
      }),

      1 => {
        let participation = {
          let mut participation_len = [0; 4];
          reader.read_exact(&mut participation_len)?;
          let participation_len = u32::from_le_bytes(participation_len);

          if participation_len > u32::try_from(TRANSACTION_SIZE_LIMIT).unwrap() {
            Err(io::Error::other(
              "participation present in transaction exceeded transaction size limit",
            ))?;
          }
          let participation_len = usize::try_from(participation_len).unwrap();

          let mut participation = vec![0; participation_len];
          reader.read_exact(&mut participation)?;
          participation
        };

        let signed = Signed::read_without_nonce(reader, 0)?;

        Ok(Transaction::DkgParticipation { participation, signed })
      }

      2 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut confirmation_nonces = [0; 64];
        reader.read_exact(&mut confirmation_nonces)?;

        let signed = Signed::read_without_nonce(reader, 0)?;

        Ok(Transaction::DkgConfirmationNonces { attempt, confirmation_nonces, signed })
      }

      3 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut confirmation_share = [0; 32];
        reader.read_exact(&mut confirmation_share)?;

        let signed = Signed::read_without_nonce(reader, 1)?;

        Ok(Transaction::DkgConfirmationShare { attempt, confirmation_share, signed })
      }

      4 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        Ok(Transaction::CosignSubstrateBlock(block))
      }

      5 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        let mut batch = [0; 4];
        reader.read_exact(&mut batch)?;
        Ok(Transaction::Batch { block, batch: u32::from_le_bytes(batch) })
      }

      6 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::SubstrateBlock(u64::from_le_bytes(block)))
      }

      7 => SignData::read(reader).map(Transaction::SubstrateSign),
      8 => SignData::read(reader).map(Transaction::Sign),

      9 => {
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

      10 => {
        let mut len = [0];
        reader.read_exact(&mut len)?;
        let len = len[0];
        // If the set has as many validators as MAX_KEY_SHARES_PER_SET, then the amount of distinct
        // validators (the amount of validators reported on) will be at most
        // `MAX_KEY_SHARES_PER_SET - 1`
        if u32::from(len) > (serai_client::validator_sets::primitives::MAX_KEY_SHARES_PER_SET - 1) {
          Err(io::Error::other("more points reported than allowed validator"))?;
        }
        let mut points = vec![0u32; len.into()];
        for points in &mut points {
          let mut these_points = [0; 4];
          reader.read_exact(&mut these_points)?;
          *points = u32::from_le_bytes(these_points);
        }
        Ok(Transaction::SlashReport(points, Signed::read_without_nonce(reader, 0)?))
      }

      _ => Err(io::Error::other("invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::RemoveParticipant { participant, signed } => {
        writer.write_all(&[0])?;
        writer.write_all(&participant.to_bytes())?;
        signed.write_without_nonce(writer)
      }

      Transaction::DkgParticipation { participation, signed } => {
        writer.write_all(&[1])?;
        writer.write_all(&u32::try_from(participation.len()).unwrap().to_le_bytes())?;
        writer.write_all(participation)?;
        signed.write_without_nonce(writer)
      }

      Transaction::DkgConfirmationNonces { attempt, confirmation_nonces, signed } => {
        writer.write_all(&[2])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(confirmation_nonces)?;
        signed.write_without_nonce(writer)
      }

      Transaction::DkgConfirmationShare { attempt, confirmation_share, signed } => {
        writer.write_all(&[3])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(confirmation_share)?;
        signed.write_without_nonce(writer)
      }

      Transaction::CosignSubstrateBlock(block) => {
        writer.write_all(&[4])?;
        writer.write_all(block)
      }

      Transaction::Batch { block, batch } => {
        writer.write_all(&[5])?;
        writer.write_all(block)?;
        writer.write_all(&batch.to_le_bytes())
      }

      Transaction::SubstrateBlock(block) => {
        writer.write_all(&[6])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::SubstrateSign(data) => {
        writer.write_all(&[7])?;
        data.write(writer)
      }
      Transaction::Sign(data) => {
        writer.write_all(&[8])?;
        data.write(writer)
      }
      Transaction::SignCompleted { plan, tx_hash, first_signer, signature } => {
        writer.write_all(&[9])?;
        writer.write_all(plan)?;
        writer
          .write_all(&[u8::try_from(tx_hash.len()).expect("tx hash length exceed 255 bytes")])?;
        writer.write_all(tx_hash)?;
        writer.write_all(&first_signer.to_bytes())?;
        signature.write(writer)
      }
      Transaction::SlashReport(points, signed) => {
        writer.write_all(&[10])?;
        writer.write_all(&[u8::try_from(points.len()).unwrap()])?;
        for points in points {
          writer.write_all(&points.to_le_bytes())?;
        }
        signed.write_without_nonce(writer)
      }
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind<'_> {
    match self {
      Transaction::RemoveParticipant { participant, signed } => {
        TransactionKind::Signed((b"remove", participant.to_bytes()).encode(), signed)
      }

      Transaction::DkgParticipation { signed, .. } => {
        TransactionKind::Signed(b"dkg".to_vec(), signed)
      }
      Transaction::DkgConfirmationNonces { attempt, signed, .. } |
      Transaction::DkgConfirmationShare { attempt, signed, .. } => {
        TransactionKind::Signed((b"dkg_confirmation", attempt).encode(), signed)
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

      Transaction::SlashReport(_, signed) => {
        TransactionKind::Signed(b"slash_report".to_vec(), signed)
      }
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
      #[allow(clippy::match_same_arms)] // Doesn't make semantic sense here
      let nonce = match tx {
        Transaction::RemoveParticipant { .. } => 0,

        Transaction::DkgParticipation { .. } => 0,
        // Uses a nonce of 0 as it has an internal attempt counter we distinguish by
        Transaction::DkgConfirmationNonces { .. } => 0,
        // Uses a nonce of 1 due to internal attempt counter and due to following
        // DkgConfirmationNonces
        Transaction::DkgConfirmationShare { .. } => 1,

        Transaction::CosignSubstrateBlock(_) => panic!("signing CosignSubstrateBlock"),

        Transaction::Batch { .. } => panic!("signing Batch"),
        Transaction::SubstrateBlock(_) => panic!("signing SubstrateBlock"),

        Transaction::SubstrateSign(data) => data.label.nonce(),
        Transaction::Sign(data) => data.label.nonce(),

        Transaction::SignCompleted { .. } => panic!("signing SignCompleted"),

        Transaction::SlashReport(_, _) => 0,
      };

      (
        nonce,
        #[allow(clippy::match_same_arms)]
        match tx {
          Transaction::RemoveParticipant { ref mut signed, .. } |
          Transaction::DkgParticipation { ref mut signed, .. } |
          Transaction::DkgConfirmationNonces { ref mut signed, .. } => signed,
          Transaction::DkgConfirmationShare { ref mut signed, .. } => signed,

          Transaction::CosignSubstrateBlock(_) => panic!("signing CosignSubstrateBlock"),

          Transaction::Batch { .. } => panic!("signing Batch"),
          Transaction::SubstrateBlock(_) => panic!("signing SubstrateBlock"),

          Transaction::SubstrateSign(ref mut data) => &mut data.signed,
          Transaction::Sign(ref mut data) => &mut data.signed,

          Transaction::SignCompleted { .. } => panic!("signing SignCompleted"),

          Transaction::SlashReport(_, ref mut signed) => signed,
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
