use core::ops::{Deref, Range};
use std::io::{self, Read, Write};

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

use serai_client::{
  primitives::{NetworkId, PublicKey},
  validator_sets::primitives::{Session, ValidatorSet},
};

#[rustfmt::skip]
use tributary::{
  ReadWrite,
  transaction::{Signed, TransactionError, TransactionKind, Transaction as TransactionTrait},
  TRANSACTION_SIZE_LIMIT,
};

mod db;
pub use db::*;

mod nonce_decider;
pub use nonce_decider::*;

mod dkg_confirmer;

mod handle;
pub use handle::*;

pub mod scanner;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TributarySpec {
  serai_block: [u8; 32],
  start_time: u64,
  set: ValidatorSet,
  validators: Vec<(<Ristretto as Ciphersuite>::G, u16)>,
}

impl TributarySpec {
  pub fn new(
    serai_block: [u8; 32],
    start_time: u64,
    set: ValidatorSet,
    set_participants: Vec<(PublicKey, u16)>,
  ) -> TributarySpec {
    let mut validators = vec![];
    for (participant, shares) in set_participants {
      let participant = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref())
        .expect("invalid key registered as participant");
      validators.push((participant, shares));
    }

    Self { serai_block, start_time, set, validators }
  }

  pub fn set(&self) -> ValidatorSet {
    self.set
  }

  pub fn genesis(&self) -> [u8; 32] {
    // Calculate the genesis for this Tributary
    let mut genesis = RecommendedTranscript::new(b"Serai Tributary Genesis");
    // This locks it to a specific Serai chain
    genesis.append_message(b"serai_block", self.serai_block);
    genesis.append_message(b"session", self.set.session.0.to_le_bytes());
    genesis.append_message(b"network", self.set.network.encode());
    let genesis = genesis.challenge(b"genesis");
    let genesis_ref: &[u8] = genesis.as_ref();
    genesis_ref[.. 32].try_into().unwrap()
  }

  pub fn start_time(&self) -> u64 {
    self.start_time
  }

  pub fn n(&self) -> u16 {
    self.validators.iter().map(|(_, weight)| weight).sum()
  }

  pub fn t(&self) -> u16 {
    ((2 * self.n()) / 3) + 1
  }

  pub fn i(&self, key: <Ristretto as Ciphersuite>::G) -> Option<Range<Participant>> {
    let mut i = 1;
    for (validator, weight) in &self.validators {
      if validator == &key {
        return Some(Range {
          start: Participant::new(i).unwrap(),
          end: Participant::new(i + weight).unwrap(),
        });
      }
      i += weight;
    }
    None
  }

  pub fn validators(&self) -> Vec<(<Ristretto as Ciphersuite>::G, u64)> {
    self.validators.iter().map(|(validator, weight)| (*validator, u64::from(*weight))).collect()
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.serai_block)?;
    writer.write_all(&self.start_time.to_le_bytes())?;
    writer.write_all(&self.set.session.0.to_le_bytes())?;
    let network_encoded = self.set.network.encode();
    assert_eq!(network_encoded.len(), 1);
    writer.write_all(&network_encoded)?;
    writer.write_all(&u32::try_from(self.validators.len()).unwrap().to_le_bytes())?;
    for validator in &self.validators {
      writer.write_all(&validator.0.to_bytes())?;
      writer.write_all(&validator.1.to_le_bytes())?;
    }
    Ok(())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }

  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    let mut serai_block = [0; 32];
    reader.read_exact(&mut serai_block)?;

    let mut start_time = [0; 8];
    reader.read_exact(&mut start_time)?;
    let start_time = u64::from_le_bytes(start_time);

    let mut session = [0; 4];
    reader.read_exact(&mut session)?;
    let session = Session(u32::from_le_bytes(session));

    let mut network = [0; 1];
    reader.read_exact(&mut network)?;
    let network = NetworkId::decode(&mut &network[..])
      .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid network"))?;

    let mut validators_len = [0; 4];
    reader.read_exact(&mut validators_len)?;
    let validators_len = usize::try_from(u32::from_le_bytes(validators_len)).unwrap();

    let mut validators = Vec::with_capacity(validators_len);
    for _ in 0 .. validators_len {
      let key = Ristretto::read_G(reader)?;
      let mut weight = [0; 2];
      reader.read_exact(&mut weight)?;
      validators.push((key, u16::from_le_bytes(weight)));
    }

    Ok(Self { serai_block, start_time, set: ValidatorSet { session, network }, validators })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignData<const N: usize> {
  pub plan: [u8; N],
  pub attempt: u32,

  pub data: Vec<Vec<u8>>,

  pub signed: Signed,
}

impl<const N: usize> ReadWrite for SignData<N> {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut plan = [0; N];
    reader.read_exact(&mut plan)?;

    let mut attempt = [0; 4];
    reader.read_exact(&mut attempt)?;
    let attempt = u32::from_le_bytes(attempt);

    let data = {
      let mut data_pieces = [0];
      reader.read_exact(&mut data_pieces)?;
      if data_pieces[0] == 0 {
        Err(io::Error::new(io::ErrorKind::Other, "zero pieces of data in SignData"))?;
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

    let signed = Signed::read(reader)?;

    Ok(SignData { plan, attempt, data, signed })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.plan)?;
    writer.write_all(&self.attempt.to_le_bytes())?;

    writer.write_all(&[u8::try_from(self.data.len()).unwrap()])?;
    for data in &self.data {
      if data.len() > u16::MAX.into() {
        // Currently, the largest individual preproces is a Monero transaction
        // It provides 4 commitments per input (128 bytes), a 64-byte proof for them, along with a
        // key image and proof (96 bytes)
        // Even with all of that, we could support 227 inputs in a single TX
        // Monero is limited to ~120 inputs per TX
        //
        // Bitcoin has a much higher input count of 520, yet it only uses 64 bytes per preprocess
        Err(io::Error::new(io::ErrorKind::Other, "signing data exceeded 65535 bytes"))?;
      }
      writer.write_all(&u16::try_from(data.len()).unwrap().to_le_bytes())?;
      writer.write_all(data)?;
    }

    self.signed.write(writer)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  RemoveParticipant(Participant),

  // Once this completes successfully, no more instances should be created.
  DkgCommitments(u32, Vec<Vec<u8>>, Signed),
  DkgShares {
    attempt: u32,
    // Receiving Participant, Sending Participant, Share
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
  DkgConfirmed(u32, [u8; 32], Signed),

  // When we have synchrony on a batch, we can allow signing it
  // TODO (never?): This is less efficient compared to an ExternalBlock provided transaction,
  // which would be binding over the block hash and automatically achieve synchrony on all
  // relevant batches. ExternalBlock was removed for this due to complexity around the pipeline
  // with the current processor, yet it would still be an improvement.
  Batch([u8; 32], [u8; 5]),
  // When a Serai block is finalized, with the contained batches, we can allow the associated plan
  // IDs
  SubstrateBlock(u64),

  BatchPreprocess(SignData<5>),
  BatchShare(SignData<5>),

  SignPreprocess(SignData<32>),
  SignShare(SignData<32>),
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

impl ReadWrite for Transaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => Ok(Transaction::RemoveParticipant({
        let mut participant = [0; 2];
        reader.read_exact(&mut participant)?;
        Participant::new(u16::from_le_bytes(participant)).ok_or_else(|| {
          io::Error::new(io::ErrorKind::Other, "invalid participant in RemoveParticipant")
        })?
      })),

      1 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let commitments = {
          let mut commitments_len = [0; 1];
          reader.read_exact(&mut commitments_len)?;
          let commitments_len = usize::from(commitments_len[0]);
          if commitments_len == 0 {
            Err(io::Error::new(io::ErrorKind::Other, "zero commitments in DkgCommitments"))?;
          }

          let mut each_commitments_len = [0; 2];
          reader.read_exact(&mut each_commitments_len)?;
          let each_commitments_len = usize::from(u16::from_le_bytes(each_commitments_len));
          if (commitments_len * each_commitments_len) > TRANSACTION_SIZE_LIMIT {
            Err(io::Error::new(
              io::ErrorKind::Other,
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

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgCommitments(attempt, commitments, signed))
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

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgShares { attempt, shares, confirmation_nonces, signed })
      }

      3 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut accuser = [0; 2];
        reader.read_exact(&mut accuser)?;
        let accuser = Participant::new(u16::from_le_bytes(accuser)).ok_or_else(|| {
          io::Error::new(io::ErrorKind::Other, "invalid participant in InvalidDkgShare")
        })?;

        let mut faulty = [0; 2];
        reader.read_exact(&mut faulty)?;
        let faulty = Participant::new(u16::from_le_bytes(faulty)).ok_or_else(|| {
          io::Error::new(io::ErrorKind::Other, "invalid participant in InvalidDkgShare")
        })?;

        let mut blame_len = [0; 2];
        reader.read_exact(&mut blame_len)?;
        let mut blame = vec![0; u16::from_le_bytes(blame_len).into()];
        reader.read_exact(&mut blame)?;

        let signed = Signed::read(reader)?;

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

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgConfirmed(attempt, confirmation_share, signed))
      }

      5 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        let mut batch = [0; 5];
        reader.read_exact(&mut batch)?;
        Ok(Transaction::Batch(block, batch))
      }

      6 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::SubstrateBlock(u64::from_le_bytes(block)))
      }

      7 => SignData::read(reader).map(Transaction::BatchPreprocess),
      8 => SignData::read(reader).map(Transaction::BatchShare),

      9 => SignData::read(reader).map(Transaction::SignPreprocess),
      10 => SignData::read(reader).map(Transaction::SignShare),

      11 => {
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

      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::RemoveParticipant(i) => {
        writer.write_all(&[0])?;
        writer.write_all(&u16::from(*i).to_le_bytes())
      }

      Transaction::DkgCommitments(attempt, commitments, signed) => {
        writer.write_all(&[1])?;
        writer.write_all(&attempt.to_le_bytes())?;
        if commitments.is_empty() {
          Err(io::Error::new(io::ErrorKind::Other, "zero commitments in DkgCommitments"))?
        }
        writer.write_all(&[u8::try_from(commitments.len()).unwrap()])?;
        for commitments_i in commitments {
          if commitments_i.len() != commitments[0].len() {
            Err(io::Error::new(
              io::ErrorKind::Other,
              "commitments of differing sizes in DkgCommitments",
            ))?
          }
        }
        writer.write_all(&u16::try_from(commitments[0].len()).unwrap().to_le_bytes())?;
        for commitments in commitments {
          writer.write_all(commitments)?;
        }
        signed.write(writer)
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
        signed.write(writer)
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

        signed.write(writer)
      }

      Transaction::DkgConfirmed(attempt, share, signed) => {
        writer.write_all(&[4])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(share)?;
        signed.write(writer)
      }

      Transaction::Batch(block, batch) => {
        writer.write_all(&[5])?;
        writer.write_all(block)?;
        writer.write_all(batch)
      }

      Transaction::SubstrateBlock(block) => {
        writer.write_all(&[6])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::BatchPreprocess(data) => {
        writer.write_all(&[7])?;
        data.write(writer)
      }
      Transaction::BatchShare(data) => {
        writer.write_all(&[8])?;
        data.write(writer)
      }

      Transaction::SignPreprocess(data) => {
        writer.write_all(&[9])?;
        data.write(writer)
      }
      Transaction::SignShare(data) => {
        writer.write_all(&[10])?;
        data.write(writer)
      }
      Transaction::SignCompleted { plan, tx_hash, first_signer, signature } => {
        writer.write_all(&[11])?;
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
      Transaction::RemoveParticipant(_) => TransactionKind::Provided("remove"),

      Transaction::DkgCommitments(_, _, signed) => TransactionKind::Signed(signed),
      Transaction::DkgShares { signed, .. } => TransactionKind::Signed(signed),
      Transaction::InvalidDkgShare { signed, .. } => TransactionKind::Signed(signed),
      Transaction::DkgConfirmed(_, _, signed) => TransactionKind::Signed(signed),

      Transaction::Batch(_, _) => TransactionKind::Provided("batch"),
      Transaction::SubstrateBlock(_) => TransactionKind::Provided("serai"),

      Transaction::BatchPreprocess(data) => TransactionKind::Signed(&data.signed),
      Transaction::BatchShare(data) => TransactionKind::Signed(&data.signed),

      Transaction::SignPreprocess(data) => TransactionKind::Signed(&data.signed),
      Transaction::SignShare(data) => TransactionKind::Signed(&data.signed),
      Transaction::SignCompleted { .. } => TransactionKind::Unsigned,
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = self.serialize();
    if let TransactionKind::Signed(signed) = self.kind() {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), signed.signature.serialize());
    }
    Blake2s256::digest(tx).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    if let Transaction::BatchShare(data) = self {
      for data in &data.data {
        if data.len() != 32 {
          Err(TransactionError::InvalidContent)?;
        }
      }
    }

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
    nonce: u32,
  ) {
    fn signed(tx: &mut Transaction) -> &mut Signed {
      match tx {
        Transaction::RemoveParticipant(_) => panic!("signing RemoveParticipant"),

        Transaction::DkgCommitments(_, _, ref mut signed) => signed,
        Transaction::DkgShares { ref mut signed, .. } => signed,
        Transaction::InvalidDkgShare { ref mut signed, .. } => signed,
        Transaction::DkgConfirmed(_, _, ref mut signed) => signed,

        Transaction::Batch(_, _) => panic!("signing Batch"),
        Transaction::SubstrateBlock(_) => panic!("signing SubstrateBlock"),

        Transaction::BatchPreprocess(ref mut data) => &mut data.signed,
        Transaction::BatchShare(ref mut data) => &mut data.signed,

        Transaction::SignPreprocess(ref mut data) => &mut data.signed,
        Transaction::SignShare(ref mut data) => &mut data.signed,
        Transaction::SignCompleted { .. } => panic!("signing SignCompleted"),
      }
    }

    let signed_ref = signed(self);
    signed_ref.signer = Ristretto::generator() * key.deref();
    signed_ref.nonce = nonce;

    let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));
    signed(self).signature.R = <Ristretto as Ciphersuite>::generator() * sig_nonce.deref();
    let sig_hash = self.sig_hash(genesis);
    signed(self).signature = SchnorrSignature::<Ristretto>::sign(key, sig_nonce, sig_hash);
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
