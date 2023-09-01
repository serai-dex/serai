use core::ops::Deref;
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

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
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, ValidatorSetData},
};

#[rustfmt::skip]
use tributary::{
  ReadWrite,
  transaction::{Signed, TransactionError, TransactionKind, Transaction as TransactionTrait}
};

mod db;
pub use db::*;

mod handle;
pub use handle::*;

pub mod scanner;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TributarySpec {
  serai_block: [u8; 32],
  start_time: u64,
  set: ValidatorSet,
  validators: Vec<(<Ristretto as Ciphersuite>::G, u64)>,
}

impl TributarySpec {
  pub fn new(
    serai_block: [u8; 32],
    start_time: u64,
    set: ValidatorSet,
    set_data: ValidatorSetData,
  ) -> TributarySpec {
    let mut validators = vec![];
    for (participant, amount) in set_data.participants {
      // TODO: Ban invalid keys from being validators on the Serai side
      let participant = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref())
        .expect("invalid key registered as participant");
      // Give one weight on Tributary per bond instance
      validators.push((participant, amount.0 / set_data.bond.0));
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
    // TODO: Support multiple key shares
    // self.validators.iter().map(|(_, weight)| u16::try_from(weight).unwrap()).sum()
    self.validators().len().try_into().unwrap()
  }

  pub fn t(&self) -> u16 {
    ((2 * self.n()) / 3) + 1
  }

  pub fn i(&self, key: <Ristretto as Ciphersuite>::G) -> Option<Participant> {
    let mut i = 1;
    // TODO: Support multiple key shares
    for (validator, _weight) in &self.validators {
      if validator == &key {
        // return (i .. (i + weight)).to_vec();
        return Some(Participant::new(i).unwrap());
      }
      // i += weight;
      i += 1;
    }
    None
  }

  pub fn validators(&self) -> Vec<(<Ristretto as Ciphersuite>::G, u64)> {
    self.validators.clone()
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
      let mut bond = [0; 8];
      reader.read_exact(&mut bond)?;
      validators.push((key, u64::from_le_bytes(bond)));
    }

    Ok(Self { serai_block, start_time, set: ValidatorSet { session, network }, validators })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignData {
  pub plan: [u8; 32],
  pub attempt: u32,

  pub data: Vec<u8>,

  pub signed: Signed,
}

impl ReadWrite for SignData {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut plan = [0; 32];
    reader.read_exact(&mut plan)?;

    let mut attempt = [0; 4];
    reader.read_exact(&mut attempt)?;
    let attempt = u32::from_le_bytes(attempt);

    let data = {
      let mut data_len = [0; 2];
      reader.read_exact(&mut data_len)?;
      let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
      reader.read_exact(&mut data)?;
      data
    };

    let signed = Signed::read(reader)?;

    Ok(SignData { plan, attempt, data, signed })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.plan)?;
    writer.write_all(&self.attempt.to_le_bytes())?;

    if self.data.len() > u16::MAX.into() {
      // Currently, the largest sign item would be a Monero transaction
      // It provides 4 commitments per input (128 bytes), a 64-byte proof for them, along with a
      // key image and proof (96 bytes)
      // Even with all of that, we could support 227 inputs in a single TX
      // Monero is limited to ~120 inputs per TX
      Err(io::Error::new(io::ErrorKind::Other, "signing data exceeded 65535 bytes"))?;
    }
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)?;

    self.signed.write(writer)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  // Once this completes successfully, no more instances should be created.
  DkgCommitments(u32, Vec<u8>, Signed),
  DkgShares {
    attempt: u32,
    sender_i: Participant,
    shares: HashMap<Participant, Vec<u8>>,
    confirmation_nonces: [u8; 64],
    signed: Signed,
  },
  DkgConfirmed(u32, [u8; 32], Signed),

  // When we have synchrony on a batch, we can allow signing it
  // TODO (never?): This is less efficient compared to an ExternalBlock provided transaction,
  // which would be binding over the block hash and automatically achieve synchrony on all
  // relevant batches. ExternalBlock was removed for this due to complexity around the pipeline
  // with the current processor, yet it would still be an improvement.
  Batch([u8; 32], [u8; 32]),
  // When a Serai block is finalized, with the contained batches, we can allow the associated plan
  // IDs
  SubstrateBlock(u64),

  BatchPreprocess(SignData),
  BatchShare(SignData),

  SignPreprocess(SignData),
  SignShare(SignData),
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
      0 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let commitments = {
          let mut commitments_len = [0; 2];
          reader.read_exact(&mut commitments_len)?;
          let mut commitments = vec![0; usize::from(u16::from_le_bytes(commitments_len))];
          reader.read_exact(&mut commitments)?;
          commitments
        };

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgCommitments(attempt, commitments, signed))
      }

      1 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut sender_i = [0; 2];
        reader.read_exact(&mut sender_i)?;
        let sender_i = u16::from_le_bytes(sender_i);

        let shares = {
          let mut share_quantity = [0; 2];
          reader.read_exact(&mut share_quantity)?;

          let mut share_len = [0; 2];
          reader.read_exact(&mut share_len)?;
          let share_len = usize::from(u16::from_le_bytes(share_len));

          let mut shares = HashMap::new();
          for i in 0 .. u16::from_le_bytes(share_quantity) {
            let mut participant = Participant::new(i + 1).unwrap();
            if u16::from(participant) >= sender_i {
              participant = Participant::new(u16::from(participant) + 1).unwrap();
            }
            let mut share = vec![0; share_len];
            reader.read_exact(&mut share)?;
            shares.insert(participant, share);
          }
          shares
        };

        let mut confirmation_nonces = [0; 64];
        reader.read_exact(&mut confirmation_nonces)?;

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgShares {
          attempt,
          sender_i: Participant::new(sender_i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid sender participant"))?,
          shares,
          confirmation_nonces,
          signed,
        })
      }

      2 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let mut confirmation_share = [0; 32];
        reader.read_exact(&mut confirmation_share)?;

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgConfirmed(attempt, confirmation_share, signed))
      }

      3 => {
        let mut block = [0; 32];
        reader.read_exact(&mut block)?;
        let mut batch = [0; 32];
        reader.read_exact(&mut batch)?;
        Ok(Transaction::Batch(block, batch))
      }

      4 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::SubstrateBlock(u64::from_le_bytes(block)))
      }

      5 => SignData::read(reader).map(Transaction::BatchPreprocess),
      6 => SignData::read(reader).map(Transaction::BatchShare),

      7 => SignData::read(reader).map(Transaction::SignPreprocess),
      8 => SignData::read(reader).map(Transaction::SignShare),

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

      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::DkgCommitments(attempt, commitments, signed) => {
        writer.write_all(&[0])?;
        writer.write_all(&attempt.to_le_bytes())?;
        if commitments.len() > u16::MAX.into() {
          // t commitments and an encryption key mean a u16 is fine until a threshold > 2000 occurs
          Err(io::Error::new(io::ErrorKind::Other, "dkg commitments exceeded 65535 bytes"))?;
        }
        writer.write_all(&u16::try_from(commitments.len()).unwrap().to_le_bytes())?;
        writer.write_all(commitments)?;
        signed.write(writer)
      }

      Transaction::DkgShares { attempt, sender_i, shares, confirmation_nonces, signed } => {
        writer.write_all(&[1])?;
        writer.write_all(&attempt.to_le_bytes())?;

        // It's unfortunate to have this so duplicated, yet it avoids needing to pass a Spec to
        // read in order to create a valid DkgShares
        // TODO: Transform DkgShares to having a Vec of shares, with post-expansion to the proper
        // HashMap
        writer.write_all(&u16::from(*sender_i).to_le_bytes())?;

        // Shares are indexed by non-zero u16s (Participants), so this can't fail
        writer.write_all(&u16::try_from(shares.len()).unwrap().to_le_bytes())?;

        let mut share_len = None;
        let mut found_our_share = false;
        for participant in 1 ..= (shares.len() + 1) {
          let Some(share) =
            &shares.get(&Participant::new(u16::try_from(participant).unwrap()).unwrap())
          else {
            assert!(!found_our_share);
            found_our_share = true;
            continue;
          };

          if let Some(share_len) = share_len {
            if share.len() != share_len {
              panic!("variable length shares");
            }
          } else {
            // For BLS12-381 G2, this would be:
            // - A 32-byte share
            // - A 96-byte ephemeral key
            // - A 128-byte signature
            // Hence why this has to be u16
            writer.write_all(&u16::try_from(share.len()).unwrap().to_le_bytes())?;
            share_len = Some(share.len());
          }

          writer.write_all(share)?;
        }
        writer.write_all(confirmation_nonces)?;
        signed.write(writer)
      }

      Transaction::DkgConfirmed(attempt, share, signed) => {
        writer.write_all(&[2])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(share)?;
        signed.write(writer)
      }

      Transaction::Batch(block, batch) => {
        writer.write_all(&[3])?;
        writer.write_all(block)?;
        writer.write_all(batch)
      }

      Transaction::SubstrateBlock(block) => {
        writer.write_all(&[4])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::BatchPreprocess(data) => {
        writer.write_all(&[5])?;
        data.write(writer)
      }
      Transaction::BatchShare(data) => {
        writer.write_all(&[6])?;
        data.write(writer)
      }

      Transaction::SignPreprocess(data) => {
        writer.write_all(&[7])?;
        data.write(writer)
      }
      Transaction::SignShare(data) => {
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
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind<'_> {
    match self {
      Transaction::DkgCommitments(_, _, signed) => TransactionKind::Signed(signed),
      Transaction::DkgShares { signed, .. } => TransactionKind::Signed(signed),
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
      if data.data.len() != 32 {
        Err(TransactionError::InvalidContent)?;
      }
    }

    if let Transaction::SignCompleted { plan, tx_hash, first_signer, signature } = self {
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
        Transaction::DkgCommitments(_, _, ref mut signed) => signed,
        Transaction::DkgShares { ref mut signed, .. } => signed,
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
