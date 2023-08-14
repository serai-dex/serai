use core::ops::Deref;
use std::{io, collections::HashMap, sync::Arc};

use scale::Encode;
use ::tendermint::{
  ext::{Network, Signer as SignerTrait, SignatureScheme, BlockNumber, RoundNumber},
  SignedMessageFor, DataFor, Message, SignedMessage, Data,
};
use zeroize::Zeroizing;
use rand::{RngCore, CryptoRng, rngs::OsRng};

use blake2::{Digest, Blake2s256};

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::{
  transaction::{Signed, TransactionError, TransactionKind, Transaction, verify_transaction},
  ReadWrite,
  tendermint::{
    tx::{TendermintTx, VoteSignature, SlashVote},
    Validators, Signer,
  },
};

use lazy_static::lazy_static;

use tokio::sync::Mutex;

#[cfg(test)]
mod signed;

#[cfg(test)]
mod tendermint;

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = $crate::tests::transaction::SEQUENTIAL.lock().await;
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}

pub fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  Signed {
    signer: <Ristretto as Ciphersuite>::G::random(&mut *rng),
    nonce: u32::try_from(rng.next_u64() >> 32 >> 1).unwrap(),
    signature: SchnorrSignature::<Ristretto> {
      R: <Ristretto as Ciphersuite>::G::random(&mut *rng),
      s: <Ristretto as Ciphersuite>::F::random(rng),
    },
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvidedTransaction(pub Vec<u8>);

impl ReadWrite for ProvidedTransaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let mut data = vec![0; usize::try_from(u32::from_le_bytes(len)).unwrap()];
    reader.read_exact(&mut data)?;
    Ok(ProvidedTransaction(data))
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.0.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.0)
  }
}

impl Transaction for ProvidedTransaction {
  fn kind(&self) -> TransactionKind<'_> {
    TransactionKind::Provided("provided")
  }

  fn hash(&self) -> [u8; 32] {
    Blake2s256::digest(self.serialize()).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

pub fn random_provided_transaction<R: RngCore + CryptoRng>(rng: &mut R) -> ProvidedTransaction {
  let mut data = vec![0; 512];
  rng.fill_bytes(&mut data);
  ProvidedTransaction(data)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedTransaction(pub Vec<u8>, pub Signed);

impl ReadWrite for SignedTransaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let mut data = vec![0; usize::try_from(u32::from_le_bytes(len)).unwrap()];
    reader.read_exact(&mut data)?;

    Ok(SignedTransaction(data, Signed::read(reader)?))
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.0.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.0)?;
    self.1.write(writer)
  }
}

impl Transaction for SignedTransaction {
  fn kind(&self) -> TransactionKind<'_> {
    TransactionKind::Signed(&self.1)
  }

  fn hash(&self) -> [u8; 32] {
    let serialized = self.serialize();
    Blake2s256::digest(&serialized[.. (serialized.len() - 64)]).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

pub fn signed_transaction<R: RngCore + CryptoRng>(
  rng: &mut R,
  genesis: [u8; 32],
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  nonce: u32,
) -> SignedTransaction {
  let mut data = vec![0; 512];
  rng.fill_bytes(&mut data);

  let signer = <Ristretto as Ciphersuite>::generator() * **key;

  let mut tx =
    SignedTransaction(data, Signed { signer, nonce, signature: random_signed(rng).signature });

  let sig_nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng));
  tx.1.signature.R = Ristretto::generator() * sig_nonce.deref();
  tx.1.signature = SchnorrSignature::sign(key, sig_nonce, tx.sig_hash(genesis));

  let mut nonces = HashMap::from([(signer, nonce)]);
  verify_transaction(&tx, genesis, &mut nonces).unwrap();
  assert_eq!(nonces, HashMap::from([(tx.1.signer, tx.1.nonce.wrapping_add(1))]));

  tx
}

pub fn random_signed_transaction<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> ([u8; 32], SignedTransaction) {
  let mut genesis = [0; 32];
  rng.fill_bytes(&mut genesis);

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut *rng));
  // Shift over an additional bit to ensure it won't overflow when incremented
  let nonce = u32::try_from(rng.next_u64() >> 32 >> 1).unwrap();

  (genesis, signed_transaction(rng, genesis, &key, nonce))
}

pub fn new_genesis() -> [u8; 32] {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  genesis
}

pub async fn signer() -> ([u8; 32], Signer, [u8; 32], Arc<Validators>) {
  // signer
  let genesis = new_genesis();
  let signer =
    Signer::new(genesis, Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
  let validator_id = signer.validator_id().await.unwrap();

  // schema
  let signer_g = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut validator_id.as_slice()).unwrap();
  let validators = Arc::new(Validators::new(genesis, vec![(signer_g, 1)]).unwrap());

  (genesis, signer, validator_id, validators)
}

pub fn encode_evidence<N: Network>(ev: Vec<SignedMessageFor<N>>) -> Vec<u8> {
  let mut data = vec![];
  data.extend(u8::to_le_bytes(u8::try_from(ev.len()).unwrap()));
  for msg in ev {
    let encoded = msg.encode();
    data.extend(u32::to_le_bytes(u32::try_from(encoded.len()).unwrap()));
    data.extend(encoded);
  }
  data
}

pub fn tx_from_evidence<N: Network>(ev: Vec<SignedMessageFor<N>>) -> TendermintTx {
  let evidence = encode_evidence::<N>(ev);
  TendermintTx::SlashEvidence(evidence)
}

pub async fn signed_from_data<N: Network>(
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  signer_id: N::ValidatorId,
  block_number: u64,
  round_number: u32,
  data: DataFor<N>,
) -> SignedMessageFor<N> {
  let msg = Message {
    sender: signer_id,
    block: BlockNumber(block_number),
    round: RoundNumber(round_number),
    data,
  };
  let sig = signer.sign(&msg.encode()).await;
  SignedMessage { msg, sig }
}

pub async fn random_evidence_tx<N: Network>(
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  b: N::Block,
) -> TendermintTx {
  let data = Data::Proposal(Some(RoundNumber(0)), b);
  let signer_id = signer.validator_id().await.unwrap();
  let signed = signed_from_data::<N>(signer, signer_id, 0, 0, data).await;
  tx_from_evidence::<N>(vec![signed])
}

pub fn random_vote_tx<R: RngCore + CryptoRng>(rng: &mut R, genesis: [u8; 32]) -> TendermintTx {
  // private key
  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut *rng));

  // vote data
  let mut id = [0u8; 32];
  let mut target = [0u8; 32];
  rng.fill_bytes(&mut id);
  rng.fill_bytes(&mut target);

  let mut tx = TendermintTx::SlashVote(SlashVote { id, target, sig: VoteSignature::default() });
  tx.sign(rng, genesis, &key);

  tx
}
