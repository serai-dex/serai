use std::{
  io,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use blake2::{Digest, Blake2s256};

use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use crate::{ReadWrite, Signed, TransactionError, TransactionKind, Transaction, verify_transaction};

#[cfg(test)]
mod signed;

#[cfg(test)]
mod provided;

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
    TransactionKind::Provided
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

  tx.1.signature = SchnorrSignature::sign(
    key,
    Zeroizing::new(<Ristretto as Ciphersuite>::F::random(rng)),
    tx.sig_hash(genesis),
  );

  let mut nonces = HashMap::from([(signer, nonce)]);
  verify_transaction(&tx, genesis, &mut HashSet::new(), &mut nonces).unwrap();
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
