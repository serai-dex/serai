use std::{io, collections::HashMap, sync::Arc, fmt::Debug};

use blake2::{Blake2s256, Digest};
use ciphersuite::{
  group::{ff::Field, Group},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use serai_db::MemDb;
use tendermint::ext::Commit;

use crate::{
  ReadWrite, BlockError, Block, Transaction,
  tests::p2p::LocalP2p,
  transaction::{TransactionError, Signed, TransactionKind, Transaction as TransactionTrait},
  tendermint::{TendermintNetwork, Validators}
};

type N = TendermintNetwork<MemDb, NonceTransaction, LocalP2p>;

// A transaction solely defined by its nonce and a distinguisher (to allow creating distinct TXs
// sharing a nonce).
#[derive(Clone, PartialEq, Eq, Debug)]
struct NonceTransaction(u32, u8, Signed);

impl NonceTransaction {
  fn new(nonce: u32, distinguisher: u8) -> Self {
    NonceTransaction(
      nonce,
      distinguisher,
      Signed {
        signer: <Ristretto as Ciphersuite>::G::identity(),
        nonce,
        signature: SchnorrSignature::<Ristretto> {
          R: <Ristretto as Ciphersuite>::G::identity(),
          s: <Ristretto as Ciphersuite>::F::ZERO,
        },
      },
    )
  }
}

impl ReadWrite for NonceTransaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut nonce = [0; 4];
    reader.read_exact(&mut nonce)?;
    let nonce = u32::from_le_bytes(nonce);

    let mut distinguisher = [0];
    reader.read_exact(&mut distinguisher)?;

    Ok(NonceTransaction::new(nonce, distinguisher[0]))
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.0.to_le_bytes())?;
    writer.write_all(&[self.1])
  }
}

impl TransactionTrait for NonceTransaction {
  fn kind(&self) -> TransactionKind<'_> {
    TransactionKind::Signed(&self.2)
  }

  fn hash(&self) -> [u8; 32] {
    Blake2s256::digest([self.0.to_le_bytes().as_ref(), &[self.1]].concat()).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    Ok(())
  }
}

#[test]
fn empty_block() {
  const GENESIS: [u8; 32] = [0xff; 32];
  const LAST: [u8; 32] = [0x01; 32];
  let validators = Arc::new(Validators::new(GENESIS, vec![]).unwrap());
  let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
  };
  let unsigned_in_chain = |_: [u8; 32]| {false};
  Block::<NonceTransaction>::new(LAST, vec![], vec![])
    .verify::<N>(
      GENESIS, LAST, HashMap::new(), HashMap::new(), validators, commit, unsigned_in_chain
    ).unwrap();
}

#[test]
fn duplicate_nonces() {
  const GENESIS: [u8; 32] = [0xff; 32];
  const LAST: [u8; 32] = [0x01; 32];

  let validators = Arc::new(Validators::new(GENESIS, vec![]).unwrap());

  // Run once without duplicating a nonce, and once with, so that's confirmed to be the faulty
  // component
  for i in [1, 0] {
    let mut mempool = vec![];
    let mut insert = |tx: NonceTransaction| mempool.push(Transaction::Application(tx));
    insert(NonceTransaction::new(0, 0));
    insert(NonceTransaction::new(i, 1));

    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
    };
    let unsigned_in_chain = |_: [u8; 32]| {false};

    let res = Block::new(LAST, vec![], mempool).verify::<N>(
      GENESIS,
      LAST,
      HashMap::new(),
      HashMap::from([(<Ristretto as Ciphersuite>::G::identity(), 0)]),
      validators.clone(),
      commit,
      unsigned_in_chain
    );
    if i == 1 {
      res.unwrap();
    } else {
      assert_eq!(res, Err(BlockError::TransactionError(TransactionError::InvalidNonce)));
    }
  }
}
