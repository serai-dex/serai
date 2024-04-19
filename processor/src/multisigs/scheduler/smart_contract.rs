use std::{io, collections::HashSet};

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use serai_client::primitives::{NetworkId, Coin, Balance};

use crate::{
  Get, DbTxn, Db, Payment, Plan, create_db,
  networks::{Output, Network},
  multisigs::scheduler::{SchedulerAddendum, Scheduler as SchedulerTrait},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scheduler<N: Network> {
  key: <N::Curve as Ciphersuite>::G,
  coins: HashSet<Coin>,
  rotated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Addendum<N: Network> {
  Nonce(u64),
  RotateTo { nonce: u64, new_key: <N::Curve as Ciphersuite>::G },
}

impl<N: Network> SchedulerAddendum for Addendum<N> {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let mut nonce = [0; 8];
        reader.read_exact(&mut nonce)?;
        Ok(Addendum::Nonce(u64::from_le_bytes(nonce)))
      }
      1 => {
        let mut nonce = [0; 8];
        reader.read_exact(&mut nonce)?;
        let nonce = u64::from_le_bytes(nonce);

        let new_key = N::Curve::read_G(reader)?;
        Ok(Addendum::RotateTo { nonce, new_key })
      }
      _ => Err(io::Error::other("reading unknown Addendum type"))?,
    }
  }
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Addendum::Nonce(nonce) => {
        writer.write_all(&[0])?;
        writer.write_all(&nonce.to_le_bytes())
      }
      Addendum::RotateTo { nonce, new_key } => {
        writer.write_all(&[1])?;
        writer.write_all(&nonce.to_le_bytes())?;
        writer.write_all(new_key.to_bytes().as_ref())
      }
    }
  }
}

create_db! {
  SchedulerDb {
    LastNonce: () -> u64,
    Rotated: (key: &[u8]) -> (),
  }
}

impl<N: Network<Scheduler = Self>> SchedulerTrait<N> for Scheduler<N> {
  type Addendum = Addendum<N>;

  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool {
    self.rotated
  }

  /// Create a new Scheduler.
  fn new<D: Db>(
    _txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> Self {
    assert!(N::branch_address(key).is_none());
    assert!(N::change_address(key).is_none());
    assert!(N::forward_address(key).is_none());

    Scheduler { key, coins: network.coins().iter().copied().collect(), rotated: false }
  }

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(
    db: &D,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> io::Result<Self> {
    Ok(Scheduler {
      key,
      coins: network.coins().iter().copied().collect(),
      rotated: Rotated::get(db, key.to_bytes().as_ref()).is_some(),
    })
  }

  fn can_use_branch(&self, _balance: Balance) -> bool {
    false
  }

  fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
    force_spend: bool,
  ) -> Vec<Plan<N>> {
    for utxo in utxos {
      assert!(self.coins.contains(&utxo.balance().coin));
    }

    let mut nonce = LastNonce::get(txn).map_or(0, |nonce| nonce + 1);
    let mut plans = vec![];
    for chunk in payments.as_slice().chunks(N::MAX_OUTPUTS) {
      plans.push(Plan {
        key: self.key,
        inputs: vec![],
        payments: chunk.to_vec(),
        change: None,
        scheduler_addendum: Addendum::Nonce(nonce),
      });
      nonce += 1;
    }

    // If we're supposed to rotate to the new key, create an empty Plan which will signify the key
    // update
    if force_spend && (!self.rotated) {
      plans.push(Plan {
        key: self.key,
        inputs: vec![],
        payments: vec![],
        change: None,
        scheduler_addendum: Addendum::RotateTo { nonce, new_key: key_for_any_change },
      });
      nonce += 1;
      self.rotated = true;
      Rotated::set(txn, self.key.to_bytes().as_ref(), &());
    }

    LastNonce::set(txn, &nonce);

    plans
  }

  fn consume_payments<D: Db>(&mut self, _txn: &mut D::Transaction<'_>) -> Vec<Payment<N>> {
    vec![]
  }

  fn created_output<D: Db>(
    &mut self,
    _txn: &mut D::Transaction<'_>,
    _expected: u64,
    _actual: Option<u64>,
  ) {
    panic!("Smart Contract Scheduler created a Branch output")
  }

  /// Refund a specific output.
  fn refund_plan<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    output: N::Output,
    refund_to: N::Address,
  ) -> Plan<N> {
    let nonce = LastNonce::get(txn).map_or(0, |nonce| nonce + 1);
    LastNonce::set(txn, &(nonce + 1));
    Plan {
      key: self.key,
      inputs: vec![],
      payments: vec![Payment { address: refund_to, data: None, balance: output.balance() }],
      change: None,
      scheduler_addendum: Addendum::Nonce(nonce),
    }
  }

  fn shim_forward_plan(_output: N::Output, _to: <N::Curve as Ciphersuite>::G) -> Option<Plan<N>> {
    None
  }

  /// Forward a specific output to the new multisig.
  ///
  /// Returns None if no forwarding is necessary.
  fn forward_plan<D: Db>(
    &mut self,
    _txn: &mut D::Transaction<'_>,
    _output: N::Output,
    _to: <N::Curve as Ciphersuite>::G,
  ) -> Option<Plan<N>> {
    None
  }
}
