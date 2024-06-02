use std::io;

use ciphersuite::Ciphersuite;
pub use serai_db::*;

use scale::{Encode, Decode};
use serai_client::{primitives::Balance, in_instructions::primitives::InInstructionWithBalance};

use crate::{
  Get, Plan,
  networks::{Output, Transaction, Network},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlanFromScanning<N: Network> {
  Refund(N::Output, N::Address),
  Forward(N::Output),
}

impl<N: Network> PlanFromScanning<N> {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let output = N::Output::read(reader)?;

        let mut address_vec_len = [0; 4];
        reader.read_exact(&mut address_vec_len)?;
        let mut address_vec =
          vec![0; usize::try_from(u32::from_le_bytes(address_vec_len)).unwrap()];
        reader.read_exact(&mut address_vec)?;
        let address =
          N::Address::try_from(address_vec).map_err(|_| "invalid address saved to disk").unwrap();

        Ok(PlanFromScanning::Refund(output, address))
      }
      1 => {
        let output = N::Output::read(reader)?;
        Ok(PlanFromScanning::Forward(output))
      }
      _ => panic!("reading unrecognized PlanFromScanning"),
    }
  }
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      PlanFromScanning::Refund(output, address) => {
        writer.write_all(&[0])?;
        output.write(writer)?;

        let address_vec: Vec<u8> =
          address.clone().try_into().map_err(|_| "invalid address being refunded to").unwrap();
        writer.write_all(&u32::try_from(address_vec.len()).unwrap().to_le_bytes())?;
        writer.write_all(&address_vec)
      }
      PlanFromScanning::Forward(output) => {
        writer.write_all(&[1])?;
        output.write(writer)
      }
    }
  }
}

create_db!(
  MultisigsDb {
    NextBatchDb: () -> u32,
    PlanDb: (id: &[u8]) -> Vec<u8>,
    PlansFromScanningDb: (block_number: u64) -> Vec<u8>,
    OperatingCostsDb: () -> u64,
    ResolvedDb: (tx: &[u8]) -> [u8; 32],
    SigningDb: (key: &[u8]) -> Vec<u8>,
    ForwardedOutputDb: (balance: Balance) -> Vec<u8>,
    DelayedOutputDb: () -> Vec<u8>
  }
);

impl PlanDb {
  pub fn save_active_plan<N: Network>(
    txn: &mut impl DbTxn,
    key: &[u8],
    block_number: usize,
    plan: &Plan<N>,
    operating_costs_at_time: u64,
  ) {
    let id = plan.id();

    {
      let mut signing = SigningDb::get(txn, key).unwrap_or_default();

      // If we've already noted we're signing this, return
      assert_eq!(signing.len() % 32, 0);
      for i in 0 .. (signing.len() / 32) {
        if signing[(i * 32) .. ((i + 1) * 32)] == id {
          return;
        }
      }

      signing.extend(&id);
      SigningDb::set(txn, key, &signing);
    }

    {
      let mut buf = block_number.to_le_bytes().to_vec();
      plan.write(&mut buf).unwrap();
      buf.extend(&operating_costs_at_time.to_le_bytes());
      Self::set(txn, &id, &buf);
    }
  }

  pub fn active_plans<N: Network>(getter: &impl Get, key: &[u8]) -> Vec<(u64, Plan<N>, u64)> {
    let signing = SigningDb::get(getter, key).unwrap_or_default();
    let mut res = vec![];

    assert_eq!(signing.len() % 32, 0);
    for i in 0 .. (signing.len() / 32) {
      let id = &signing[(i * 32) .. ((i + 1) * 32)];
      let buf = Self::get(getter, id).unwrap();

      let block_number = u64::from_le_bytes(buf[.. 8].try_into().unwrap());
      let plan = Plan::<N>::read::<&[u8]>(&mut &buf[8 ..]).unwrap();
      assert_eq!(id, &plan.id());
      let operating_costs = u64::from_le_bytes(buf[(buf.len() - 8) ..].try_into().unwrap());
      res.push((block_number, plan, operating_costs));
    }
    res
  }

  pub fn plan_by_key_with_self_change<N: Network>(
    getter: &impl Get,
    key: <N::Curve as Ciphersuite>::G,
    id: [u8; 32],
  ) -> bool {
    let plan = Plan::<N>::read::<&[u8]>(&mut &Self::get(getter, &id).unwrap()[8 ..]).unwrap();
    assert_eq!(plan.id(), id);
    if let Some(change) = N::change_address(plan.key) {
      (key == plan.key) && (Some(change) == plan.change)
    } else {
      false
    }
  }
}

impl OperatingCostsDb {
  pub fn take_operating_costs(txn: &mut impl DbTxn) -> u64 {
    let existing = Self::get(txn).unwrap_or_default();
    txn.del(Self::key());
    existing
  }
  pub fn set_operating_costs(txn: &mut impl DbTxn, amount: u64) {
    if amount != 0 {
      Self::set(txn, &amount);
    }
  }
}

impl ResolvedDb {
  pub fn resolve_plan<N: Network>(
    txn: &mut impl DbTxn,
    key: &[u8],
    plan: [u8; 32],
    resolution: &<N::Transaction as Transaction<N>>::Id,
  ) {
    let mut signing = SigningDb::get(txn, key).unwrap_or_default();
    assert_eq!(signing.len() % 32, 0);

    let mut found = false;
    for i in 0 .. (signing.len() / 32) {
      let start = i * 32;
      let end = i + 32;
      if signing[start .. end] == plan {
        found = true;
        signing = [&signing[.. start], &signing[end ..]].concat();
        break;
      }
    }

    if !found {
      log::warn!("told to finish signing {} yet wasn't actively signing it", hex::encode(plan));
    }
    SigningDb::set(txn, key, &signing);
    Self::set(txn, resolution.as_ref(), &plan);
  }
}

impl PlansFromScanningDb {
  pub fn set_plans_from_scanning<N: Network>(
    txn: &mut impl DbTxn,
    block_number: usize,
    plans: Vec<PlanFromScanning<N>>,
  ) {
    let mut buf = vec![];
    for plan in plans {
      plan.write(&mut buf).unwrap();
    }
    Self::set(txn, block_number.try_into().unwrap(), &buf);
  }

  pub fn take_plans_from_scanning<N: Network>(
    txn: &mut impl DbTxn,
    block_number: usize,
  ) -> Option<Vec<PlanFromScanning<N>>> {
    let block_number = u64::try_from(block_number).unwrap();
    let res = Self::get(txn, block_number).map(|plans| {
      let mut plans_ref = plans.as_slice();
      let mut res = vec![];
      while !plans_ref.is_empty() {
        res.push(PlanFromScanning::<N>::read(&mut plans_ref).unwrap());
      }
      res
    });
    if res.is_some() {
      txn.del(Self::key(block_number));
    }
    res
  }
}

impl ForwardedOutputDb {
  pub fn save_forwarded_output(txn: &mut impl DbTxn, instruction: &InInstructionWithBalance) {
    let mut existing = Self::get(txn, instruction.balance).unwrap_or_default();
    existing.extend(instruction.encode());
    Self::set(txn, instruction.balance, &existing);
  }

  pub fn take_forwarded_output(
    txn: &mut impl DbTxn,
    balance: Balance,
  ) -> Option<InInstructionWithBalance> {
    let outputs = Self::get(txn, balance)?;
    let mut outputs_ref = outputs.as_slice();
    let res = InInstructionWithBalance::decode(&mut outputs_ref).unwrap();
    assert!(outputs_ref.len() < outputs.len());
    if outputs_ref.is_empty() {
      txn.del(Self::key(balance));
    } else {
      Self::set(txn, balance, &outputs);
    }
    Some(res)
  }
}

impl DelayedOutputDb {
  pub fn save_delayed_output(txn: &mut impl DbTxn, instruction: &InInstructionWithBalance) {
    let mut existing = Self::get(txn).unwrap_or_default();
    existing.extend(instruction.encode());
    Self::set(txn, &existing);
  }

  pub fn take_delayed_outputs(txn: &mut impl DbTxn) -> Vec<InInstructionWithBalance> {
    let Some(outputs) = Self::get(txn) else { return vec![] };
    txn.del(Self::key());

    let mut outputs_ref = outputs.as_slice();
    let mut res = vec![];
    while !outputs_ref.is_empty() {
      res.push(InInstructionWithBalance::decode(&mut outputs_ref).unwrap());
    }
    res
  }
}
