use std::{
  io::{self, Read},
  collections::{VecDeque, HashMap},
};

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use crate::{
  networks::{OutputType, Output, Network},
  DbTxn, Db, Payment, Plan,
};

/// Stateless, deterministic output/payment manager.
#[derive(PartialEq, Eq, Debug)]
pub struct Scheduler<N: Network> {
  key: <N::Curve as Ciphersuite>::G,

  // Serai, when it has more outputs expected than it can handle in a single tranaction, will
  // schedule the outputs to be handled later. Immediately, it just creates additional outputs
  // which will eventually handle those outputs
  //
  // These maps map output amounts, which we'll receive in the future, to the payments they should
  // be used on
  //
  // When those output amounts appear, their payments should be scheduled
  // The Vec<Payment> is for all payments that should be done per output instance
  // The VecDeque allows multiple sets of payments with the same sum amount to properly co-exist
  //
  // queued_plans are for outputs which we will create, yet when created, will have their amount
  // reduced by the fee it cost to be created. The Scheduler will then be told how what amount the
  // output actually has, and it'll be moved into plans
  queued_plans: HashMap<u64, VecDeque<Vec<Payment<N>>>>,
  plans: HashMap<u64, VecDeque<Vec<Payment<N>>>>,

  // UTXOs available
  utxos: Vec<N::Output>,

  // Payments awaiting scheduling due to the output availability problem
  payments: VecDeque<Payment<N>>,
}

fn scheduler_key<D: Db, G: GroupEncoding>(key: &G) -> Vec<u8> {
  D::key(b"SCHEDULER", b"scheduler", key.to_bytes())
}

impl<N: Network> Scheduler<N> {
  fn read<R: Read>(key: <N::Curve as Ciphersuite>::G, reader: &mut R) -> io::Result<Self> {
    let mut read_plans = || -> io::Result<_> {
      let mut all_plans = HashMap::new();
      let mut all_plans_len = [0; 4];
      reader.read_exact(&mut all_plans_len)?;
      for _ in 0 .. u32::from_le_bytes(all_plans_len) {
        let mut amount = [0; 8];
        reader.read_exact(&mut amount)?;
        let amount = u64::from_le_bytes(amount);

        let mut plans = VecDeque::new();
        let mut plans_len = [0; 4];
        reader.read_exact(&mut plans_len)?;
        for _ in 0 .. u32::from_le_bytes(plans_len) {
          let mut payments = vec![];
          let mut payments_len = [0; 4];
          reader.read_exact(&mut payments_len)?;

          for _ in 0 .. u32::from_le_bytes(payments_len) {
            payments.push(Payment::read(reader)?);
          }
          plans.push_back(payments);
        }
        all_plans.insert(amount, plans);
      }
      Ok(all_plans)
    };
    let queued_plans = read_plans()?;
    let plans = read_plans()?;

    let mut utxos = vec![];
    let mut utxos_len = [0; 4];
    reader.read_exact(&mut utxos_len)?;
    for _ in 0 .. u32::from_le_bytes(utxos_len) {
      utxos.push(N::Output::read(reader)?);
    }

    let mut payments = VecDeque::new();
    let mut payments_len = [0; 4];
    reader.read_exact(&mut payments_len)?;
    for _ in 0 .. u32::from_le_bytes(payments_len) {
      payments.push_back(Payment::read(reader)?);
    }

    Ok(Scheduler { key, queued_plans, plans, utxos, payments })
  }

  // TODO2: Get rid of this
  // We reserialize the entire scheduler on any mutation to save it to the DB which is horrible
  // We should have an incremental solution
  fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(4096);

    let mut write_plans = |plans: &HashMap<u64, VecDeque<Vec<Payment<N>>>>| {
      res.extend(u32::try_from(plans.len()).unwrap().to_le_bytes());
      for (amount, list_of_plans) in plans {
        res.extend(amount.to_le_bytes());
        res.extend(u32::try_from(list_of_plans.len()).unwrap().to_le_bytes());
        for plan in list_of_plans {
          res.extend(u32::try_from(plan.len()).unwrap().to_le_bytes());
          for payment in plan {
            payment.write(&mut res).unwrap();
          }
        }
      }
    };
    write_plans(&self.queued_plans);
    write_plans(&self.plans);

    res.extend(u32::try_from(self.utxos.len()).unwrap().to_le_bytes());
    for utxo in &self.utxos {
      utxo.write(&mut res).unwrap();
    }

    res.extend(u32::try_from(self.payments.len()).unwrap().to_le_bytes());
    for payment in &self.payments {
      payment.write(&mut res).unwrap();
    }

    debug_assert_eq!(&Self::read(self.key, &mut res.as_slice()).unwrap(), self);
    res
  }

  pub fn new<D: Db>(txn: &mut D::Transaction<'_>, key: <N::Curve as Ciphersuite>::G) -> Self {
    let res = Scheduler {
      key,
      queued_plans: HashMap::new(),
      plans: HashMap::new(),
      utxos: vec![],
      payments: VecDeque::new(),
    };
    // Save it to disk so from_db won't panic if we don't mutate it before rebooting
    txn.put(scheduler_key::<D, _>(&res.key), res.serialize());
    res
  }

  pub fn from_db<D: Db>(db: &D, key: <N::Curve as Ciphersuite>::G) -> io::Result<Self> {
    let scheduler = db.get(scheduler_key::<D, _>(&key)).unwrap_or_else(|| {
      panic!("loading scheduler from DB without scheduler for {}", hex::encode(key.to_bytes()))
    });
    let mut reader_slice = scheduler.as_slice();
    let reader = &mut reader_slice;

    Self::read(key, reader)
  }

  pub fn can_use_branch(&self, amount: u64) -> bool {
    self.plans.contains_key(&amount)
  }

  fn execute(
    &mut self,
    inputs: Vec<N::Output>,
    mut payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
  ) -> Plan<N> {
    let mut change = false;
    let mut max = N::MAX_OUTPUTS;

    let payment_amounts =
      |payments: &Vec<Payment<N>>| payments.iter().map(|payment| payment.amount).sum::<u64>();

    // Requires a change output
    if inputs.iter().map(Output::amount).sum::<u64>() != payment_amounts(&payments) {
      change = true;
      max -= 1;
    }

    let mut add_plan = |payments| {
      let amount = payment_amounts(&payments);
      #[allow(clippy::unwrap_or_default)]
      self.queued_plans.entry(amount).or_insert(VecDeque::new()).push_back(payments);
      amount
    };

    let branch_address = N::branch_address(self.key);

    // If we have more payments than we can handle in a single TX, create plans for them
    // TODO2: This isn't perfect. For 258 outputs, and a MAX_OUTPUTS of 16, this will create:
    // 15 branches of 16 leaves
    // 1 branch of:
    // - 1 branch of 16 leaves
    // - 2 leaves
    // If this was perfect, the heaviest branch would have 1 branch of 3 leaves and 15 leaves
    while payments.len() > max {
      // The resulting TX will have the remaining payments and a new branch payment
      let to_remove = (payments.len() + 1) - N::MAX_OUTPUTS;
      // Don't remove more than possible
      let to_remove = to_remove.min(N::MAX_OUTPUTS);

      // Create the plan
      let removed = payments.drain((payments.len() - to_remove) ..).collect::<Vec<_>>();
      assert_eq!(removed.len(), to_remove);
      let amount = add_plan(removed);

      // Create the payment for the plan
      // Push it to the front so it's not moved into a branch until all lower-depth items are
      payments.insert(0, Payment { address: branch_address.clone(), data: None, amount });
    }

    Plan {
      key: self.key,
      inputs,
      payments,
      change: Some(N::change_address(key_for_any_change)).filter(|_| change),
    }
  }

  fn add_outputs(
    &mut self,
    mut utxos: Vec<N::Output>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
  ) -> Vec<Plan<N>> {
    log::info!("adding {} outputs", utxos.len());

    let mut txs = vec![];

    for utxo in utxos.drain(..) {
      if utxo.kind() == OutputType::Branch {
        let amount = utxo.amount();
        if let Some(plans) = self.plans.get_mut(&amount) {
          // Execute the first set of payments possible with an output of this amount
          let payments = plans.pop_front().unwrap();
          // They won't be equal if we dropped payments due to being dust
          assert!(amount >= payments.iter().map(|payment| payment.amount).sum::<u64>());

          // If we've grabbed the last plan for this output amount, remove it from the map
          if plans.is_empty() {
            self.plans.remove(&amount);
          }

          // Create a TX for these payments
          txs.push(self.execute(vec![utxo], payments, key_for_any_change));
          continue;
        }
      }

      self.utxos.push(utxo);
    }

    log::info!("{} planned TXs have had their required inputs confirmed", txs.len());
    txs
  }

  // Schedule a series of outputs/payments.
  pub fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    mut payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
    force_spend: bool,
  ) -> Vec<Plan<N>> {
    // Drop payments to our own branch address
    /*
      created_output will be called any time we send to a branch address. If it's called, and it
      wasn't expecting to be called, that's almost certainly an error. The only way to guarantee
      this however is to only have us send to a branch address when creating a branch, hence the
      dropping of pointless payments.

      This is not comprehensive as a payment may still be made to another active multisig's branch
      address, depending on timing. This is safe as the issue only occurs when a multisig sends to
      its *own* branch address, since created_output is called on the signer's Scheduler.
    */
    {
      let branch_address = N::branch_address(self.key);
      payments =
        payments.drain(..).filter(|payment| payment.address != branch_address).collect::<Vec<_>>();
    }

    let mut plans = self.add_outputs(utxos, key_for_any_change);

    log::info!("scheduling {} new payments", payments.len());

    // Add all new payments to the list of pending payments
    self.payments.extend(payments);
    let payments_at_start = self.payments.len();
    log::info!("{} payments are now scheduled", payments_at_start);

    // If we don't have UTXOs available, don't try to continue
    if self.utxos.is_empty() {
      log::info!("no utxos currently avilable");
      return plans;
    }

    // Sort UTXOs so the highest valued ones are first
    self.utxos.sort_by(|a, b| a.amount().cmp(&b.amount()).reverse());

    // We always want to aggregate our UTXOs into a single UTXO in the name of simplicity
    // We may have more UTXOs than will fit into a TX though
    // We use the most valuable UTXOs to handle our current payments, and we return aggregation TXs
    // for the rest of the inputs
    // Since we do multiple aggregation TXs at once, this will execute in logarithmic time
    let utxos = self.utxos.drain(..).collect::<Vec<_>>();
    let mut utxo_chunks =
      utxos.chunks(N::MAX_INPUTS).map(|chunk| chunk.to_vec()).collect::<Vec<_>>();

    // Use the first chunk for any scheduled payments, since it has the most value
    let utxos = utxo_chunks.remove(0);

    // If the last chunk exists and only has one output, don't try aggregating it
    // Just immediately consider it another output
    if let Some(mut chunk) = utxo_chunks.pop() {
      if chunk.len() == 1 {
        self.utxos.push(chunk.pop().unwrap());
      } else {
        utxo_chunks.push(chunk);
      }
    }

    for chunk in utxo_chunks.drain(..) {
      // TODO: While payments have their TXs' fees deducted from themselves, that doesn't hold here
      // We need to the documented, but not yet implemented, virtual amount scheme to solve this
      log::debug!("aggregating a chunk of {} inputs", N::MAX_INPUTS);
      plans.push(Plan {
        key: self.key,
        inputs: chunk,
        payments: vec![],
        change: Some(N::change_address(key_for_any_change)),
      })
    }

    // We want to use all possible UTXOs for all possible payments
    let mut balance = utxos.iter().map(Output::amount).sum::<u64>();

    // If we can't fulfill the next payment, we have encountered an instance of the UTXO
    // availability problem
    // This shows up in networks like Monero, where because we spent outputs, our change has yet to
    // re-appear. Since it has yet to re-appear, we only operate with a balance which is a subset
    // of our total balance
    // Despite this, we may be ordered to fulfill a payment which is our total balance
    // The solution is to wait for the temporarily unavailable change outputs to re-appear,
    // granting us access to our full balance
    let mut executing = vec![];
    while !self.payments.is_empty() {
      let amount = self.payments[0].amount;
      if balance.checked_sub(amount).is_some() {
        balance -= amount;
        executing.push(self.payments.pop_front().unwrap());
      } else {
        // Doesn't check if other payments would fit into the current batch as doing so may never
        // let enough inputs become simultaneously availabile to enable handling of payments[0]
        break;
      }
    }

    // Now that we have the list of payments we can successfully handle right now, create the TX
    // for them
    if !executing.is_empty() {
      plans.push(self.execute(utxos, executing, key_for_any_change));
    } else {
      // If we don't have any payments to execute, save these UTXOs for later
      self.utxos.extend(utxos);
    }

    // If we're instructed to force a spend, do so
    // This is used when an old multisig is retiring and we want to always transfer outputs to the
    // new one, regardless if we currently have payments
    if force_spend && (!self.utxos.is_empty()) {
      assert!(self.utxos.len() <= N::MAX_INPUTS);
      plans.push(Plan {
        key: self.key,
        inputs: self.utxos.drain(..).collect::<Vec<_>>(),
        payments: vec![],
        change: Some(N::change_address(key_for_any_change)),
      });
    }

    txn.put(scheduler_key::<D, _>(&self.key), self.serialize());

    log::info!(
      "created {} plans containing {} payments to sign",
      plans.len(),
      payments_at_start - self.payments.len(),
    );
    plans
  }

  pub fn consume_payments<D: Db>(&mut self, txn: &mut D::Transaction<'_>) -> Vec<Payment<N>> {
    let res: Vec<_> = self.payments.drain(..).collect();
    if !res.is_empty() {
      txn.put(scheduler_key::<D, _>(&self.key), self.serialize());
    }
    res
  }

  // Note a branch output as having been created, with the amount it was actually created with,
  // or not having been created due to being too small
  // This can be called whenever, so long as it's properly ordered
  // (it's independent to Serai/the chain we're scheduling over, yet still expects outputs to be
  // created in the same order Plans are returned in)
  pub fn created_output<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    expected: u64,
    actual: Option<u64>,
  ) {
    log::debug!("output expected to have {} had {:?} after fees", expected, actual);

    // Get the payments this output is expected to handle
    let queued = self.queued_plans.get_mut(&expected).unwrap();
    let mut payments = queued.pop_front().unwrap();
    assert_eq!(expected, payments.iter().map(|payment| payment.amount).sum::<u64>());
    // If this was the last set of payments at this amount, remove it
    if queued.is_empty() {
      self.queued_plans.remove(&expected);
    }

    // If we didn't actually create this output, return, dropping the child payments
    let actual = match actual {
      Some(actual) => actual,
      None => return,
    };

    // Amortize the fee amongst all payments
    // While some networks, like Ethereum, may have some payments take notably more gas, those
    // payments will have their own gas deducted when they're created. The difference in output
    // value present here is solely the cost of the branch, which is used for all of these
    // payments, regardless of how much they'll end up costing
    let diff = actual - expected;
    let payments_len = u64::try_from(payments.len()).unwrap();
    let per_payment = diff / payments_len;
    // The above division isn't perfect
    let mut remainder = diff - (per_payment * payments_len);

    for payment in payments.iter_mut() {
      payment.amount = payment.amount.saturating_sub(per_payment + remainder);
      // Only subtract the remainder once
      remainder = 0;
    }

    // Drop payments now below the dust threshold
    let payments =
      payments.drain(..).filter(|payment| payment.amount >= N::DUST).collect::<Vec<_>>();
    // Sanity check this was done properly
    assert!(actual >= payments.iter().map(|payment| payment.amount).sum::<u64>());
    if payments.is_empty() {
      return;
    }

    #[allow(clippy::unwrap_or_default)]
    self.plans.entry(actual).or_insert(VecDeque::new()).push_back(payments);

    // TODO2: This shows how ridiculous the serialize function is
    txn.put(scheduler_key::<D, _>(&self.key), self.serialize());
  }
}
