use core::time::Duration;
use std::collections::HashSet;

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use scale::{Encode, Decode};
use messages::SubstrateContext;

use serai_client::{
  primitives::{MAX_DATA_LEN, NetworkId, Coin, ExternalAddress, BlockHash, Data},
  in_instructions::primitives::{
    InInstructionWithBalance, Batch, RefundableInInstruction, Shorthand, MAX_BATCH_SIZE,
  },
  coins::primitives::{OutInstruction, OutInstructionWithBalance},
};

use log::{info, error};

use tokio::time::sleep;

#[cfg(not(test))]
mod scanner;
#[cfg(test)]
pub mod scanner;

use scanner::{ScannerEvent, ScannerHandle, Scanner};

mod db;
use db::*;

pub(crate) mod scheduler;
use scheduler::Scheduler;

use crate::{
  Get, Db, Payment, Plan,
  networks::{OutputType, Output, SignableTransaction, Eventuality, Block, PreparedSend, Network},
};

// InInstructionWithBalance from an external output
fn instruction_from_output<N: Network>(
  output: &N::Output,
) -> (Option<ExternalAddress>, Option<InInstructionWithBalance>) {
  assert_eq!(output.kind(), OutputType::External);

  let presumed_origin = output.presumed_origin().map(|address| {
    ExternalAddress::new(
      address
        .try_into()
        .map_err(|_| ())
        .expect("presumed origin couldn't be converted to a Vec<u8>"),
    )
    .expect("presumed origin exceeded address limits")
  });

  let mut data = output.data();
  let max_data_len = usize::try_from(MAX_DATA_LEN).unwrap();
  if data.len() > max_data_len {
    error!(
      "data in output {} exceeded MAX_DATA_LEN ({MAX_DATA_LEN}): {}. skipping",
      hex::encode(output.id()),
      data.len(),
    );
    return (presumed_origin, None);
  }

  let Ok(shorthand) = Shorthand::decode(&mut data) else { return (presumed_origin, None) };
  let Ok(instruction) = RefundableInInstruction::try_from(shorthand) else {
    return (presumed_origin, None);
  };

  let mut balance = output.balance();
  // Deduct twice the cost to aggregate to prevent economic attacks by malicious miners against
  // other users
  balance.amount.0 -= 2 * N::COST_TO_AGGREGATE;

  (
    instruction.origin.or(presumed_origin),
    Some(InInstructionWithBalance { instruction: instruction.instruction, balance }),
  )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RotationStep {
  // Use the existing multisig for all actions (steps 1-3)
  UseExisting,
  // Use the new multisig as change (step 4)
  NewAsChange,
  // The existing multisig is expected to solely forward transactions at this point (step 5)
  ForwardFromExisting,
  // The existing multisig is expected to finish its own transactions and do nothing more
  // (step 6)
  ClosingExisting,
}

async fn prepare_send<N: Network>(
  network: &N,
  block_number: usize,
  plan: Plan<N>,
  operating_costs: u64,
) -> PreparedSend<N> {
  loop {
    match network.prepare_send(block_number, plan.clone(), operating_costs).await {
      Ok(prepared) => {
        return prepared;
      }
      Err(e) => {
        error!("couldn't prepare a send for plan {}: {e}", hex::encode(plan.id()));
        // The processor is either trying to create an invalid TX (fatal) or the node went
        // offline
        // The former requires a patch, the latter is a connection issue
        // If the latter, this is an appropriate sleep. If the former, we should panic, yet
        // this won't flood the console ad infinitum
        sleep(Duration::from_secs(60)).await;
      }
    }
  }
}

pub struct MultisigViewer<N: Network> {
  activation_block: usize,
  key: <N::Curve as Ciphersuite>::G,
  scheduler: N::Scheduler,
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub enum MultisigEvent<N: Network> {
  // Batches to publish
  Batches(Option<(<N::Curve as Ciphersuite>::G, <N::Curve as Ciphersuite>::G)>, Vec<Batch>),
  // Eventuality completion found on-chain
  Completed(Vec<u8>, [u8; 32], <N::Eventuality as Eventuality>::Completion),
}

pub struct MultisigManager<D: Db, N: Network> {
  scanner: ScannerHandle<N, D>,
  existing: Option<MultisigViewer<N>>,
  new: Option<MultisigViewer<N>>,
}

impl<D: Db, N: Network> MultisigManager<D, N> {
  pub async fn new(
    raw_db: &D,
    network: &N,
  ) -> (
    Self,
    Vec<<N::Curve as Ciphersuite>::G>,
    Vec<(Plan<N>, N::SignableTransaction, N::Eventuality)>,
  ) {
    // The scanner has no long-standing orders to re-issue
    let (mut scanner, current_keys) = Scanner::new(network.clone(), raw_db.clone());

    let mut schedulers = vec![];

    assert!(current_keys.len() <= 2);
    let mut actively_signing = vec![];
    for (_, key) in &current_keys {
      schedulers.push(
        N::Scheduler::from_db(
          raw_db,
          *key,
          match N::NETWORK {
            NetworkId::Serai => panic!("adding a key for Serai"),
            NetworkId::Bitcoin => Coin::Bitcoin,
            // TODO: This is incomplete to DAI
            NetworkId::Ethereum => Coin::Ether,
            NetworkId::Monero => Coin::Monero,
          },
        )
        .unwrap(),
      );

      // Load any TXs being actively signed
      let key = key.to_bytes();
      for (block_number, plan, operating_costs) in PlanDb::active_plans::<N>(raw_db, key.as_ref()) {
        let block_number = block_number.try_into().unwrap();

        let id = plan.id();
        info!("reloading plan {}: {:?}", hex::encode(id), plan);

        let key_bytes = plan.key.to_bytes();

        let Some((tx, eventuality)) =
          prepare_send(network, block_number, plan.clone(), operating_costs).await.tx
        else {
          panic!("previously created transaction is no longer being created")
        };

        scanner
          .register_eventuality(key_bytes.as_ref(), block_number, id, eventuality.clone())
          .await;
        actively_signing.push((plan, tx, eventuality));
      }
    }

    (
      MultisigManager {
        scanner,
        existing: current_keys.first().copied().map(|(activation_block, key)| MultisigViewer {
          activation_block,
          key,
          scheduler: schedulers.remove(0),
        }),
        new: current_keys.get(1).copied().map(|(activation_block, key)| MultisigViewer {
          activation_block,
          key,
          scheduler: schedulers.remove(0),
        }),
      },
      current_keys.into_iter().map(|(_, key)| key).collect(),
      actively_signing,
    )
  }

  /// Returns the block number for a block hash, if it's known and all keys have scanned the block.
  // This is guaranteed to atomically increment so long as no new keys are added to the scanner
  // which activate at a block before the currently highest scanned block. This is prevented by
  // the processor waiting for `Batch` inclusion before scanning too far ahead, and activation only
  // happening after the "too far ahead" window.
  pub async fn block_number<G: Get>(
    &self,
    getter: &G,
    hash: &<N::Block as Block<N>>::Id,
  ) -> Option<usize> {
    let latest = ScannerHandle::<N, D>::block_number(getter, hash)?;

    // While the scanner has cemented this block, that doesn't mean it's been scanned for all
    // keys
    // ram_scanned will return the lowest scanned block number out of all keys
    if latest > self.scanner.ram_scanned().await {
      return None;
    }
    Some(latest)
  }

  pub async fn add_key(
    &mut self,
    txn: &mut D::Transaction<'_>,
    activation_block: usize,
    external_key: <N::Curve as Ciphersuite>::G,
  ) {
    self.scanner.register_key(txn, activation_block, external_key).await;
    let viewer = Some(MultisigViewer {
      activation_block,
      key: external_key,
      scheduler: N::Scheduler::new::<D>(
        txn,
        external_key,
        match N::NETWORK {
          NetworkId::Serai => panic!("adding a key for Serai"),
          NetworkId::Bitcoin => Coin::Bitcoin,
          // TODO: This is incomplete to DAI
          NetworkId::Ethereum => Coin::Ether,
          NetworkId::Monero => Coin::Monero,
        },
      ),
    });

    if self.existing.is_none() {
      self.existing = viewer;
      return;
    }
    self.new = viewer;
  }

  fn current_rotation_step(&self, block_number: usize) -> RotationStep {
    let Some(new) = self.new.as_ref() else { return RotationStep::UseExisting };

    // Period numbering here has no meaning other than these are the time values useful here, and
    // the order they're calculated in. They have no reference/shared marker with anything else

    // ESTIMATED_BLOCK_TIME_IN_SECONDS is fine to use here. While inaccurate, it shouldn't be
    // drastically off, and even if it is, it's a hiccup to latency handling only possible when
    // rotating. The error rate wouldn't be acceptable if it was allowed to accumulate over time,
    // yet rotation occurs on Serai's clock, disconnecting any errors here from any prior.

    // N::CONFIRMATIONS + 10 minutes
    let period_1_start = new.activation_block +
      N::CONFIRMATIONS +
      (10usize * 60).div_ceil(N::ESTIMATED_BLOCK_TIME_IN_SECONDS);

    // N::CONFIRMATIONS
    let period_2_start = period_1_start + N::CONFIRMATIONS;

    // 6 hours after period 2
    // Also ensure 6 hours is greater than the amount of CONFIRMATIONS, for sanity purposes
    let period_3_start =
      period_2_start + ((6 * 60 * 60) / N::ESTIMATED_BLOCK_TIME_IN_SECONDS).max(N::CONFIRMATIONS);

    if block_number < period_1_start {
      RotationStep::UseExisting
    } else if block_number < period_2_start {
      RotationStep::NewAsChange
    } else if block_number < period_3_start {
      RotationStep::ForwardFromExisting
    } else {
      RotationStep::ClosingExisting
    }
  }

  // Convert new Burns to Payments.
  //
  // Also moves payments from the old Scheduler to the new multisig if the step calls for it.
  fn burns_to_payments(
    &mut self,
    txn: &mut D::Transaction<'_>,
    step: RotationStep,
    burns: Vec<OutInstructionWithBalance>,
  ) -> (Vec<Payment<N>>, Vec<Payment<N>>) {
    let mut payments = vec![];
    for out in burns {
      let OutInstructionWithBalance { instruction: OutInstruction { address, data }, balance } =
        out;
      assert_eq!(balance.coin.network(), N::NETWORK);

      if let Ok(address) = N::Address::try_from(address.consume()) {
        payments.push(Payment { address, data: data.map(Data::consume), balance });
      }
    }

    let payments = payments;
    match step {
      RotationStep::UseExisting | RotationStep::NewAsChange => (payments, vec![]),
      RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => {
        // Consume any payments the prior scheduler was unable to complete
        // This should only actually matter once
        let mut new_payments = self.existing.as_mut().unwrap().scheduler.consume_payments::<D>(txn);
        // Add the new payments
        new_payments.extend(payments);
        (vec![], new_payments)
      }
    }
  }

  fn split_outputs_by_key(&self, outputs: Vec<N::Output>) -> (Vec<N::Output>, Vec<N::Output>) {
    let mut existing_outputs = Vec::with_capacity(outputs.len());
    let mut new_outputs = vec![];

    let existing_key = self.existing.as_ref().unwrap().key;
    let new_key = self.new.as_ref().map(|new| new.key);
    for output in outputs {
      if output.key() == existing_key {
        existing_outputs.push(output);
      } else {
        assert_eq!(Some(output.key()), new_key);
        new_outputs.push(output);
      }
    }

    (existing_outputs, new_outputs)
  }

  fn refund_plan(output: N::Output, refund_to: N::Address) -> Plan<N> {
    log::info!("creating refund plan for {}", hex::encode(output.id()));
    assert_eq!(output.kind(), OutputType::External);
    Plan {
      key: output.key(),
      // Uses a payment as this will still be successfully sent due to fee amortization,
      // and because change is currently always a Serai key
      payments: vec![Payment { address: refund_to, data: None, balance: output.balance() }],
      inputs: vec![output],
      change: None,
    }
  }

  fn forward_plan(&self, output: N::Output) -> Plan<N> {
    log::info!("creating forwarding plan for {}", hex::encode(output.id()));

    /*
      Sending a Plan, with arbitrary data proxying the InInstruction, would require adding
      a flow for networks which drop their data to still embed arbitrary data. It'd also have
      edge cases causing failures (we'd need to manually provide the origin if it was implied,
      which may exceed the encoding limit).

      Instead, we save the InInstruction as we scan this output. Then, when the output is
      successfully forwarded, we simply read it from the local database. This also saves the
      costs of embedding arbitrary data.

      Since we can't rely on the Eventuality system to detect if it's a forwarded transaction,
      due to the asynchonicity of the Eventuality system, we instead interpret an Forwarded
      output which has an amount associated with an InInstruction which was forwarded as having
      been forwarded.
    */

    Plan {
      key: self.existing.as_ref().unwrap().key,
      payments: vec![Payment {
        address: N::forward_address(self.new.as_ref().unwrap().key),
        data: None,
        balance: output.balance(),
      }],
      inputs: vec![output],
      change: None,
    }
  }

  // Filter newly received outputs due to the step being RotationStep::ClosingExisting.
  //
  // Returns the Plans for the `Branch`s which should be created off outputs which passed the
  // filter.
  fn filter_outputs_due_to_closing(
    &mut self,
    txn: &mut D::Transaction<'_>,
    existing_outputs: &mut Vec<N::Output>,
  ) -> Vec<Plan<N>> {
    /*
      The document says to only handle outputs we created. We don't know what outputs we
      created. We do have an ordered view of equivalent outputs however, and can assume the
      first (and likely only) ones are the ones we created.

      Accordingly, only handling outputs we created should be definable as only handling
      outputs from the resolution of Eventualities.

      This isn't feasible. It requires knowing what Eventualities were completed in this block,
      when we handle this block, which we don't know without fully serialized scanning + Batch
      publication.

      Take the following scenario:
      1) A network uses 10 confirmations. Block x is scanned, meaning x+9a exists.
      2) 67% of nodes process x, create, sign, and publish a TX, creating an Eventuality.
      3) A reorganization to a shorter chain occurs, including the published TX in x+1b.
      4) The 33% of nodes which are latent will be allowed to scan x+1b as soon as x+10b
         exists. They won't wait for Serai to include the Batch for x until they try to scan
         x+10b.
      5) These latent nodes will handle x+1b, post-create an Eventuality, post-learn x+1b
         contained resolutions, changing how x+1b should've been interpreted.

      We either have to:
      A) Fully serialize scanning (removing the ability to utilize throughput to allow higher
         latency, at least while the step is `ClosingExisting`).
      B) Create Eventualities immediately, which we can't do as then both the external
         network's clock AND Serai's clock can trigger Eventualities, removing ordering.
         We'd need to shift entirely to the external network's clock, only handling Burns
         outside the parallelization window (which would be extremely latent).
      C) Use a different mechanism to determine if we created an output.
      D) Re-define which outputs are still to be handled after the 6 hour period expires, such
         that the multisig's lifetime cannot be further extended yet it does fulfill its
         responsibility.

      External outputs to the existing multisig will be:
      - Scanned before the rotation and unused (as used External outputs become Change)
      - Forwarded immediately upon scanning
      - Not scanned before the cut off time (and accordingly dropped)

      For the first case, since they're scanned before the rotation and unused, they'll be
      forwarded with all other available outputs (since they'll be available when scanned).

      Change outputs will be:
      - Scanned before the rotation and forwarded with all other available outputs
      - Forwarded immediately upon scanning
      - Not scanned before the cut off time, requiring an extension exclusive to these outputs

      The important thing to note about honest Change outputs to the existing multisig is that
      they'll only be created within `CONFIRMATIONS+1` blocks of the activation block. Also
      important to note is that there's another explicit window of `CONFIRMATIONS` before the
      6 hour window.

      Eventualities are not guaranteed to be known before we scan the block containing their
      resolution. They are guaranteed to be known within `CONFIRMATIONS-1` blocks however, due
      to the limitation on how far we'll scan ahead.

      This means we will know of all Eventualities related to Change outputs we need to forward
      before the 6 hour period begins (as forwarding outputs will not create any Change outputs
      to the existing multisig).

      This means a definition of complete can be defined as:
      1) Handled all Branch outputs
      2) Forwarded all External outputs received before the end of 6 hour window
      3) Forwarded the results of all Eventualities with Change, which will have been created
         before the 6 hour window

      How can we track and ensure this without needing to check if an output is from the
      resolution of an Eventuality?

      1) We only create Branch outputs before the 6 hour window starts. These are guaranteed
         to appear within `CONFIRMATIONS` blocks. They will exist with arbitrary depth however,
         meaning that upon completion they will spawn several more Eventualities. The further
         created Eventualities re-risk being present after the 6 hour period ends.

         We can:
         1) Build a queue for Branch outputs, delaying their handling until relevant
            Eventualities are guaranteed to be present.

            This solution would theoretically work for all outputs and allow collapsing this
            problem to simply:

            > Accordingly, only handling outputs we created should be definable as only
              handling outputs from the resolution of Eventualities.

         2) Create all Eventualities under a Branch at time of Branch creation.
            This idea fails as Plans are tightly bound to outputs.

         3) Don't track Branch outputs by Eventualities, yet by the amount of Branch outputs
            remaining. Any Branch output received, of a useful amount, is assumed to be our
            own and handled. All other Branch outputs, even if they're the completion of some
            Eventuality, are dropped.

            This avoids needing any additional queue, avoiding additional pipelining/latency.

      2) External outputs are self-evident. We simply stop handling them at the cut-off point,
         and only start checking after `CONFIRMATIONS` blocks if all Eventualities are
         complete.

      3) Since all Change Eventualities will be known prior to the 6 hour window's beginning,
         we can safely check if a received Change output is the resolution of an Eventuality.
         We only need to forward it if so. Forwarding it simply requires only checking if
         Eventualities are complete after `CONFIRMATIONS` blocks, same as for straggling
         External outputs.
    */

    let mut plans = vec![];
    existing_outputs.retain(|output| {
      match output.kind() {
        OutputType::External | OutputType::Forwarded => false,
        OutputType::Branch => {
          let scheduler = &mut self.existing.as_mut().unwrap().scheduler;
          // There *would* be a race condition here due to the fact we only mark a `Branch` output
          // as needed when we process the block (and handle scheduling), yet actual `Branch`
          // outputs may appear as soon as the next block (and we scan the next block before we
          // process the prior block)
          //
          // Unlike Eventuality checking, which happens on scanning and is therefore asynchronous,
          // all scheduling (and this check against the scheduler) happens on processing, which is
          // synchronous
          //
          // While we could move Eventuality checking into the block processing, removing its
          // asynchonicity, we could only check data the Scanner deems important. The Scanner won't
          // deem important Eventuality resolutions which don't create an output to Serai unless
          // it knows of the Eventuality. Accordingly, at best we could have a split role (the
          // Scanner noting completion of Eventualities which don't have relevant outputs, the
          // processing noting completion of ones which do)
          //
          // This is unnecessary, due to the current flow around Eventuality resolutions and the
          // current bounds naturally found being sufficiently amenable, yet notable for the future
          if scheduler.can_use_branch(output.balance()) {
            // We could simply call can_use_branch, yet it'd have an edge case where if we receive
            // two outputs for 100, and we could use one such output, we'd handle both.
            //
            // Individually schedule each output once confirming they're usable in order to avoid
            // this.
            let mut plan = scheduler.schedule::<D>(
              txn,
              vec![output.clone()],
              vec![],
              self.new.as_ref().unwrap().key,
              false,
            );
            assert_eq!(plan.len(), 1);
            let plan = plan.remove(0);
            plans.push(plan);
          }
          false
        }
        OutputType::Change => {
          // If the TX containing this output resolved an Eventuality...
          if let Some(plan) = ResolvedDb::get(txn, output.tx_id().as_ref()) {
            // And the Eventuality had change...
            // We need this check as Eventualities have a race condition and can't be relied
            // on, as extensively detailed above. Eventualities explicitly with change do have
            // a safe timing window however
            if PlanDb::plan_by_key_with_self_change::<N>(
              txn,
              // Pass the key so the DB checks the Plan's key is this multisig's, preventing a
              // potential issue where the new multisig creates a Plan with change *and a
              // payment to the existing multisig's change address*
              self.existing.as_ref().unwrap().key,
              plan,
            ) {
              // Then this is an honest change output we need to forward
              // (or it's a payment to the change address in the same transaction as an honest
              // change output, which is fine to let slip in)
              return true;
            }
          }
          false
        }
      }
    });
    plans
  }

  // Returns the Plans caused from a block being acknowledged.
  //
  // Will rotate keys if the block acknowledged is the retirement block.
  async fn plans_from_block(
    &mut self,
    txn: &mut D::Transaction<'_>,
    block_number: usize,
    block_id: <N::Block as Block<N>>::Id,
    step: &mut RotationStep,
    burns: Vec<OutInstructionWithBalance>,
  ) -> (bool, Vec<Plan<N>>, HashSet<[u8; 32]>) {
    let (mut existing_payments, mut new_payments) = self.burns_to_payments(txn, *step, burns);

    let mut plans = vec![];
    let mut plans_from_scanning = HashSet::new();

    // We now have to acknowledge the acknowledged block, if it's new
    // It won't be if this block's `InInstruction`s were split into multiple `Batch`s
    let (acquired_lock, (mut existing_outputs, new_outputs)) = {
      let (acquired_lock, mut outputs) = if ScannerHandle::<N, D>::db_scanned(txn)
        .expect("published a Batch despite never scanning a block") <
        block_number
      {
        // Load plans crated when we scanned the block
        plans = PlansFromScanningDb::take_plans_from_scanning::<N>(txn, block_number).unwrap();
        for plan in &plans {
          plans_from_scanning.insert(plan.id());
        }

        let (is_retirement_block, outputs) = self.scanner.ack_block(txn, block_id.clone()).await;
        if is_retirement_block {
          let existing = self.existing.take().unwrap();
          assert!(existing.scheduler.empty());
          self.existing = self.new.take();
          *step = RotationStep::UseExisting;
          assert!(existing_payments.is_empty());
          existing_payments = new_payments;
          new_payments = vec![];
        }
        (true, outputs)
      } else {
        (false, vec![])
      };

      // Remove all outputs already present in plans
      let mut output_set = HashSet::new();
      for plan in &plans {
        for input in &plan.inputs {
          output_set.insert(input.id().as_ref().to_vec());
        }
      }
      outputs.retain(|output| !output_set.remove(output.id().as_ref()));
      assert_eq!(output_set.len(), 0);

      (acquired_lock, self.split_outputs_by_key(outputs))
    };

    // If we're closing the existing multisig, filter its outputs down
    if *step == RotationStep::ClosingExisting {
      plans.extend(self.filter_outputs_due_to_closing(txn, &mut existing_outputs));
    }

    // Now that we've done all our filtering, schedule the existing multisig's outputs
    plans.extend({
      let existing = self.existing.as_mut().unwrap();
      let existing_key = existing.key;
      self.existing.as_mut().unwrap().scheduler.schedule::<D>(
        txn,
        existing_outputs,
        existing_payments,
        match *step {
          RotationStep::UseExisting => existing_key,
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => self.new.as_ref().unwrap().key,
        },
        match *step {
          RotationStep::UseExisting | RotationStep::NewAsChange => false,
          RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => true,
        },
      )
    });

    for plan in &plans {
      if plan.change == Some(N::change_address(plan.key)) {
        // Assert these are only created during the expected step
        match *step {
          RotationStep::UseExisting => {}
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => panic!("change was set to self despite rotating"),
        }
      }
    }

    // Schedule the new multisig's outputs too
    if let Some(new) = self.new.as_mut() {
      plans.extend(new.scheduler.schedule::<D>(txn, new_outputs, new_payments, new.key, false));
    }

    (acquired_lock, plans, plans_from_scanning)
  }

  /// Handle a SubstrateBlock event, building the relevant Plans.
  pub async fn substrate_block(
    &mut self,
    txn: &mut D::Transaction<'_>,
    network: &N,
    context: SubstrateContext,
    burns: Vec<OutInstructionWithBalance>,
  ) -> (bool, Vec<(<N::Curve as Ciphersuite>::G, [u8; 32], N::SignableTransaction, N::Eventuality)>)
  {
    let mut block_id = <N::Block as Block<N>>::Id::default();
    block_id.as_mut().copy_from_slice(context.network_latest_finalized_block.as_ref());
    let block_number = ScannerHandle::<N, D>::block_number(txn, &block_id)
      .expect("SubstrateBlock with context we haven't synced");

    // Determine what step of rotation we're currently in
    let mut step = self.current_rotation_step(block_number);

    // Get the Plans from this block
    let (acquired_lock, plans, plans_from_scanning) =
      self.plans_from_block(txn, block_number, block_id, &mut step, burns).await;

    let res = {
      let mut res = Vec::with_capacity(plans.len());

      for plan in plans {
        let id = plan.id();
        info!("preparing plan {}: {:?}", hex::encode(id), plan);

        let key = plan.key;
        let key_bytes = key.to_bytes();

        let (tx, post_fee_branches) = {
          let running_operating_costs = OperatingCostsDb::take_operating_costs(txn);

          PlanDb::save_active_plan::<N>(
            txn,
            key_bytes.as_ref(),
            block_number,
            &plan,
            running_operating_costs,
          );

          // If this Plan is from the scanner handler below, don't take the opportunity to amortze
          // operating costs
          // It operates with limited context, and on a different clock, making it nable to react
          // to operating costs
          // Despite this, in order to properly save forwarded outputs' instructions, it needs to
          // know the actual value forwarded outputs will be created with
          // Including operating costs prevents that
          let from_scanning = plans_from_scanning.contains(&plan.id());
          let to_use_operating_costs = if from_scanning { 0 } else { running_operating_costs };

          let PreparedSend { tx, post_fee_branches, mut operating_costs } =
            prepare_send(network, block_number, plan, to_use_operating_costs).await;

          // Restore running_operating_costs to operating_costs
          if from_scanning {
            // If we're forwarding (or refunding) this output, operating_costs should still be 0
            // Either this TX wasn't created, causing no operating costs, or it was yet it'd be
            // amortized
            assert_eq!(operating_costs, 0);

            operating_costs += running_operating_costs;
          }

          OperatingCostsDb::set_operating_costs(txn, operating_costs);

          (tx, post_fee_branches)
        };

        for branch in post_fee_branches {
          let existing = self.existing.as_mut().unwrap();
          let to_use = if key == existing.key {
            existing
          } else {
            let new = self
              .new
              .as_mut()
              .expect("plan wasn't for existing multisig yet there wasn't a new multisig");
            assert_eq!(key, new.key);
            new
          };

          to_use.scheduler.created_output::<D>(txn, branch.expected, branch.actual);
        }

        if let Some((tx, eventuality)) = tx {
          // The main function we return to will send an event to the coordinator which must be
          // fired before these registered Eventualities have their Completions fired
          // Safety is derived from a mutable lock on the Scanner being preserved, preventing
          // scanning (and detection of Eventuality resolutions) before it's released
          // It's only released by the main function after it does what it will
          self
            .scanner
            .register_eventuality(key_bytes.as_ref(), block_number, id, eventuality.clone())
            .await;

          res.push((key, id, tx, eventuality));
        }

        // TODO: If the TX is None, restore its inputs to the scheduler for efficiency's sake
        // If this TODO is removed, also reduce the operating costs
      }
      res
    };
    (acquired_lock, res)
  }

  pub async fn release_scanner_lock(&mut self) {
    self.scanner.release_lock().await;
  }

  pub async fn scanner_event_to_multisig_event(
    &self,
    txn: &mut D::Transaction<'_>,
    network: &N,
    msg: ScannerEvent<N>,
  ) -> MultisigEvent<N> {
    let (block_number, event) = match msg {
      ScannerEvent::Block { is_retirement_block, block, mut outputs } => {
        // Since the Scanner is asynchronous, the following is a concern for race conditions
        // We safely know the step of a block since keys are declared, and the Scanner is safe
        // with respect to the declaration of keys
        // Accordingly, the following calls regarding new keys and step should be safe
        let block_number = ScannerHandle::<N, D>::block_number(txn, &block)
          .expect("didn't have the block number for a block we just scanned");
        let step = self.current_rotation_step(block_number);

        // Instructions created from this block
        let mut instructions = vec![];

        // If any of these outputs were forwarded, create their instruction now
        for output in &outputs {
          if output.kind() != OutputType::Forwarded {
            continue;
          }

          if let Some(instruction) = ForwardedOutputDb::take_forwarded_output(txn, output.balance())
          {
            instructions.push(instruction);
          }
        }

        // If the remaining outputs aren't externally received funds, don't handle them as
        // instructions
        outputs.retain(|output| output.kind() == OutputType::External);

        // These plans are of limited context. They're only allowed the outputs newly received
        // within this block and are intended to handle forwarding transactions/refunds
        let mut plans = vec![];

        // If the old multisig is explicitly only supposed to forward, create all such plans now
        if step == RotationStep::ForwardFromExisting {
          let mut i = 0;
          while i < outputs.len() {
            let output = &outputs[i];
            let plans = &mut plans;
            let txn = &mut *txn;

            #[allow(clippy::redundant_closure_call)]
            let should_retain = (|| async move {
              // If this output doesn't belong to the existing multisig, it shouldn't be forwarded
              if output.key() != self.existing.as_ref().unwrap().key {
                return true;
              }

              let plans_at_start = plans.len();
              let (refund_to, instruction) = instruction_from_output::<N>(output);
              if let Some(mut instruction) = instruction {
                // Build a dedicated Plan forwarding this
                let forward_plan = self.forward_plan(output.clone());
                plans.push(forward_plan.clone());

                // Set the instruction for this output to be returned
                // We need to set it under the amount it's forwarded with, so prepare its forwarding
                // TX to determine the fees involved
                let PreparedSend { tx, post_fee_branches: _, operating_costs } =
                  prepare_send(network, block_number, forward_plan, 0).await;
                // operating_costs should not increase in a forwarding TX
                assert_eq!(operating_costs, 0);

                // If this actually forwarded any coins, save the output as forwarded
                // If this didn't create a TX, we don't bother saving the output as forwarded
                // The fact we already created and pushed a plan still using this output will cause
                // it to not be retained here, and later the plan will be dropped as this did here,
                // letting it die out
                if let Some(tx) = &tx {
                  instruction.balance.amount.0 -= tx.0.fee();
                  ForwardedOutputDb::save_forwarded_output(txn, &instruction);
                }
              } else if let Some(refund_to) = refund_to {
                if let Ok(refund_to) = refund_to.consume().try_into() {
                  // Build a dedicated Plan refunding this
                  plans.push(Self::refund_plan(output.clone(), refund_to));
                }
              }

              // Only keep if we didn't make a Plan consuming it
              plans_at_start == plans.len()
            })()
            .await;
            if should_retain {
              i += 1;
              continue;
            }
            outputs.remove(i);
          }
        }

        for output in outputs {
          // If this is an External transaction to the existing multisig, and we're either solely
          // forwarding or closing the existing multisig, drop it
          // In the case of the forwarding case, we'll report it once it hits the new multisig
          if (match step {
            RotationStep::UseExisting | RotationStep::NewAsChange => false,
            RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => true,
          }) && (output.key() == self.existing.as_ref().unwrap().key)
          {
            continue;
          }

          let (refund_to, instruction) = instruction_from_output::<N>(&output);
          let Some(instruction) = instruction else {
            if let Some(refund_to) = refund_to {
              if let Ok(refund_to) = refund_to.consume().try_into() {
                plans.push(Self::refund_plan(output.clone(), refund_to));
              }
            }
            continue;
          };

          // Delay External outputs received to new multisig earlier than expected
          if Some(output.key()) == self.new.as_ref().map(|new| new.key) {
            match step {
              RotationStep::UseExisting => {
                DelayedOutputDb::save_delayed_output(txn, &instruction);
                continue;
              }
              RotationStep::NewAsChange |
              RotationStep::ForwardFromExisting |
              RotationStep::ClosingExisting => {}
            }
          }

          instructions.push(instruction);
        }

        // Save the plans created while scanning
        // TODO: Should we combine all of these plans to reduce the fees incurred from their
        // execution? They're refunds and forwards. Neither should need isolate Plan/Eventualities.
        PlansFromScanningDb::set_plans_from_scanning(txn, block_number, plans);

        // If any outputs were delayed, append them into this block
        match step {
          RotationStep::UseExisting => {}
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => {
            instructions.extend(DelayedOutputDb::take_delayed_outputs(txn));
          }
        }

        let mut block_hash = [0; 32];
        block_hash.copy_from_slice(block.as_ref());
        let mut batch_id = NextBatchDb::get(txn).unwrap_or_default();

        // start with empty batch
        let mut batches = vec![Batch {
          network: N::NETWORK,
          id: batch_id,
          block: BlockHash(block_hash),
          instructions: vec![],
        }];

        for instruction in instructions {
          let batch = batches.last_mut().unwrap();
          batch.instructions.push(instruction);

          // check if batch is over-size
          if batch.encode().len() > MAX_BATCH_SIZE {
            // pop the last instruction so it's back in size
            let instruction = batch.instructions.pop().unwrap();

            // bump the id for the new batch
            batch_id += 1;

            // make a new batch with this instruction included
            batches.push(Batch {
              network: N::NETWORK,
              id: batch_id,
              block: BlockHash(block_hash),
              instructions: vec![instruction],
            });
          }
        }

        // Save the next batch ID
        NextBatchDb::set(txn, &(batch_id + 1));

        (
          block_number,
          MultisigEvent::Batches(
            if is_retirement_block {
              Some((self.existing.as_ref().unwrap().key, self.new.as_ref().unwrap().key))
            } else {
              None
            },
            batches,
          ),
        )
      }

      // This must be emitted before ScannerEvent::Block for all completions of known Eventualities
      // within the block. Unknown Eventualities may have their Completed events emitted after
      // ScannerEvent::Block however.
      ScannerEvent::Completed(key, block_number, id, tx_id, completion) => {
        ResolvedDb::resolve_plan::<N>(txn, &key, id, &tx_id);
        (block_number, MultisigEvent::Completed(key, id, completion))
      }
    };

    // If we either received a Block event (which will be the trigger when we have no
    // Plans/Eventualities leading into ClosingExisting), or we received the last Completed for
    // this multisig, set its retirement block
    let existing = self.existing.as_ref().unwrap();

    // This multisig is closing
    let closing = self.current_rotation_step(block_number) == RotationStep::ClosingExisting;
    // There's nothing left in its Scheduler. This call is safe as:
    // 1) When ClosingExisting, all outputs should've been already forwarded, preventing
    //    new UTXOs from accumulating.
    // 2) No new payments should be issued.
    // 3) While there may be plans, they'll be dropped to create Eventualities.
    //    If this Eventuality is resolved, the Plan has already been dropped.
    // 4) If this Eventuality will trigger a Plan, it'll still be in the plans HashMap.
    let scheduler_is_empty = closing && existing.scheduler.empty();
    // Nothing is still being signed
    let no_active_plans = scheduler_is_empty &&
      PlanDb::active_plans::<N>(txn, existing.key.to_bytes().as_ref()).is_empty();

    self
      .scanner
      .multisig_completed
      // The above explicitly included their predecessor to ensure short-circuiting, yet their
      // names aren't defined as an aggregate check. Still including all three here ensures all are
      // used in the final value
      .send(closing && scheduler_is_empty && no_active_plans)
      .unwrap();

    event
  }

  pub async fn next_scanner_event(&mut self) -> ScannerEvent<N> {
    self.scanner.events.recv().await.unwrap()
  }
}
