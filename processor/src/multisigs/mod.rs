use core::time::Duration;
use std::{sync::RwLock, collections::HashMap};

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use scale::{Encode, Decode};
use messages::SubstrateContext;

use serai_client::{
  primitives::{BlockHash, MAX_DATA_LEN},
  in_instructions::primitives::{
    InInstructionWithBalance, Batch, RefundableInInstruction, Shorthand, MAX_BATCH_SIZE,
  },
  tokens::primitives::{OutInstruction, OutInstructionWithBalance},
};

use log::{info, error};

use tokio::time::sleep;

#[cfg(not(test))]
mod scanner;
#[cfg(test)]
pub mod scanner;

use scanner::{ScannerEvent, ScannerHandle, Scanner};

mod db;
use db::MultisigsDb;

#[cfg(not(test))]
mod scheduler;
#[cfg(test)]
pub mod scheduler;
use scheduler::Scheduler;

use crate::{
  Get, Db, Payment, PostFeeBranch, Plan,
  networks::{OutputType, Output, Transaction, SignableTransaction, Block, Network, get_block},
};

// InInstructionWithBalance from an external output
fn instruction_from_output<N: Network>(output: &N::Output) -> Option<InInstructionWithBalance> {
  assert_eq!(output.kind(), OutputType::External);

  let mut data = output.data();
  let max_data_len = usize::try_from(MAX_DATA_LEN).unwrap();
  if data.len() > max_data_len {
    error!(
      "data in output {} exceeded MAX_DATA_LEN ({MAX_DATA_LEN}): {}. skipping",
      hex::encode(output.id()),
      data.len(),
    );
    None?;
  }

  let Ok(shorthand) = Shorthand::decode(&mut data) else { None? };
  let Ok(instruction) = RefundableInInstruction::try_from(shorthand) else { None? };

  // TODO2: Set instruction.origin if not set (and handle refunds in general)
  Some(InInstructionWithBalance { instruction: instruction.instruction, balance: output.balance() })
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

async fn get_fee<N: Network>(network: &N, block_number: usize) -> N::Fee {
  // TODO2: Use an fee representative of several blocks
  get_block(network, block_number).await.median_fee()
}

async fn prepare_send<N: Network>(
  network: &N,
  block_number: usize,
  fee: N::Fee,
  plan: Plan<N>,
) -> (Option<(N::SignableTransaction, N::Eventuality)>, Vec<PostFeeBranch>) {
  loop {
    match network.prepare_send(block_number, plan.clone(), fee).await {
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
  scheduler: Scheduler<N>,
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub enum MultisigEvent<N: Network> {
  // Batches to publish
  Batches(Option<(<N::Curve as Ciphersuite>::G, <N::Curve as Ciphersuite>::G)>, Vec<Batch>),
  // Eventuality completion found on-chain
  Completed(Vec<u8>, [u8; 32], N::Transaction),
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
      schedulers.push(Scheduler::from_db(raw_db, *key).unwrap());

      // Load any TXs being actively signed
      let key = key.to_bytes();
      for (block_number, plan) in MultisigsDb::<N, D>::active_plans(raw_db, key.as_ref()) {
        let block_number = block_number.try_into().unwrap();

        let fee = get_fee(network, block_number).await;

        let id = plan.id();
        info!("reloading plan {}: {:?}", hex::encode(id), plan);

        let key_bytes = plan.key.to_bytes();

        let (Some((tx, eventuality)), _) =
          prepare_send(network, block_number, fee, plan.clone()).await
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
        existing: current_keys.get(0).cloned().map(|(activation_block, key)| MultisigViewer {
          activation_block,
          key,
          scheduler: schedulers.remove(0),
        }),
        new: current_keys.get(1).cloned().map(|(activation_block, key)| MultisigViewer {
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
      scheduler: Scheduler::<N>::new::<D>(txn, external_key),
    });

    if self.existing.is_none() {
      self.existing = viewer;
      return;
    }
    self.new = viewer;
  }

  fn current_rotation_step(&self, block_number: usize) -> RotationStep {
    let Some(new) = self.new.as_ref() else { return RotationStep::UseExisting };

    // Period numbering here has no meaning other than these the time values useful here, and the
    // order they're built in. They have no reference/shared marker with anything else

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
        // TODO: Add coin to payment
        payments.push(Payment {
          address,
          data: data.map(|data| data.consume()),
          amount: balance.amount.0,
        });
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

  // Manually creates Plans for all External outputs needing forwarding/refunding.
  //
  // Returns created Plans and a map of forwarded output IDs to their associated InInstructions.
  fn filter_outputs_due_to_forwarding(
    &self,
    existing_outputs: &mut Vec<N::Output>,
  ) -> (Vec<Plan<N>>, HashMap<Vec<u8>, InInstructionWithBalance>) {
    // Manually create a Plan for all External outputs needing forwarding/refunding

    /*
      Sending a Plan, with arbitrary data proxying the InInstruction, would require adding
      a flow for networks which drop their data to still embed arbitrary data. It'd also have
      edge cases causing failures.

      Instead, we save the InInstruction as we scan this output. Then, when the output is
      successfully forwarded, we simply read it from the local database. This also saves the
      costs of embedding arbitrary data.

      Since we can't rely on the Eventuality system to detect if it's a forwarded transaction,
      due to the asynchonicity of the Eventuality system, we instead interpret an External
      output with no InInstruction, which has an amount associated with an InInstruction
      being forwarded, as having been forwarded. This does create a specific edge case where
      a user who doesn't include an InInstruction may not be refunded however, if they share
      an exact amount with an expected-to-be-forwarded transaction. This is deemed acceptable.

      TODO: Add a fourth address, forwarded_address, to prevent this.
    */

    let mut plans = vec![];
    let mut forwarding = HashMap::new();
    existing_outputs.retain(|output| {
      if output.kind() == OutputType::External {
        if let Some(instruction) = instruction_from_output::<N>(output) {
          // Build a dedicated Plan forwarding this
          plans.push(Plan {
            key: self.existing.as_ref().unwrap().key,
            inputs: vec![output.clone()],
            payments: vec![],
            change: Some(N::address(self.new.as_ref().unwrap().key)),
          });

          // Set the instruction for this output to be returned
          forwarding.insert(output.id().as_ref().to_vec(), instruction);
        }

        // TODO: Refund here
        false
      } else {
        true
      }
    });
    (plans, forwarding)
  }

  // Filter newly received outputs due to the step being RotationStep::ClosingExisting.
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
        OutputType::External => false,
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
          if scheduler.can_use_branch(output.amount()) {
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
          if let Some(plan) = MultisigsDb::<N, D>::resolved_plan(txn, output.tx_id()) {
            // And the Eventuality had change...
            // We need this check as Eventualities have a race condition and can't be relied
            // on, as extensively detailed above. Eventualities explicitly with change do have
            // a safe timing window however
            if MultisigsDb::<N, D>::plan_by_key_with_self_change(
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
  ) -> (bool, Vec<Plan<N>>, HashMap<Vec<u8>, InInstructionWithBalance>) {
    let (mut existing_payments, mut new_payments) = self.burns_to_payments(txn, *step, burns);

    // We now have to acknowledge the acknowledged block, if it's new
    // It won't be if this block's `InInstruction`s were split into multiple `Batch`s
    let (acquired_lock, (mut existing_outputs, new_outputs)) = {
      let (acquired_lock, outputs) = if ScannerHandle::<N, D>::db_scanned(txn)
        .expect("published a Batch despite never scanning a block") <
        block_number
      {
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
      (acquired_lock, self.split_outputs_by_key(outputs))
    };

    let (mut plans, forwarded_external_outputs) = match *step {
      RotationStep::UseExisting | RotationStep::NewAsChange => (vec![], HashMap::new()),
      RotationStep::ForwardFromExisting => {
        self.filter_outputs_due_to_forwarding(&mut existing_outputs)
      }
      RotationStep::ClosingExisting => {
        (self.filter_outputs_due_to_closing(txn, &mut existing_outputs), HashMap::new())
      }
    };

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
      assert_eq!(plan.key, self.existing.as_ref().unwrap().key);
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

    if let Some(new) = self.new.as_mut() {
      plans.extend(new.scheduler.schedule::<D>(txn, new_outputs, new_payments, new.key, false));
    }

    (acquired_lock, plans, forwarded_external_outputs)
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
    let (acquired_lock, plans, mut forwarded_external_outputs) =
      self.plans_from_block(txn, block_number, block_id, &mut step, burns).await;

    let res = {
      let mut res = Vec::with_capacity(plans.len());
      let fee = get_fee(network, block_number).await;

      for plan in plans {
        let id = plan.id();
        info!("preparing plan {}: {:?}", hex::encode(id), plan);

        let key = plan.key;
        let key_bytes = key.to_bytes();
        MultisigsDb::<N, D>::save_active_plan(
          txn,
          key_bytes.as_ref(),
          block_number.try_into().unwrap(),
          &plan,
        );

        let to_be_forwarded = forwarded_external_outputs.remove(plan.inputs[0].id().as_ref());
        if to_be_forwarded.is_some() {
          assert_eq!(plan.inputs.len(), 1);
        }
        let (tx, branches) = prepare_send(network, block_number, fee, plan).await;

        // If this is a Plan for an output we're forwarding, we need to save the InInstruction for
        // its output under the amount successfully forwarded
        if let Some(mut instruction) = to_be_forwarded {
          // If we can't successfully create a forwarding TX, simply drop this
          if let Some(tx) = &tx {
            instruction.balance.amount.0 -= tx.0.fee();
            MultisigsDb::<N, D>::save_forwarded_output(txn, instruction);
          }
        }

        for branch in branches {
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

        // TODO: If the TX is None, restore its inputs to the scheduler
        // Otherwise, if the TX had a change output, dropping its inputs would burn funds
        // Are there exceptional cases upon rotation?
      }
      res
    };
    (acquired_lock, res)
  }

  pub async fn release_scanner_lock(&mut self) {
    self.scanner.release_lock().await;
  }

  fn scanner_event_to_multisig_event(
    &self,
    txn: &mut D::Transaction<'_>,
    msg: ScannerEvent<N>,
  ) -> MultisigEvent<N> {
    let (block_number, event) = match msg {
      ScannerEvent::Block { is_retirement_block, block, outputs } => {
        // Since the Scanner is asynchronous, the following is a concern for race conditions
        // We safely know the step of a block since keys are declared, and the Scanner is safe
        // with respect to the declaration of keys
        // Accordingly, the following calls regarding new keys and step should be safe
        let block_number = ScannerHandle::<N, D>::block_number(txn, &block)
          .expect("didn't have the block number for a block we just scanned");
        let step = self.current_rotation_step(block_number);

        let mut instructions = vec![];
        for output in outputs {
          // If these aren't externally received funds, don't handle it as an instruction
          if output.kind() != OutputType::External {
            continue;
          }

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

          let instruction = if let Some(instruction) = instruction_from_output::<N>(&output) {
            instruction
          } else {
            if !output.data().is_empty() {
              // TODO2: Refund
              continue;
            }

            if let Some(instruction) =
              MultisigsDb::<N, D>::take_forwarded_output(txn, output.amount())
            {
              instruction
            } else {
              // TODO2: Refund
              continue;
            }
          };

          // Delay External outputs received to new multisig earlier than expected
          if Some(output.key()) == self.new.as_ref().map(|new| new.key) {
            match step {
              RotationStep::UseExisting => {
                MultisigsDb::<N, D>::save_delayed_output(txn, instruction);
                continue;
              }
              RotationStep::NewAsChange |
              RotationStep::ForwardFromExisting |
              RotationStep::ClosingExisting => {}
            }
          }

          instructions.push(instruction);
        }

        // If any outputs were delayed, append them into this block
        match step {
          RotationStep::UseExisting => {}
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => {
            instructions.extend(MultisigsDb::<N, D>::take_delayed_outputs(txn));
          }
        }

        let mut block_hash = [0; 32];
        block_hash.copy_from_slice(block.as_ref());
        let mut batch_id = MultisigsDb::<N, D>::next_batch_id(txn);

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
        MultisigsDb::<N, D>::set_next_batch_id(txn, batch_id + 1);

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
      ScannerEvent::Completed(key, block_number, id, tx) => {
        MultisigsDb::<N, D>::resolve_plan(txn, &key, id, tx.id());
        (block_number, MultisigEvent::Completed(key, id, tx))
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
      MultisigsDb::<N, D>::active_plans(txn, existing.key.to_bytes().as_ref()).is_empty();

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

  // async fn where dropping the Future causes no state changes
  // This property is derived from recv having this property, and recv being the only async call
  pub async fn next_event(&mut self, txn: &RwLock<D::Transaction<'_>>) -> MultisigEvent<N> {
    let event = self.scanner.events.recv().await.unwrap();

    // No further code is async

    self.scanner_event_to_multisig_event(&mut *txn.write().unwrap(), event)
  }
}
