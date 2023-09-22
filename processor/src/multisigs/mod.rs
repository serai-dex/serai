use core::time::Duration;
use std::collections::{VecDeque, HashMap};

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
  Signer,
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

#[derive(Clone, Debug)]
pub enum MultisigEvent<N: Network> {
  // Batches to publish
  Batches(Vec<Batch>),
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
    Vec<([u8; 32], N::SignableTransaction, N::Eventuality)>,
  ) {
    // The scanner has no long-standing orders to re-issue
    let (mut scanner, current_keys) = Scanner::new(network.clone(), raw_db.clone());

    let mut schedulers = vec![];

    let multisigs_db = MultisigsDb::<N, _>::new(raw_db.clone());

    assert!(current_keys.len() <= 2);
    let mut actively_signing = vec![];
    for (_, key) in &current_keys {
      schedulers.push(Scheduler::from_db(raw_db, *key).unwrap());

      // Load any TXs being actively signed
      let key = key.to_bytes();
      for (block_number, plan) in multisigs_db.active_plans(key.as_ref()) {
        let block_number = block_number.try_into().unwrap();

        let fee = get_fee(network, block_number).await;

        let id = plan.id();
        info!("reloading plan {}: {:?}", hex::encode(id), plan);

        let key_bytes = plan.key.to_bytes();

        let (Some((tx, eventuality)), _) = prepare_send(network, block_number, fee, plan).await
        else {
          panic!("previously created transaction is no longer being created")
        };

        scanner
          .register_eventuality(key_bytes.as_ref(), block_number, id, eventuality.clone())
          .await;
        actively_signing.push((id, tx, eventuality));
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
    if let Some(new) = self.new.as_ref() {
      if block_number < (new.activation_block + (N::CONFIRMATIONS + 1)) {
        RotationStep::UseExisting
      } else if block_number < (new.activation_block + (N::CONFIRMATIONS + 1) + N::CONFIRMATIONS) {
        RotationStep::NewAsChange
      } else {
        RotationStep::ForwardFromExisting

        // TODO: ClosingExisting ?
      }
    } else {
      RotationStep::UseExisting
    }
  }

  /// Handle a SubstrateBlock event, building the relevant Plans.
  pub async fn substrate_block(
    &mut self,
    txn: &mut D::Transaction<'_>,
    context: SubstrateContext,
    burns: Vec<OutInstructionWithBalance>,
  ) -> Vec<Plan<N>> {
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

    let mut block_id = <N::Block as Block<N>>::Id::default();
    block_id.as_mut().copy_from_slice(context.network_latest_finalized_block.as_ref());
    let block_number = ScannerHandle::<N, D>::block_number(txn, &block_id)
      .expect("SubstrateBlock with context we haven't synced");

    // Determine what step of rotation we're currently in
    let step = self.current_rotation_step(block_number);

    let mut existing_payments = vec![];
    let mut new_payments = vec![];
    match step {
      RotationStep::UseExisting | RotationStep::NewAsChange => existing_payments = payments,
      RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => {
        // Consume any payments the prior scheduler was unable to complete
        // This should only actually matter once
        new_payments = self.existing.as_mut().unwrap().scheduler.consume_payments::<D>(txn);
        // Add the new payments
        new_payments.extend(payments);
      }
    }

    // We now have to acknowledge the acknowledged block, if it's new
    let outputs = if ScannerHandle::<N, D>::db_scanned(txn)
      .expect("published a Batch despite never scanning a block") <
      block_number
    {
      self.scanner.ack_block(txn, block_id.clone()).await
    } else {
      vec![]
    };
    let outputs_len = outputs.len();

    let new_outputs = if let Some(new) = self.new.as_ref() {
      outputs.iter().filter(|output| output.key() == new.key).cloned().collect()
    } else {
      vec![]
    };
    let mut existing_outputs: Vec<_> = outputs
      .into_iter()
      .filter(|output| output.key() == self.existing.as_ref().unwrap().key)
      .collect();
    assert_eq!(existing_outputs.len() + new_outputs.len(), outputs_len);

    let mut plans = vec![];

    match step {
      RotationStep::UseExisting | RotationStep::NewAsChange => {}
      RotationStep::ForwardFromExisting => {
        // Manually create a Plan for all External outputs needing forwarding/refunding
        // Branch and Change will be handled by the below Scheduler call

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

              // Save the instruction for this output to disk
              // TODO: Don't write this to the DB. Return it, to be passed to the next function
              MultisigsDb::<N, D>::save_to_be_forwarded_output_instruction(
                txn,
                output.id(),
                instruction,
              );
            }

            false
          } else {
            true
          }
        });
      }
      RotationStep::ClosingExisting => {
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

          TODO: Make sure we don't release the Scanner lock between ack_block and
          register_eventuality.

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

        existing_outputs.retain(|output| {
          match output.kind() {
            OutputType::External => false,
            OutputType::Branch => {
              // We could simply call can_use_branch, yet it'd have an edge case where if we
              // receive two outputs for 100, and we could use one such output, we'd handle both.
              //
              // Individually schedule each output once confirming they're usable in order to
              // avoid this.
              let scheduler = &mut self.existing.as_mut().unwrap().scheduler;
              if scheduler.can_use_branch(output.amount()) {
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
      }
    }

    // TODO: Do we want a singular Plan Vec?
    plans.extend({
      let existing = self.existing.as_mut().unwrap();
      let existing_key = existing.key;
      self.existing.as_mut().unwrap().scheduler.schedule::<D>(
        txn,
        existing_outputs,
        existing_payments,
        match step {
          RotationStep::UseExisting => existing_key,
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => self.new.as_ref().unwrap().key,
        },
        match step {
          RotationStep::UseExisting | RotationStep::NewAsChange => false,
          RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => true,
        },
      )
    });
    if let Some(new) = self.new.as_mut() {
      plans.extend(new.scheduler.schedule::<D>(txn, new_outputs, new_payments, new.key, false));
    }

    for plan in &plans {
      if plan.change == Some(N::change_address(plan.key)) {
        // Assert these are only created during the expected step
        // TODO: Check when we register the Eventuality for this Plan, the step isn't
        // ForwardFromExisting nor ClosingExisting. They should appear during NewAsChange, at the
        // latest, due to the scan-ahead limit
        match step {
          RotationStep::UseExisting => {}
          RotationStep::NewAsChange |
          RotationStep::ForwardFromExisting |
          RotationStep::ClosingExisting => panic!("change was set to self despite rotating"),
        }
      }
    }

    plans
  }

  // TODO: Merge this with the above function?
  pub async fn sign_plans(
    &mut self,
    txn: &mut D::Transaction<'_>,
    network: &N,
    context: SubstrateContext,
    signers: &mut HashMap<Vec<u8>, Signer<N, D>>,
    plans: Vec<Plan<N>>,
  ) {
    let mut plans = VecDeque::from(plans);

    let mut block_hash = <N::Block as Block<N>>::Id::default();
    block_hash.as_mut().copy_from_slice(&context.network_latest_finalized_block.0);
    // block_number call is safe since it access a piece of static data
    let block_number = ScannerHandle::<N, D>::block_number(txn, &block_hash)
      .expect("told to sign_plans on a context we're not synced to");

    let fee = get_fee(network, block_number).await;

    while let Some(plan) = plans.pop_front() {
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
      let to_be_forwarded =
        MultisigsDb::<N, D>::take_to_be_forwarded_output_instruction(txn, plan.inputs[0].id());
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
        self
          .scanner
          .register_eventuality(key_bytes.as_ref(), block_number, id, eventuality.clone())
          .await;

        if let Some(signer) = signers.get_mut(key_bytes.as_ref()) {
          signer.sign_transaction(txn, id, tx, eventuality).await;
        }
      }

      // TODO: If the TX is None, should we restore its inputs to the scheduler?
    }
  }

  fn scanner_event_to_multisig_event(
    &self,
    txn: &mut D::Transaction<'_>,
    msg: ScannerEvent<N>,
  ) -> MultisigEvent<N> {
    match msg {
      ScannerEvent::Block { block, outputs } => {
        let mut block_hash = [0; 32];
        block_hash.copy_from_slice(block.as_ref());
        // TODO: Move this out from Scanner now that the Scanner no longer handles batches
        let mut batch_id = self.scanner.next_batch_id(txn);

        // start with empty batch
        let mut batches = vec![Batch {
          network: N::NETWORK,
          id: batch_id,
          block: BlockHash(block_hash),
          instructions: vec![],
        }];
        for output in outputs {
          // If these aren't externally received funds, don't handle it as an instruction
          if output.kind() != OutputType::External {
            continue;
          }

          let step = self.current_rotation_step(
            ScannerHandle::<N, D>::block_number(txn, &block)
              .expect("didn't have the block number for a block we just scanned"),
          );

          // If this is an External transaction to the existing multisig, and we're either solely
          // forwarding or closing the existing multisig, drop it
          // In the case of the forwarding case, we'll report it once it hits the new multisig
          // TODO: Delay External outputs received to new multisig earlier than expected
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
              // TODO: Refund
              continue;
            }

            if let Some(instruction) =
              MultisigsDb::<N, D>::take_forwarded_output(txn, output.amount())
            {
              instruction
            } else {
              // TODO: Refund
              continue;
            }
          };

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
        self.scanner.set_next_batch_id(txn, batch_id + 1);

        MultisigEvent::Batches(batches)
      }

      // This must be emitted before ScannerEvent::Block for all completions of known Eventualities
      // within the block. Unknown Eventualities may have their Completed events emitted after
      // ScannerEvent::Block however.
      ScannerEvent::Completed(key, id, tx) => {
        MultisigsDb::<N, D>::resolve_plan(txn, &key, id, tx.id());
        MultisigEvent::Completed(key, id, tx)
      }
    }
  }

  // async fn where dropping the Future causes no state changes
  // This property is derived from recv having this property, and recv being the only async call
  pub async fn next_event<'a>(&mut self, db: &'a mut D) -> (D::Transaction<'a>, MultisigEvent<N>) {
    let event = self.scanner.events.recv().await.unwrap();

    // No further code is async

    let mut txn = db.txn();
    let event = self.scanner_event_to_multisig_event(&mut txn, event);
    (txn, event)
  }
}
