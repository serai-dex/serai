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

#[cfg(not(test))]
mod scheduler;
#[cfg(test)]
pub mod scheduler;
use scheduler::Scheduler;

use crate::{
  Get, Db, MainDb, Payment, PostFeeBranch, Plan,
  networks::{OutputType, Output, Transaction, Block, Network, get_block},
  Signer,
};

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
  Completed(Vec<u8>, [u8; 32], <N::Transaction as Transaction<N>>::Id),
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

    // TODO: MultisigDB
    let main_db = MainDb::<N, _>::new(raw_db.clone());

    assert!(current_keys.len() <= 2);
    let mut actively_signing = vec![];
    for (_, key) in &current_keys {
      schedulers.push(Scheduler::from_db(raw_db, *key).unwrap());

      // Load any TXs being actively signed
      let key = key.to_bytes();
      for (block_number, plan) in main_db.signing(key.as_ref()) {
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
      if block_number < (new.activation_block + N::CONFIRMATIONS) {
        RotationStep::UseExisting
      } else if block_number < (new.activation_block + (2 * N::CONFIRMATIONS)) {
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
      RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => new_payments = payments,
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
    let existing_outputs: Vec<_> = outputs
      .into_iter()
      .filter(|output| output.key() == self.existing.as_ref().unwrap().key)
      .collect();
    assert_eq!(existing_outputs.len() + new_outputs.len(), outputs_len);

    // TODO: Do we want a singular Plan Vec?
    let mut plans = {
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
      )
    };
    plans.extend(if let Some(new) = self.new.as_mut() {
      new.scheduler.schedule::<D>(txn, new_outputs, new_payments, new.key)
    } else {
      vec![]
    });

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
      MainDb::<N, D>::save_signing(
        txn,
        key_bytes.as_ref(),
        block_number.try_into().unwrap(),
        &plan,
      );
      let (tx, branches) = prepare_send(network, block_number, fee, plan).await;

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
          if (match step {
            RotationStep::UseExisting | RotationStep::NewAsChange => false,
            RotationStep::ForwardFromExisting | RotationStep::ClosingExisting => true,
          }) && (output.key() == self.existing.as_ref().unwrap().key)
          {
            continue;
          }

          let mut data = output.data();
          let max_data_len = usize::try_from(MAX_DATA_LEN).unwrap();
          // TODO: Refund if we hit one of the following continues
          if data.len() > max_data_len {
            error!(
              "data in output {} exceeded MAX_DATA_LEN ({MAX_DATA_LEN}): {}. skipping",
              hex::encode(output.id()),
              data.len(),
            );
            continue;
          }

          let Ok(shorthand) = Shorthand::decode(&mut data) else { continue };
          let Ok(instruction) = RefundableInInstruction::try_from(shorthand) else { continue };

          // TODO2: Set instruction.origin if not set (and handle refunds in general)
          let instruction = InInstructionWithBalance {
            instruction: instruction.instruction,
            balance: output.balance(),
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

      ScannerEvent::Completed(key, id, tx) => MultisigEvent::Completed(key, id, tx),
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

  // TODO: Handle eventuality completions
}
