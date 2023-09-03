use std::collections::HashMap;

use frost::curve::Ciphersuite;

use scale::{Encode, Decode};
use messages::SubstrateContext;

use serai_client::{
  primitives::{BlockHash, MAX_DATA_LEN},
  in_instructions::primitives::{
    InInstructionWithBalance, Batch, RefundableInInstruction, Shorthand, MAX_BATCH_SIZE,
  },
  tokens::primitives::{OutInstruction, OutInstructionWithBalance},
};

use log::error;

// TODO: Remove this export
pub mod scanner;
use scanner::{ScannerEvent, ScannerHandle};

mod scheduler;
// TODO: Remove this export
pub use scheduler::Scheduler;

use crate::{
  Db, Payment, Plan,
  networks::{OutputType, Output, Transaction, Block, Network},
};

pub struct MultisigViewer<N: Network> {
  key: <N::Curve as Ciphersuite>::G,
  pub scheduler: Scheduler<N>,
}

#[derive(Clone, Debug)]
pub enum MultisigEvent<N: Network> {
  // Batches to publish
  Batches(Vec<Batch>),
  // Eventuality completion found on-chain
  Completed(Vec<u8>, [u8; 32], <N::Transaction as Transaction<N>>::Id),
}

pub struct MultisigManager<D: Db, N: Network> {
  pub scanner: ScannerHandle<N, D>,
  pub existing: Option<MultisigViewer<N>>,
  pub new: Option<MultisigViewer<N>>,
}

impl<D: Db, N: Network> MultisigManager<D, N> {
  // TODO: Replace this
  pub fn new(scanner: ScannerHandle<N, D>, schedulers: HashMap<Vec<u8>, Scheduler<N>>) -> Self {
    MultisigManager {
      scanner,
      existing: Some({
        assert_eq!(schedulers.len(), 1);
        let (key, scheduler) = schedulers.into_iter().next().unwrap();
        MultisigViewer { key: N::Curve::read_G(&mut key.as_slice()).unwrap(), scheduler }
      }),
      new: None,
    }
  }

  pub async fn add_key(
    &mut self,
    txn: &mut D::Transaction<'_>,
    external_block: usize,
    external_key: <N::Curve as Ciphersuite>::G,
  ) {
    self.scanner.register_key(txn, external_block, external_key).await;
    let viewer = Some(MultisigViewer {
      key: external_key,
      scheduler: Scheduler::<N>::new::<D>(txn, external_key),
    });

    if self.existing.is_none() {
      self.existing = viewer;
      return;
    }
    self.new = viewer;
  }

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

    // TODO: Properly select existing/new multisig for these payments
    let existing_payments = payments;
    let new_payments = vec![];

    // We now have to acknowledge every block for up to the acknowledged block
    let mut block_id = <N::Block as Block<N>>::Id::default();
    block_id.as_mut().copy_from_slice(&context.network_latest_finalized_block.0);

    // TODO: Do we want a singular Plan Vec?
    let mut plans = {
      let existing = self.existing.as_mut().unwrap();
      let outputs = self.scanner.ack_up_to_block(txn, existing.key, block_id.clone()).await;
      existing.scheduler.schedule::<D>(txn, outputs, existing_payments)
    };

    plans.extend(if let Some(new) = self.new.as_mut() {
      let outputs = self.scanner.ack_up_to_block(txn, new.key, block_id).await;
      new.scheduler.schedule::<D>(txn, outputs, new_payments)
    } else {
      vec![]
    });

    plans
  }

  // TODO: Embed this into MultisigManager
  pub fn scanner_event(
    &mut self,
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

  // TODO: Handle eventuality completions
}
