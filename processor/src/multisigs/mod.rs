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

// TODO: Remove this export
pub mod scanner;
use scanner::{ScannerEvent, ScannerHandle};

mod scheduler;
// TODO: Remove this export
pub use scheduler::Scheduler;

use crate::{
  Db, MainDb, Payment, PostFeeBranch, Plan,
  networks::{OutputType, Output, Transaction, Block, Network, get_block},
  Signer,
};

// TODO: Remove this pub
pub async fn get_fee<N: Network>(network: &N, block_number: usize) -> N::Fee {
  // TODO2: Use an fee representative of several blocks
  get_block(network, block_number).await.median_fee()
}

// TODO: Remove this pub
pub async fn prepare_send<N: Network>(
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

  // TODO: On boot, build an index of all standing blocks -> block number
  pub async fn block_number(&self, hash: &<N::Block as Block<N>>::Id) -> Option<usize> {
    self.scanner.block_number(hash).await
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
    let block_number = self
      .scanner
      .block_number(&block_hash)
      .await
      .expect("told to sign_plans on a context we're not synced to");

    let fee = get_fee(network, block_number).await;

    while let Some(plan) = plans.pop_front() {
      let id = plan.id();
      info!("preparing plan {}: {:?}", hex::encode(id), plan);

      let key = plan.key.to_bytes();
      MainDb::<N, D>::save_signing(txn, key.as_ref(), block_number.try_into().unwrap(), &plan);
      let (tx, branches) = prepare_send(network, block_number, fee, plan).await;

      for branch in branches {
        // TODO: Properly select existing/new multisig
        self.existing.as_mut().unwrap().scheduler.created_output::<D>(
          txn,
          branch.expected,
          branch.actual,
        );
      }

      if let Some((tx, eventuality)) = tx {
        self
          .scanner
          .register_eventuality(key.as_ref(), block_number, id, eventuality.clone())
          .await;

        if let Some(signer) = signers.get_mut(key.as_ref()) {
          signer.sign_transaction(txn, id, tx, eventuality).await;
        }
      }

      // TODO: If the TX is None, should we restore its inputs to the scheduler?
    }
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
