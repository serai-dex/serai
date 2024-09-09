use core::marker::PhantomData;

use serai_db::{DbTxn, Db};

use serai_coins_primitives::{OutInstruction, OutInstructionWithBalance};

use primitives::task::ContinuallyRan;
use crate::{
  db::{ScannerGlobalDb, SubstrateToEventualityDb, AcknowledgedBatches},
  report, ScannerFeed, KeyFor,
};

mod db;
use db::*;

pub(crate) fn queue_acknowledge_batch<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  batch_id: u32,
  in_instruction_succeededs: Vec<bool>,
  burns: Vec<OutInstructionWithBalance>,
  key_to_activate: Option<KeyFor<S>>,
) {
  SubstrateDb::<S>::queue_acknowledge_batch(
    txn,
    batch_id,
    in_instruction_succeededs,
    burns,
    key_to_activate,
  )
}
pub(crate) fn queue_queue_burns<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  burns: Vec<OutInstructionWithBalance>,
) {
  SubstrateDb::<S>::queue_queue_burns(txn, burns)
}

/*
  When Serai acknowledges a Batch, we can only handle it once we've scanned the chain and generated
  the same Batch ourselves. This takes the `acknowledge_batch`, `queue_burns` arguments and sits on
  them until we're able to process them.
*/
#[allow(non_snake_case)]
pub(crate) struct SubstrateTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

impl<D: Db, S: ScannerFeed> SubstrateTask<D, S> {
  pub(crate) fn new(db: D) -> Self {
    Self { db, _S: PhantomData }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for SubstrateTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut made_progress = false;
    loop {
      // Fetch the next action to handle
      let mut txn = self.db.txn();
      let Some(action) = SubstrateDb::<S>::next_action(&mut txn) else {
        drop(txn);
        return Ok(made_progress);
      };

      match action {
        Action::AcknowledgeBatch(AcknowledgeBatch {
          batch_id,
          in_instruction_succeededs,
          mut burns,
          key_to_activate,
        }) => {
          // Check if we have the information for this batch
          let Some(block_number) = report::take_block_number_for_batch::<S>(&mut txn, batch_id)
          else {
            // If we don't, drop this txn (restoring the action to the database)
            drop(txn);
            return Ok(made_progress);
          };

          {
            let external_key_for_session_to_sign_batch =
              report::take_external_key_for_session_to_sign_batch::<S>(&mut txn, batch_id).unwrap();
            AcknowledgedBatches::send(&mut txn, &external_key_for_session_to_sign_batch, batch_id);
          }

          // Mark we made progress and handle this
          made_progress = true;

          assert!(
            ScannerGlobalDb::<S>::is_block_notable(&txn, block_number),
            "acknowledging a block which wasn't notable"
          );
          if let Some(prior_highest_acknowledged_block) =
            ScannerGlobalDb::<S>::highest_acknowledged_block(&txn)
          {
            // If a single block produced multiple Batches, the block number won't increment
            assert!(
              block_number >= prior_highest_acknowledged_block,
              "acknowledging blocks out-of-order"
            );
            for b in (prior_highest_acknowledged_block + 1) .. block_number {
              assert!(
                !ScannerGlobalDb::<S>::is_block_notable(&txn, b),
                "skipped acknowledging a block which was notable"
              );
            }
          }

          ScannerGlobalDb::<S>::set_highest_acknowledged_block(&mut txn, block_number);
          if let Some(key_to_activate) = key_to_activate {
            ScannerGlobalDb::<S>::queue_key(
              &mut txn,
              block_number + S::WINDOW_LENGTH,
              key_to_activate,
            );
          }

          // Return the balances for any InInstructions which failed to execute
          {
            let return_information = report::take_return_information::<S>(&mut txn, batch_id)
              .expect("didn't save the return information for Batch we published");
            assert_eq!(
              in_instruction_succeededs.len(),
              return_information.len(),
              "amount of InInstruction succeededs differed from amount of return information saved"
            );

            // We map these into standard Burns
            for (succeeded, return_information) in
              in_instruction_succeededs.into_iter().zip(return_information)
            {
              if succeeded {
                continue;
              }

              if let Some(report::ReturnInformation { address, balance }) = return_information {
                burns.push(OutInstructionWithBalance {
                  instruction: OutInstruction { address: address.into(), data: None },
                  balance,
                });
              }
            }
          }

          // We send these Burns as stemming from this block we just acknowledged
          // This causes them to be acted on after we accumulate the outputs from this block
          SubstrateToEventualityDb::send_burns::<S>(&mut txn, block_number, burns);
        }

        Action::QueueBurns(burns) => {
          // We can instantly handle this so long as we've handled all prior actions
          made_progress = true;

          let queue_as_of = ScannerGlobalDb::<S>::highest_acknowledged_block(&txn)
            .expect("queueing Burns yet never acknowledged a block");

          SubstrateToEventualityDb::send_burns::<S>(&mut txn, queue_as_of, burns);
        }
      }

      txn.commit();
    }
  }
}
