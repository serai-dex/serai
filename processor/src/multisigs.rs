use std::collections::HashMap;

use frost::curve::Ciphersuite;

use messages::SubstrateContext;

use serai_client::tokens::primitives::{OutInstruction, OutInstructionWithBalance};

use crate::{Db, Payment, Plan, Block, Network, ScannerHandle, Scheduler};

pub struct MultisigViewer<N: Network> {
  key: <N::Curve as Ciphersuite>::G,
  pub scheduler: Scheduler<N>,
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

  // TODO: Listen for SubstrateBlock events
  // TODO: Handle eventuality completions
}
