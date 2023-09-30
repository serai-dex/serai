use core::future::Future;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use serai_client::{validator_sets::primitives::ValidatorSet, subxt::utils::Encoded};

use tributary::{
  Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, decode_evidence},
    TendermintNetwork,
  },
  TransactionKind,
};

use serai_db::DbTxn;

use crate::{
  Db,
  tributary::handle::handle_application_tx,
  processors::Processors,
  tributary::{TributaryDb, TributarySpec, Transaction},
  P2p,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecognizedIdType {
  Batch,
  Plan,
}

// Handle a specific Tributary block
#[allow(clippy::needless_pass_by_ref_mut)] // False positive?
async fn handle_block<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = ()>,
  RID: crate::RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  block: Block<Transaction>,
) {
  log::info!("found block for Tributary {:?}", spec.set());

  let genesis = spec.genesis();
  let hash = block.hash();

  let mut event_id = 0;
  #[allow(clippy::explicit_counter_loop)] // event_id isn't TX index. It just currently lines up
  for tx in block.transactions {
    if TributaryDb::<D>::handled_event(&db.0, hash, event_id) {
      event_id += 1;
      continue;
    }

    let mut txn = db.0.txn();

    match tx {
      TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
        // Since the evidence is on the chain, it should already have been validated
        // We can just punish the signer
        let msgs = decode_evidence::<TendermintNetwork<D, Transaction, P>>(&ev).unwrap();

        // Since anything with evidence is fundamentally faulty behavior, not just temporal errors,
        // mark the node as fatally slashed
        TributaryDb::<D>::set_fatally_slashed(&mut txn, genesis, msgs.0.msg.sender);

        // TODO2: disconnect the node from network/ban from further participation in Tributary
      }
      TributaryTransaction::Application(tx) => {
        handle_application_tx::<D, _, _, _, _, _>(
          tx,
          spec,
          processors,
          publish_serai_tx.clone(),
          key,
          recognized_id.clone(),
          &mut txn,
        )
        .await;
      }
    }

    TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
    txn.commit();

    event_id += 1;
  }

  // TODO2: Trigger any necessary re-attempts
}

pub(crate) async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = ()>,
  RID: crate::RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = db.last_block(genesis);
  while let Some(next) = tributary.block_after(&last_block) {
    let block = tributary.block(&next).unwrap();

    for tx in &block.transactions {
      // since we know provided txs are the first in the block, we can assume that
      // all of them were ok if we haven't returned yet and got a new kind, so we can
      // break and continue to scan the block.
      let TransactionKind::Provided(order) = tx.kind() else {
        break;
      };

      // make sure we have all the provided txs in this block locally
      if !tributary.provided_txs_ok_for_block(&block.hash(), order) {
        return;
      }
    }

    handle_block::<_, _, _, _, _, _, P>(
      db,
      key,
      recognized_id.clone(),
      processors,
      publish_serai_tx.clone(),
      spec,
      block,
    )
    .await;
    last_block = next;
    db.set_last_block(genesis, next);
  }
}
