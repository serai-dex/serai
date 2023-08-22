use core::future::Future;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use serai_client::{validator_sets::primitives::ValidatorSet, subxt::utils::Encoded};

use tokio::sync::mpsc::UnboundedSender;

use tributary::{
  Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, decode_evidence},
    TendermintNetwork,
  },
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
  Block,
  Plan,
}

// Handle a specific Tributary block
#[allow(clippy::needless_pass_by_ref_mut)] // False positive?
async fn handle_block<
  D: Db,
  Pro: Processors,
  F: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> F,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
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

        // TODO: disconnect the node from network/ban from further participation in Tributary
      }
      TributaryTransaction::Application(tx) => {
        handle_application_tx::<D, _, _, _>(
          tx,
          spec,
          processors,
          publish_serai_tx.clone(),
          genesis,
          key,
          recognized_id,
          &mut txn,
        )
        .await;
      }
    }

    TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
    txn.commit();

    event_id += 1;
  }

  // TODO: Trigger any necessary re-attempts
}

pub async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  F: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> F,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = db.last_block(genesis);
  while let Some(next) = tributary.block_after(&last_block) {
    let block = tributary.block(&next).unwrap();
    handle_block::<_, _, _, _, P>(
      db,
      key,
      recognized_id,
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
