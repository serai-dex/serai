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

use serai_db::{Get, DbTxn};

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

  let mut event_id = 0; // TODO: should start from -1 so that we need only 1 event_id += 1?
  #[allow(clippy::explicit_counter_loop)] // event_id isn't TX index. It just currently lines up
  for tx in block.transactions {
    if TributaryDb::<D>::handled_event(&db.0, hash, event_id) {
      event_id += 1;
      continue;
    }

    let mut txn = db.0.txn();

    match tx {
      TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
        // since the evidence is on the chain, it already
        // should be valid. So we can just punish the signer.
        let msgs = decode_evidence::<TendermintNetwork<D, Transaction, P>>(&ev).unwrap();

        // mark the node as fatally slashed
        TributaryDb::<D>::set_fatally_slashed(&mut txn, genesis, msgs[0].msg.sender);

        // TODO: disconnect the node from network
      }
      TributaryTransaction::Tendermint(TendermintTx::SlashVote(vote)) => {
        // TODO: make sure same signer doesn't vote twice

        // increment the counter for this vote
        let vote_key = TributaryDb::<D>::slash_vote_key(genesis, vote.id, vote.target);
        let mut count = txn.get(&vote_key).map_or(0, |c| u32::from_le_bytes(c.try_into().unwrap()));
        count += 1;
        txn.put(vote_key, count.to_le_bytes());

        // TODO: check whether 2/3 of all validators voted.
        // and increment the slash points if yes.
        // if a node has a certain number more than the median slash points,
        // the node should be removed.
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
