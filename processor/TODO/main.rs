use messages::{
  coordinator::{
    SubstrateSignableId, PlanMeta, CoordinatorMessage as CoordinatorCoordinatorMessage,
  },
  CoordinatorMessage,
};

use serai_env as env;

use message_queue::{Service, client::MessageQueue};

mod db;
pub use db::*;

mod coordinator;
pub use coordinator::*;

mod multisigs;
use multisigs::{MultisigEvent, MultisigManager};

#[cfg(test)]
mod tests;

async fn handle_coordinator_msg<D: Db, N: Network, Co: Coordinator>(
  txn: &mut D::Transaction<'_>,
  network: &N,
  coordinator: &mut Co,
  tributary_mutable: &mut TributaryMutable<N, D>,
  substrate_mutable: &mut SubstrateMutable<N, D>,
  msg: &Message,
) {
  match msg.msg.clone() {
    CoordinatorMessage::Substrate(msg) => {
      match msg {
        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context,
          block: substrate_block,
          burns,
          batches,
        } => {
          // Send SubstrateBlockAck, with relevant plan IDs, before we trigger the signing of these
          // plans
          if !tributary_mutable.signers.is_empty() {
            coordinator
              .send(messages::coordinator::ProcessorMessage::SubstrateBlockAck {
                block: substrate_block,
                plans: to_sign
                  .iter()
                  .filter_map(|signable| {
                    SessionDb::get(txn, signable.0.to_bytes().as_ref())
                      .map(|session| PlanMeta { session, id: signable.1 })
                  })
                  .collect(),
              })
              .await;
          }
        }
      }
    }
  }
}
