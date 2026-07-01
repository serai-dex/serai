use core::future::Future;
use std::sync::Arc;

use zeroize::Zeroizing;

use ciphersuite::*;
use dalek_ff_group::Ristretto;

use tokio::sync::mpsc;

use serai_db::{DbTxn, Db as _};

use serai_client_serai::abi::primitives::{
  network_id::ExternalNetworkId,
  validator_sets::{Session, ExternalValidatorSet},
};
use message_queue::{Service, Metadata, Client as MessageQueue};

use tributary_sdk::Tributary;

use serai_task::ContinuallyRan;

use serai_env::Environment;

use serai_coordinator_tributary::Transaction;
use serai_coordinator_p2p::P2p;

use crate::{Db, KeySet};

pub(crate) struct SubstrateTask<P: P2p> {
  pub(crate) env: Environment,
  pub(crate) private_serai_auxiliary_key: Zeroizing<<Ristretto as WrappedGroup>::F>,
  pub(crate) db: Db,
  pub(crate) message_queue: Arc<MessageQueue>,
  pub(crate) p2p: P,
  pub(crate) p2p_add_tributary:
    mpsc::UnboundedSender<(ExternalValidatorSet, Tributary<Db, Transaction, P>)>,
  pub(crate) p2p_retire_tributary: mpsc::UnboundedSender<ExternalValidatorSet>,
}

impl<P: P2p> SubstrateTask<P> {
  // Helper to calculate next session to be retired
  fn next_session_to_be_retired(txn: &impl DbTxn, network: ExternalNetworkId) -> Session {
    let prior_retired = crate::db::RetiredTributary::get(txn, network);
    prior_retired.map(|session| Session(session.0 + 1)).unwrap_or(Session(0))
  }
  // Helper to retire a session
  fn retire_session(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
    session: Session,
    p2p_retire_tributary: &mpsc::UnboundedSender<ExternalValidatorSet>,
  ) {
    crate::db::RetiredTributary::set(txn, network, &session);
    p2p_retire_tributary
      .send(ExternalValidatorSet { network, session })
      .expect("p2p retire_tributary channel dropped?");
  }
}

impl<P: P2p> ContinuallyRan for SubstrateTask<P> {
  type Error = String; // TODO
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      // Handle the Canonical events
      for network in ExternalNetworkId::all() {
        loop {
          let mut txn = self.db.txn();
          let Some(msg) = serai_coordinator_substrate::Canonical::try_recv(&mut txn, network)
          else {
            break;
          };

          match msg {
            messages::substrate::CoordinatorMessage::SetKeys { session, .. } => {
              KeySet::set(&mut txn, ExternalValidatorSet { network, session }, &());
            }
            messages::substrate::CoordinatorMessage::SlashesReported { session } => {
              let next_session_to_be_retired = Self::next_session_to_be_retired(&txn, network);
              assert_eq!(session, next_session_to_be_retired);
              Self::retire_session(&mut txn, network, session, &self.p2p_retire_tributary);
            }
            messages::substrate::CoordinatorMessage::Block { .. } => {}
          }

          let msg = messages::CoordinatorMessage::from(msg);
          let metadata = Metadata {
            from: Service::Coordinator,
            to: Service::Processor(network),
            intent: msg.intent(),
          };
          let msg = borsh::to_vec(&msg).unwrap();
          self.message_queue.queue(metadata, msg).await?;
          txn.commit();
          made_progress = true;
        }
      }

      // Handle the NewSet events
      loop {
        let mut txn = self.db.txn();
        let Some(tributary_validator_set_info) =
          serai_coordinator_substrate::EphemeralNewDecidedSet::try_recv(&mut txn)
        else {
          break;
        };
        let ExternalValidatorSet { network, session } = tributary_validator_set_info.set;

        if let Some(historical_session) = session.0.checked_sub(2) {
          let next_session_to_be_retired = Self::next_session_to_be_retired(&txn, network);

          // We should retire the historical session if we're here
          if next_session_to_be_retired.0 == historical_session {
            Self::retire_session(
              &mut txn,
              network,
              next_session_to_be_retired,
              &self.p2p_retire_tributary,
            );
          }

          /*
            Queue this historical Tributary for deletion.

            We explicitly don't queue this upon SlashesReported, instead here, to give time to
            investigate slashed reported Tributaries if questions are raised post-slash reported.
            This gives a week (the duration of the following session) after the Tributary has been
            slash reported to make a backup of the data directory for any investigations.
          */
          crate::db::TributaryCleanup::send(
            &mut txn,
            &ExternalValidatorSet { network, session: Session(historical_session) },
          );
        }

        // Save this Tributary as active to the database
        {
          let mut active_tributaries =
            crate::db::ActiveTributaries::get(&txn).unwrap_or(Vec::with_capacity(1));
          active_tributaries.push(tributary_validator_set_info.clone());
          crate::db::ActiveTributaries::set(&mut txn, &active_tributaries);
        }

        // Send GenerateKey to the processor
        let tributary_validator_set = &tributary_validator_set_info.tributary_validator_set;
        let msg = messages::key_gen::CoordinatorMessage::GenerateKey {
          session: tributary_validator_set_info.set.session,
          threshold: tributary_validator_set.evrf_threshold(),
          substrate_evrf_public_keys: tributary_validator_set
            .evrf_networks_substrate_keys()
            .to_vec(),
          network_evrf_public_keys: tributary_validator_set.evrf_networks_external_keys().to_vec(),
        };
        let msg = messages::CoordinatorMessage::from(msg);
        let metadata = Metadata {
          from: Service::Coordinator,
          to: Service::Processor(network),
          intent: msg.intent(),
        };
        let msg = borsh::to_vec(&msg).unwrap();
        self.message_queue.queue(metadata, msg).await?;

        // Commit the transaction for all of this
        txn.commit();

        // Now spawn the Tributary
        // If we reboot after committing the txn, but before this is called, this will be called
        // on boot
        crate::tributary::spawn_tributary(
          &self.env,
          self.db.clone(),
          self.message_queue.clone(),
          self.p2p.clone(),
          &self.p2p_add_tributary,
          tributary_validator_set_info,
          self.private_serai_auxiliary_key.clone(),
        )
        .await;

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
