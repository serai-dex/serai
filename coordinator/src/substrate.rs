use core::future::Future;
use std::sync::Arc;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use tokio::sync::mpsc;

use serai_db::{DbTxn, Db as DbTrait};

use serai_client::validator_sets::primitives::{Session, ExternalValidatorSet};
use message_queue::{Service, Metadata, client::MessageQueue};

use tributary_sdk::Tributary;

use serai_task::ContinuallyRan;

use serai_coordinator_tributary::Transaction;
use serai_coordinator_p2p::P2p;

use crate::{Db, KeySet};

pub(crate) struct SubstrateTask<P: P2p> {
  pub(crate) serai_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub(crate) db: Db,
  pub(crate) message_queue: Arc<MessageQueue>,
  pub(crate) p2p: P,
  pub(crate) p2p_add_tributary:
    mpsc::UnboundedSender<(ExternalValidatorSet, Tributary<Db, Transaction, P>)>,
  pub(crate) p2p_retire_tributary: mpsc::UnboundedSender<ExternalValidatorSet>,
}

impl<P: P2p> ContinuallyRan for SubstrateTask<P> {
  type Error = String; // TODO
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      // Handle the Canonical events
      for network in serai_client::primitives::EXTERNAL_NETWORKS {
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
              let prior_retired = crate::db::RetiredTributary::get(&txn, network);
              let next_to_be_retired =
                prior_retired.map(|session| Session(session.0 + 1)).unwrap_or(Session(0));
              assert_eq!(session, next_to_be_retired);
              crate::db::RetiredTributary::set(&mut txn, network, &session);
              self
                .p2p_retire_tributary
                .send(ExternalValidatorSet { network, session })
                .expect("p2p retire_tributary channel dropped?");
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
        let Some(new_set) = serai_coordinator_substrate::NewSet::try_recv(&mut txn) else { break };

        if let Some(historic_session) = new_set.set.session.0.checked_sub(2) {
          // We should have retired this session if we're here
          if crate::db::RetiredTributary::get(&txn, new_set.set.network).map(|session| session.0) <
            Some(historic_session)
          {
            /*
              If we haven't, it's because we're processing the NewSet event before the retiry
              event from the Canonical event stream. This happens if the Canonical event, and
              then the NewSet event, is fired while we're already iterating over NewSet events.

              We break, dropping the txn, restoring this NewSet to the database, so we'll only
              handle it once a future iteration of this loop handles the retiry event.
            */
            break;
          }

          /*
            Queue this historical Tributary for deletion.

            We explicitly don't queue this upon Tributary retire, instead here, to give time to
            investigate retired Tributaries if questions are raised post-retiry. This gives a
            week (the duration of the following session) after the Tributary has been retired to
            make a backup of the data directory for any investigations.
          */
          crate::db::TributaryCleanup::send(
            &mut txn,
            &ExternalValidatorSet {
              network: new_set.set.network,
              session: Session(historic_session),
            },
          );
        }

        // Save this Tributary as active to the database
        {
          let mut active_tributaries =
            crate::db::ActiveTributaries::get(&txn).unwrap_or(Vec::with_capacity(1));
          active_tributaries.push(new_set.clone());
          crate::db::ActiveTributaries::set(&mut txn, &active_tributaries);
        }

        // Send GenerateKey to the processor
        let msg = messages::key_gen::CoordinatorMessage::GenerateKey {
          session: new_set.set.session,
          threshold: new_set.threshold,
          evrf_public_keys: new_set.evrf_public_keys.clone(),
        };
        let msg = messages::CoordinatorMessage::from(msg);
        let metadata = Metadata {
          from: Service::Coordinator,
          to: Service::Processor(new_set.set.network),
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
          self.db.clone(),
          self.message_queue.clone(),
          self.p2p.clone(),
          &self.p2p_add_tributary,
          new_set,
          self.serai_key.clone(),
        )
        .await;

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
