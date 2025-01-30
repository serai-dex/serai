use core::{borrow::Borrow, future::Future};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use serai_client::{
  primitives::ExternalNetworkId, validator_sets::primitives::Session, SeraiError, Serai,
};

use serai_task::{Task, ContinuallyRan};

use libp2p::PeerId;

use futures_util::stream::{StreamExt, FuturesUnordered};
use tokio::sync::{mpsc, RwLock};

use crate::peer_id_from_public;

pub(crate) struct Changes {
  pub(crate) removed: HashSet<PeerId>,
  pub(crate) added: HashSet<PeerId>,
}

pub(crate) struct Validators {
  serai: Arc<Serai>,

  // A cache for which session we're populated with the validators of
  sessions: HashMap<ExternalNetworkId, Session>,
  // The validators by network
  by_network: HashMap<ExternalNetworkId, HashSet<PeerId>>,
  // The validators and their networks
  validators: HashMap<PeerId, HashSet<ExternalNetworkId>>,

  // The channel to send the changes down
  changes: mpsc::UnboundedSender<Changes>,
}

impl Validators {
  pub(crate) fn new(serai: Arc<Serai>) -> (Self, mpsc::UnboundedReceiver<Changes>) {
    let (send, recv) = mpsc::unbounded_channel();
    let validators = Validators {
      serai,
      sessions: HashMap::new(),
      by_network: HashMap::new(),
      validators: HashMap::new(),
      changes: send,
    };
    (validators, recv)
  }

  async fn session_changes(
    serai: impl Borrow<Serai>,
    sessions: impl Borrow<HashMap<ExternalNetworkId, Session>>,
  ) -> Result<Vec<(ExternalNetworkId, Session, HashSet<PeerId>)>, SeraiError> {
    /*
      This uses the latest finalized block, not the latest cosigned block, which should be fine as
      in the worst case, we'd connect to unexpected validators. They still shouldn't be able to
      bypass the cosign protocol unless a historical global session was malicious, in which case
      the cosign protocol already breaks.

      Besides, we can't connect to historical validators, only the current validators.
    */
    let temporal_serai = serai.borrow().as_of_latest_finalized_block().await?;
    let temporal_serai = temporal_serai.validator_sets();

    let mut session_changes = vec![];
    {
      // FuturesUnordered can be bad practice as it'll cause timeouts if infrequently polled, but
      // we poll it till it yields all futures with the most minimal processing possible
      let mut futures = FuturesUnordered::new();
      for network in serai_client::primitives::EXTERNAL_NETWORKS {
        let sessions = sessions.borrow();
        futures.push(async move {
          let session = match temporal_serai.session(network.into()).await {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
          };

          if sessions.get(&network) == Some(&session) {
            Ok(None)
          } else {
            match temporal_serai.active_network_validators(network.into()).await {
              Ok(validators) => Ok(Some((
                network,
                session,
                validators.into_iter().map(peer_id_from_public).collect(),
              ))),
              Err(e) => Err(e),
            }
          }
        });
      }
      while let Some(session_change) = futures.next().await {
        if let Some(session_change) = session_change? {
          session_changes.push(session_change);
        }
      }
    }

    Ok(session_changes)
  }

  fn incorporate_session_changes(
    &mut self,
    session_changes: Vec<(ExternalNetworkId, Session, HashSet<PeerId>)>,
  ) {
    let mut removed = HashSet::new();
    let mut added = HashSet::new();

    for (network, session, validators) in session_changes {
      // Remove the existing validators
      for validator in self.by_network.remove(&network).unwrap_or_else(HashSet::new) {
        // Get all networks this validator is in
        let mut networks = self.validators.remove(&validator).unwrap();
        // Remove this one
        networks.remove(&network);
        if !networks.is_empty() {
          // Insert the networks back if the validator was present in other networks
          self.validators.insert(validator, networks);
        } else {
          // Because this validator is no longer present in any network, mark them as removed
          /*
            This isn't accurate. The validator isn't present in the latest session for this
            network. The validator was present in the prior session which has yet to retire. Our
            lack of explicit inclusion for both the prior session and the current session causes
            only the validators mutually present in both sessions to be responsible for all actions
            still ongoing as the prior validator set retires.

            TODO: Fix this
          */
          removed.insert(validator);
        }
      }

      // Add the new validators
      for validator in validators.iter().copied() {
        self.validators.entry(validator).or_insert_with(HashSet::new).insert(network);
        added.insert(validator);
      }
      self.by_network.insert(network, validators);

      // Update the session we have populated
      self.sessions.insert(network, session);
    }

    // Only flag validators for removal if they weren't simultaneously added by these changes
    removed.retain(|validator| !added.contains(validator));
    // Send the changes, dropping the error
    // This lets the caller opt-out of change notifications by dropping the receiver
    let _: Result<_, _> = self.changes.send(Changes { removed, added });
  }

  /// Update the view of the validators.
  pub(crate) async fn update(&mut self) -> Result<(), SeraiError> {
    let session_changes = Self::session_changes(&*self.serai, &self.sessions).await?;
    self.incorporate_session_changes(session_changes);
    Ok(())
  }

  pub(crate) fn by_network(&self) -> &HashMap<ExternalNetworkId, HashSet<PeerId>> {
    &self.by_network
  }

  pub(crate) fn networks(&self, peer_id: &PeerId) -> Option<&HashSet<ExternalNetworkId>> {
    self.validators.get(peer_id)
  }
}

/// A task which updates a set of validators.
///
/// The validators managed by this tak will have their exclusive lock held for a minimal amount of
/// time while the update occurs to minimize the disruption to the services relying on it.
pub(crate) struct UpdateValidatorsTask {
  validators: Arc<RwLock<Validators>>,
}

impl UpdateValidatorsTask {
  /// Spawn a new instance of the UpdateValidatorsTask.
  ///
  /// This returns a reference to the Validators it updates after spawning itself.
  pub(crate) fn spawn(
    serai: Arc<Serai>,
  ) -> (Arc<RwLock<Validators>>, mpsc::UnboundedReceiver<Changes>) {
    // The validators which will be updated
    let (validators, changes) = Validators::new(serai);
    let validators = Arc::new(RwLock::new(validators));

    // Define the task
    let (update_validators_task, update_validators_task_handle) = Task::new();
    // Forget the handle, as dropping the handle would stop the task
    core::mem::forget(update_validators_task_handle);
    // Spawn the task
    tokio::spawn(
      (Self { validators: validators.clone() }).continually_run(update_validators_task, vec![]),
    );

    // Return the validators
    (validators, changes)
  }
}

impl ContinuallyRan for UpdateValidatorsTask {
  // Only run every minute, not the default of every five seconds
  const DELAY_BETWEEN_ITERATIONS: u64 = 60;
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 5 * 60;

  type Error = SeraiError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let session_changes = {
        let validators = self.validators.read().await;
        Validators::session_changes(validators.serai.clone(), validators.sessions.clone()).await?
      };
      self.validators.write().await.incorporate_session_changes(session_changes);
      Ok(true)
    }
  }
}
