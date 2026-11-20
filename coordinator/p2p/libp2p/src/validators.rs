use core::{borrow::Borrow, time::Duration};
use alloc::sync::Arc;
use std::{
  sync::RwLock,
  collections::{HashSet, HashMap},
};

use serai_client_serai::abi::primitives::network_id::ExternalNetworkId;
use serai_client_serai::{RpcError, Serai};

use serai_task::{Task, ContinuallyRan};

use libp2p::PeerId;

use futures_util::stream::{StreamExt as _, FuturesUnordered};

use crate::peer_id_from_public;

pub(crate) struct Changes {
  pub(crate) removed: HashSet<PeerId>,
  pub(crate) added: HashSet<PeerId>,
}

pub(crate) struct Validators {
  serai: Arc<Serai>,

  // The validators by network
  by_network: HashMap<ExternalNetworkId, HashSet<PeerId>>,
  // The validators and their networks
  validators: HashMap<PeerId, HashSet<ExternalNetworkId>>,

  // The channel to send the changes down
  changes: async_channel::Sender<Changes>,
}

impl Validators {
  pub(crate) fn new(serai: Arc<Serai>) -> (Self, async_channel::Receiver<Changes>) {
    let (send, recv) = async_channel::bounded(1);
    let validators =
      Validators { serai, by_network: HashMap::new(), validators: HashMap::new(), changes: send };
    (validators, recv)
  }

  async fn session_changes(
    serai: impl Borrow<Serai>,
    by_network: impl Borrow<HashMap<ExternalNetworkId, HashSet<PeerId>>>,
  ) -> Result<Vec<(ExternalNetworkId, HashSet<PeerId>)>, RpcError> {
    /*
      This uses the validators the Serai node says to peer with as of its latest block, not the
      latest finalized block nor the latest cosigned block, which should be fine as in the worst
      case, we'd connect to unexpected validators. They still shouldn't be able to bypass the
      cosign protocol unless a historical global session was malicious, in which case the cosign
      protocol already breaks.

      These are the validators for the current session and for the latest decided session, as the
      latter must be able to communicate in order to generate the keys which let it become the
      current session. We can't connect to historical validators.

      As there's no singular session these validators are for, we fetch them every time and only
      yield the networks whose validators differ from the validators we're currently aware of.
    */
    let mut session_changes = vec![];
    {
      // FuturesUnordered can be bad practice as it'll cause timeouts if infrequently polled, but
      // we poll it till it yields all futures with the most minimal processing possible
      let mut futures = FuturesUnordered::new();
      for network in ExternalNetworkId::all() {
        let by_network = by_network.borrow();
        let serai = serai.borrow();
        futures.push(async move {
          let validators = serai
            .p2p_validators(network)
            .await?
            .into_iter()
            .filter_map(|validator| validator.identity.map(peer_id_from_public))
            .collect::<HashSet<_>>();

          Ok((by_network.get(&network) != Some(&validators)).then_some((network, validators)))
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
    session_changes: Vec<(ExternalNetworkId, HashSet<PeerId>)>,
  ) -> impl use<> + Send + Future<Output = ()> {
    let mut removed = HashSet::new();
    let mut added = HashSet::new();

    for (network, validators) in session_changes {
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
    }

    // Only flag validators for removal if they weren't simultaneously added by these changes
    removed.retain(|validator| !added.contains(validator));
    // Send the changes, dropping the error
    // This lets the caller opt-out of change notifications by dropping the receiver
    {
      let changes = self.changes.clone();
      async move {
        let _: Result<_, _> = changes.send(Changes { removed, added }).await;
      }
    }
  }

  /// Update the view of the validators.
  pub(crate) async fn update(&mut self) -> Result<(), RpcError> {
    let session_changes = Self::session_changes(&*self.serai, &self.by_network).await?;
    self.incorporate_session_changes(session_changes).await;
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
  ) -> (Arc<RwLock<Validators>>, async_channel::Receiver<Changes>) {
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
  const DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_mins(1);
  const MAX_DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_mins(5);

  type Error = RpcError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let session_changes = {
        let (serai, by_network) = {
          let validators = self.validators.read().unwrap();
          let serai = validators.serai.clone();
          let by_network = validators.by_network.clone();
          (serai, by_network)
        };
        Validators::session_changes(serai, by_network).await?
      };
      let send_channel =
        self.validators.write().unwrap().incorporate_session_changes(session_changes);
      send_channel.await;
      Ok(true)
    }
  }
}
