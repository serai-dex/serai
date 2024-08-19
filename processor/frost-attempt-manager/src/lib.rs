#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::collections::HashMap;

use frost::{Participant, sign::PreprocessMachine};

use serai_validator_sets_primitives::Session;

use messages::sign::{ProcessorMessage, CoordinatorMessage};

mod individual;
use individual::SigningProtocol;

/// A response to handling a message from the coordinator.
pub enum Response<M: PreprocessMachine> {
  /// Messages to send to the coordinator.
  Messages(Vec<ProcessorMessage>),
  /// A produced signature.
  Signature(M::Signature),
}

/// A manager of attempts for a variety of signing protocols.
pub struct AttemptManager<M: Clone + PreprocessMachine> {
  session: Session,
  start_i: Participant,
  active: HashMap<[u8; 32], SigningProtocol<M>>,
}

impl<M: Clone + PreprocessMachine> AttemptManager<M> {
  /// Create a new attempt manager.
  pub fn new(session: Session, start_i: Participant) -> Self {
    AttemptManager { session, start_i, active: HashMap::new() }
  }

  /// Register a signing protocol to attempt.
  pub fn register(&mut self, id: [u8; 32], machines: Vec<M>) {
    self.active.insert(id, SigningProtocol::new(self.session, self.start_i, id, machines));
  }

  /// Retire a signing protocol.
  ///
  /// This frees all memory used for it and means no further messages will be handled for it.
  /// This does not stop the protocol from being re-registered and further worked on (with
  /// undefined behavior) then. The higher-level context must never call `register` again with this
  /// ID.
  // TODO: Also have the DB for this SigningProtocol cleaned up here.
  pub fn retire(&mut self, id: [u8; 32]) {
    log::info!("retiring signing protocol {}", hex::encode(id));
    self.active.remove(&id);
  }

  /// Handle a message for a signing protocol.
  pub fn handle(&mut self, msg: CoordinatorMessage) -> Response<M> {
    match msg {
      CoordinatorMessage::Preprocesses { id, preprocesses } => {
        let Some(protocol) = self.active.get_mut(&id.id) else {
          log::trace!(
            "handling preprocesses for signing protocol {}, which we're not actively running",
            hex::encode(id.id)
          );
          return Response::Messages(vec![]);
        };
        Response::Messages(protocol.preprocesses(id.attempt, preprocesses))
      }
      CoordinatorMessage::Shares { id, shares } => {
        let Some(protocol) = self.active.get_mut(&id.id) else {
          log::trace!(
            "handling shares for signing protocol {}, which we're not actively running",
            hex::encode(id.id)
          );
          return Response::Messages(vec![]);
        };
        match protocol.shares(id.attempt, shares) {
          Ok(signature) => Response::Signature(signature),
          Err(messages) => Response::Messages(messages),
        }
      }
      CoordinatorMessage::Reattempt { id } => {
        let Some(protocol) = self.active.get_mut(&id.id) else {
          log::trace!(
            "reattempting signing protocol {}, which we're not actively running",
            hex::encode(id.id)
          );
          return Response::Messages(vec![]);
        };
        Response::Messages(protocol.attempt(id.attempt))
      }
    }
  }
}
