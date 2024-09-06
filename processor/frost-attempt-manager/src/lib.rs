#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::collections::HashMap;

use frost::{Participant, sign::PreprocessMachine};

use serai_validator_sets_primitives::Session;

use serai_db::Db;
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
pub struct AttemptManager<D: Db, M: Clone + PreprocessMachine> {
  db: D,
  session: Session,
  start_i: Participant,
  active: HashMap<[u8; 32], SigningProtocol<D, M>>,
}

impl<D: Db, M: Clone + PreprocessMachine> AttemptManager<D, M> {
  /// Create a new attempt manager.
  ///
  /// This will not restore any signing sessions from the database. Those must be re-registered.
  pub fn new(db: D, session: Session, start_i: Participant) -> Self {
    AttemptManager { db, session, start_i, active: HashMap::new() }
  }

  /// Register a signing protocol to attempt.
  ///
  /// This ID must be unique across all sessions, attempt managers, protocols, etc.
  pub fn register(&mut self, id: [u8; 32], machines: Vec<M>) -> Vec<ProcessorMessage> {
    let mut protocol =
      SigningProtocol::new(self.db.clone(), self.session, self.start_i, id, machines);
    let messages = protocol.attempt(0);
    self.active.insert(id, protocol);
    messages
  }

  /// Retire a signing protocol.
  ///
  /// This frees all memory used for it and means no further messages will be handled for it.
  /// This does not stop the protocol from being re-registered and further worked on (with
  /// undefined behavior) then. The higher-level context must never call `register` again with this
  /// ID accordingly.
  pub fn retire(&mut self, id: [u8; 32]) {
    if self.active.remove(&id).is_none() {
      log::info!("retiring protocol {}, which we didn't register/already retired", hex::encode(id));
    } else {
      log::info!("retired signing protocol {}", hex::encode(id));
    }
    SigningProtocol::<D, M>::cleanup(&mut self.db, id);
  }

  /// Handle a message for a signing protocol.
  ///
  /// Handling a message multiple times is safe and will cause subsequent calls to return
  /// `Response::Messages(vec![])`. Handling a message for a signing protocol which isn't being
  /// worked on (potentially due to rebooting) will also return `Response::Messages(vec![])`.
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
