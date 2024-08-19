use std::collections::HashMap;

use rand_core::OsRng;

use frost::{
  Participant, FrostError,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use serai_validator_sets_primitives::Session;

use serai_db::{Get, DbTxn, Db, create_db};
use messages::sign::{SignId, ProcessorMessage};

create_db!(
  FrostAttemptManager {
    Attempted: (id: [u8; 32]) -> u32,
  }
);

/// An instance of a signing protocol with re-attempts handled internally.
#[allow(clippy::type_complexity)]
pub(crate) struct SigningProtocol<D: Db, M: Clone + PreprocessMachine> {
  db: D,
  // The session this signing protocol is being conducted by.
  session: Session,
  // The `i` of our first, or starting, set of key shares we will be signing with.
  // The key shares we sign with are expected to be continguous from this position.
  start_i: Participant,
  // The ID of this signing protocol.
  id: [u8; 32],
  // This accepts a vector of `root` machines in order to support signing with multiple key shares.
  root: Vec<M>,
  preprocessed: HashMap<u32, (Vec<M::SignMachine>, HashMap<Participant, Vec<u8>>)>,
  // Here, we drop to a single machine as we only need one to complete the signature.
  shared: HashMap<
    u32,
    (
      <M::SignMachine as SignMachine<M::Signature>>::SignatureMachine,
      HashMap<Participant, Vec<u8>>,
    ),
  >,
}

impl<D: Db, M: Clone + PreprocessMachine> SigningProtocol<D, M> {
  /// Create a new signing protocol.
  pub(crate) fn new(
    db: D,
    session: Session,
    start_i: Participant,
    id: [u8; 32],
    root: Vec<M>,
  ) -> Self {
    log::info!("starting signing protocol {}", hex::encode(id));

    Self {
      db,
      session,
      start_i,
      id,
      root,
      preprocessed: HashMap::with_capacity(1),
      shared: HashMap::with_capacity(1),
    }
  }

  /// Start a new attempt of the signing protocol.
  ///
  /// Returns the (serialized) preprocesses for the attempt.
  pub(crate) fn attempt(&mut self, attempt: u32) -> Vec<ProcessorMessage> {
    /*
      We'd get slashed as malicious if we:
        1) Preprocessed
        2) Rebooted
        3) On reboot, preprocessed again, sending new preprocesses which would be deduplicated by
           the message-queue
        4) Got sent preprocesses
        5) Sent a share based on our new preprocesses, yet with everyone else expecting it to be
           based on our old preprocesses

      We avoid this by saving to the DB we preprocessed before sending our preprocessed, and only
      keeping our preprocesses for this instance of the processor. Accordingly, on reboot, we will
      flag the prior preprocess and not send new preprocesses.

      We also won't send the share we were supposed to, unfortunately, yet caching/reloading the
      preprocess has enough safety issues it isn't worth the headache.
    */
    {
      let mut txn = self.db.txn();
      let prior_attempted = Attempted::get(&txn, self.id);
      if Some(attempt) <= prior_attempted {
        return vec![];
      }
      Attempted::set(&mut txn, self.id, &attempt);
      txn.commit();
    }

    log::debug!("attemting a new instance of signing protocol {}", hex::encode(self.id));

    let mut our_preprocesses = HashMap::with_capacity(self.root.len());
    let mut preprocessed = Vec::with_capacity(self.root.len());
    let mut preprocesses = Vec::with_capacity(self.root.len());
    for (i, machine) in self.root.iter().enumerate() {
      let (machine, preprocess) = machine.clone().preprocess(&mut OsRng);
      preprocessed.push(machine);

      let mut this_preprocess = Vec::with_capacity(64);
      preprocess.write(&mut this_preprocess).unwrap();

      our_preprocesses.insert(
        Participant::new(
          u16::from(self.start_i) + u16::try_from(i).expect("signing with 2**16 machines"),
        )
        .expect("start_i + i exceeded the valid indexes for a Participant"),
        this_preprocess.clone(),
      );
      preprocesses.push(this_preprocess);
    }
    assert!(self.preprocessed.insert(attempt, (preprocessed, our_preprocesses)).is_none());

    vec![ProcessorMessage::Preprocesses {
      id: SignId { session: self.session, id: self.id, attempt },
      preprocesses,
    }]
  }

  /// Handle preprocesses for the signing protocol.
  ///
  /// Returns the (serialized) shares for the attempt.
  pub(crate) fn preprocesses(
    &mut self,
    attempt: u32,
    serialized_preprocesses: HashMap<Participant, Vec<u8>>,
  ) -> Vec<ProcessorMessage> {
    log::debug!("handling preprocesses for signing protocol {}", hex::encode(self.id));

    let Some((machines, our_serialized_preprocesses)) = self.preprocessed.remove(&attempt) else {
      return vec![];
    };

    let mut msgs = Vec::with_capacity(1);

    let mut preprocesses =
      HashMap::with_capacity(serialized_preprocesses.len() + our_serialized_preprocesses.len());
    for (i, serialized_preprocess) in
      serialized_preprocesses.into_iter().chain(our_serialized_preprocesses)
    {
      let mut serialized_preprocess = serialized_preprocess.as_slice();
      let Ok(preprocess) = machines[0].read_preprocess(&mut serialized_preprocess) else {
        msgs.push(ProcessorMessage::InvalidParticipant { session: self.session, participant: i });
        continue;
      };
      if !serialized_preprocess.is_empty() {
        msgs.push(ProcessorMessage::InvalidParticipant { session: self.session, participant: i });
        continue;
      }
      preprocesses.insert(i, preprocess);
    }
    // We throw out our preprocessed machines here, despite the fact they haven't been invalidated
    // We could reuse them with a new set of valid preprocesses
    // https://github.com/serai-dex/serai/issues/588
    if !msgs.is_empty() {
      return msgs;
    }

    let mut our_shares = HashMap::with_capacity(self.root.len());
    let mut shared = Vec::with_capacity(machines.len());
    let mut shares = Vec::with_capacity(machines.len());
    for (i, machine) in machines.into_iter().enumerate() {
      let i = Participant::new(
        u16::from(self.start_i) + u16::try_from(i).expect("signing with 2**16 machines"),
      )
      .expect("start_i + i exceeded the valid indexes for a Participant");

      let mut preprocesses = preprocesses.clone();
      assert!(preprocesses.remove(&i).is_some());

      // TODO: Replace this with `()`, which requires making the message type part of the trait
      let (machine, share) = match machine.sign(preprocesses, &[]) {
        Ok((machine, share)) => (machine, share),
        Err(e) => match e {
          FrostError::InternalError(_) |
          FrostError::InvalidParticipant(_, _) |
          FrostError::InvalidSigningSet(_) |
          FrostError::InvalidParticipantQuantity(_, _) |
          FrostError::DuplicatedParticipant(_) |
          FrostError::MissingParticipant(_) |
          FrostError::InvalidShare(_) => {
            panic!("FROST had an error which shouldn't be reachable: {e:?}");
          }
          FrostError::InvalidPreprocess(i) => {
            msgs
              .push(ProcessorMessage::InvalidParticipant { session: self.session, participant: i });
            return msgs;
          }
        },
      };
      shared.push(machine);

      let mut this_share = Vec::with_capacity(32);
      share.write(&mut this_share).unwrap();

      our_shares.insert(i, this_share.clone());
      shares.push(this_share);
    }

    assert!(self.shared.insert(attempt, (shared.swap_remove(0), our_shares)).is_none());
    log::debug!(
      "successfully handled preprocesses for signing protocol {}, sending shares",
      hex::encode(self.id)
    );
    msgs.push(ProcessorMessage::Shares {
      id: SignId { session: self.session, id: self.id, attempt },
      shares,
    });
    msgs
  }

  /// Process shares for the signing protocol.
  ///
  /// Returns the signature produced by the protocol.
  pub(crate) fn shares(
    &mut self,
    attempt: u32,
    serialized_shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<M::Signature, Vec<ProcessorMessage>> {
    log::debug!("handling shares for signing protocol {}", hex::encode(self.id));

    let Some((machine, our_serialized_shares)) = self.shared.remove(&attempt) else { Err(vec![])? };

    let mut msgs = Vec::with_capacity(1);

    let mut shares = HashMap::with_capacity(serialized_shares.len() + our_serialized_shares.len());
    for (i, serialized_share) in our_serialized_shares.into_iter().chain(serialized_shares) {
      let mut serialized_share = serialized_share.as_slice();
      let Ok(share) = machine.read_share(&mut serialized_share) else {
        msgs.push(ProcessorMessage::InvalidParticipant { session: self.session, participant: i });
        continue;
      };
      if !serialized_share.is_empty() {
        msgs.push(ProcessorMessage::InvalidParticipant { session: self.session, participant: i });
        continue;
      }
      shares.insert(i, share);
    }
    if !msgs.is_empty() {
      Err(msgs)?;
    }

    assert!(shares.remove(&self.start_i).is_some());

    let signature = match machine.complete(shares) {
      Ok(signature) => signature,
      Err(e) => match e {
        FrostError::InternalError(_) |
        FrostError::InvalidParticipant(_, _) |
        FrostError::InvalidSigningSet(_) |
        FrostError::InvalidParticipantQuantity(_, _) |
        FrostError::DuplicatedParticipant(_) |
        FrostError::MissingParticipant(_) |
        FrostError::InvalidPreprocess(_) => {
          panic!("FROST had an error which shouldn't be reachable: {e:?}");
        }
        FrostError::InvalidShare(i) => {
          Err(vec![ProcessorMessage::InvalidParticipant { session: self.session, participant: i }])?
        }
      },
    };

    log::info!("finished signing for protocol {}", hex::encode(self.id));

    Ok(signature)
  }

  /// Cleanup the database entries for a specified signing protocol.
  pub(crate) fn cleanup(db: &mut D, id: [u8; 32]) {
    let mut txn = db.txn();
    Attempted::del(&mut txn, id);
    txn.commit();
  }
}
