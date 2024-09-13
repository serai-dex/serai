use core::future::Future;
use std::collections::HashSet;

use ciphersuite::{group::GroupEncoding, Ristretto};
use frost::dkg::ThresholdKeys;

use serai_validator_sets_primitives::Session;
use serai_in_instructions_primitives::{SignedBatch, batch_message};

use serai_db::{Get, DbTxn, Db};

use messages::sign::VariantSignId;

use primitives::task::ContinuallyRan;
use scanner::{BatchesToSign, AcknowledgedBatches};

use frost_attempt_manager::*;

use crate::{
  db::{CoordinatorToBatchSignerMessages, BatchSignerToCoordinatorMessages},
  WrappedSchnorrkelMachine,
};

mod db;
use db::*;

pub(crate) fn last_acknowledged_batch(getter: &impl Get) -> Option<u32> {
  LastAcknowledgedBatch::get(getter)
}

pub(crate) fn signed_batch(getter: &impl Get, id: u32) -> Option<SignedBatch> {
  SignedBatches::get(getter, id)
}

// Fetches batches to sign and signs them.
pub(crate) struct BatchSignerTask<D: Db, E: GroupEncoding> {
  db: D,

  session: Session,
  external_key: E,
  keys: Vec<ThresholdKeys<Ristretto>>,

  active_signing_protocols: HashSet<u32>,
  attempt_manager: AttemptManager<D, WrappedSchnorrkelMachine>,
}

impl<D: Db, E: GroupEncoding> BatchSignerTask<D, E> {
  pub(crate) fn new(
    db: D,
    session: Session,
    external_key: E,
    keys: Vec<ThresholdKeys<Ristretto>>,
  ) -> Self {
    let mut active_signing_protocols = HashSet::new();
    let mut attempt_manager = AttemptManager::new(
      db.clone(),
      session,
      keys.first().expect("creating a batch signer with 0 keys").params().i(),
    );

    // Re-register all active signing protocols
    for id in ActiveSigningProtocols::get(&db, session).unwrap_or(vec![]) {
      active_signing_protocols.insert(id);

      let batch = Batches::get(&db, id).unwrap();
      assert_eq!(batch.id, id);

      let mut machines = Vec::with_capacity(keys.len());
      for keys in &keys {
        machines.push(WrappedSchnorrkelMachine::new(keys.clone(), batch_message(&batch)));
      }
      attempt_manager.register(VariantSignId::Batch(id), machines);
    }

    Self { db, session, external_key, keys, active_signing_protocols, attempt_manager }
  }
}

impl<D: Db, E: Send + GroupEncoding> ContinuallyRan for BatchSignerTask<D, E> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut iterated = false;

      // Check for new batches to sign
      loop {
        let mut txn = self.db.txn();
        let Some(batch) = BatchesToSign::try_recv(&mut txn, &self.external_key) else {
          break;
        };
        iterated = true;

        // Save this to the database as a transaction to sign
        self.active_signing_protocols.insert(batch.id);
        ActiveSigningProtocols::set(
          &mut txn,
          self.session,
          &self.active_signing_protocols.iter().copied().collect(),
        );
        Batches::set(&mut txn, batch.id, &batch);

        let mut machines = Vec::with_capacity(self.keys.len());
        for keys in &self.keys {
          machines.push(WrappedSchnorrkelMachine::new(keys.clone(), batch_message(&batch)));
        }
        for msg in self.attempt_manager.register(VariantSignId::Batch(batch.id), machines) {
          BatchSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
        }

        txn.commit();
      }

      // Check for acknowledged Batches (meaning we should no longer sign for these Batches)
      loop {
        let mut txn = self.db.txn();
        let Some(id) = AcknowledgedBatches::try_recv(&mut txn, &self.external_key) else {
          break;
        };

        {
          let last_acknowledged = LastAcknowledgedBatch::get(&txn);
          if Some(id) > last_acknowledged {
            LastAcknowledgedBatch::set(&mut txn, &id);
          }
        }

        /*
          We may have yet to register this signing protocol.

          While `BatchesToSign` is populated before `AcknowledgedBatches`, we could theoretically
          have `BatchesToSign` populated with a new batch _while iterating over
          `AcknowledgedBatches`_, and then have `AcknowledgedBatched` populated. In that edge case,
          we will see the acknowledgement notification before we see the transaction.

          In such a case, we break (dropping the txn, re-queueing the acknowledgement notification).
          On the task's next iteration, we'll process the Batch from `BatchesToSign` and be
          able to make progress.
        */
        if !self.active_signing_protocols.remove(&id) {
          break;
        }
        iterated = true;

        // Since it was, remove this as an active signing protocol
        ActiveSigningProtocols::set(
          &mut txn,
          self.session,
          &self.active_signing_protocols.iter().copied().collect(),
        );
        // Clean up the database
        Batches::del(&mut txn, id);
        SignedBatches::del(&mut txn, id);

        // We retire with a txn so we either successfully flag this Batch as acknowledged, and
        // won't re-register it (making this retire safe), or we don't flag it, meaning we will
        // re-register it, yet that's safe as we have yet to retire it
        self.attempt_manager.retire(&mut txn, VariantSignId::Batch(id));

        txn.commit();
      }

      // Handle any messages sent to us
      loop {
        let mut txn = self.db.txn();
        let Some(msg) = CoordinatorToBatchSignerMessages::try_recv(&mut txn, self.session) else {
          break;
        };
        iterated = true;

        match self.attempt_manager.handle(msg) {
          Response::Messages(msgs) => {
            for msg in msgs {
              BatchSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
            }
          }
          Response::Signature { id, signature } => {
            let VariantSignId::Batch(id) = id else { panic!("BatchSignerTask signed a non-Batch") };
            let batch =
              Batches::get(&txn, id).expect("signed a Batch we didn't save to the database");
            let signed_batch = SignedBatch { batch, signature: signature.into() };
            SignedBatches::set(&mut txn, signed_batch.batch.id, &signed_batch);
          }
        }

        txn.commit();
      }

      Ok(iterated)
    }
  }
}
