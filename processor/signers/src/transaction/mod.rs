use frost::dkg::ThresholdKeys;

use serai_validator_sets_primitives::Session;

use serai_db::{DbTxn, Db};

use primitives::task::ContinuallyRan;
use scheduler::{SignableTransaction, TransactionsToSign};
use scanner::{ScannerFeed, Scheduler};

use frost_attempt_manager::*;

use crate::{
  db::{
    CoordinatorToTransactionSignerMessages, TransactionSignerToCoordinatorMessages,
    CompletedEventualitiesForEachKey,
  },
  TransactionPublisher,
};

mod db;

// Fetches transactions to sign and signs them.
pub(crate) struct TransactionTask<
  D: Db,
  S: ScannerFeed,
  Sch: Scheduler<S>,
  P: TransactionPublisher<Sch::SignableTransaction>,
> {
  db: D,
  session: Session,
  keys: Vec<ThresholdKeys<<Sch::SignableTransaction as SignableTransaction>::Ciphersuite>>,
  attempt_manager:
    AttemptManager<D, <Sch::SignableTransaction as SignableTransaction>::PreprocessMachine>,
  publisher: P,
}

impl<D: Db, S: ScannerFeed, Sch: Scheduler<S>, P: TransactionPublisher<Sch::SignableTransaction>>
  TransactionTask<D, S, Sch, P>
{
  pub(crate) fn new(
    db: D,
    session: Session,
    keys: Vec<ThresholdKeys<<Sch::SignableTransaction as SignableTransaction>::Ciphersuite>>,
    publisher: P,
  ) -> Self {
    let attempt_manager = AttemptManager::new(
      db.clone(),
      session,
      keys.first().expect("creating a transaction signer with 0 keys").params().i(),
    );
    Self { db, session, keys, attempt_manager, publisher }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed, Sch: Scheduler<S>, P: TransactionPublisher<Sch::SignableTransaction>>
  ContinuallyRan for TransactionTask<D, S, Sch, P>
{
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut iterated = false;

    // Check for new transactions to sign
    loop {
      let mut txn = self.db.txn();
      let Some(tx) = TransactionsToSign::<Sch::SignableTransaction>::try_recv(
        &mut txn,
        &self.keys[0].group_key(),
      ) else {
        break;
      };
      iterated = true;

      let mut machines = Vec::with_capacity(self.keys.len());
      for keys in &self.keys {
        machines.push(tx.clone().sign(keys.clone()));
      }
      for msg in self.attempt_manager.register(tx.id(), machines) {
        TransactionSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
      }
      txn.commit();
    }

    // Check for completed Eventualities (meaning we should no longer sign for these transactions)
    loop {
      let mut txn = self.db.txn();
      let Some(id) = CompletedEventualitiesForEachKey::try_recv(&mut txn, self.session) else {
        break;
      };
      iterated = true;

      self.attempt_manager.retire(id);
      // TODO: Stop rebroadcasting this transaction
      txn.commit();
    }

    // Handle any messages sent to us
    loop {
      let mut txn = self.db.txn();
      let Some(msg) = CoordinatorToTransactionSignerMessages::try_recv(&mut txn, self.session)
      else {
        break;
      };
      iterated = true;

      match self.attempt_manager.handle(msg) {
        Response::Messages(msgs) => {
          for msg in msgs {
            TransactionSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
          }
        }
        Response::Signature(signed_tx) => {
          // TODO: Save this TX to the DB
          // TODO: Attempt publication every minute
          // TODO: On boot, reload all TXs to rebroadcast
          self
            .publisher
            .publish(signed_tx)
            .await
            .map_err(|e| format!("couldn't publish transaction: {e:?}"))?;
        }
      }

      txn.commit();
    }

    Ok(iterated)
  }
}
