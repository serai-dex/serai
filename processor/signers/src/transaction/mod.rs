use serai_db::{Get, DbTxn, Db};

use primitives::task::ContinuallyRan;
use scanner::ScannerFeed;
use scheduler::TransactionsToSign;

mod db;
use db::IndexDb;

// Fetches transactions to sign and signs them.
pub(crate) struct TransactionTask<D: Db, S: ScannerFeed, Sch: Scheduler> {
  db: D,
  keys: ThresholdKeys<<Sch::SignableTransaction as SignableTransaction>::Ciphersuite>,
  attempt_manager:
    AttemptManager<D, <Sch::SignableTransaction as SignableTransaction>::PreprocessMachine>,
}

impl<D: Db, S: ScannerFeed> TransactionTask<D, S> {
  pub(crate) async fn new(
    db: D,
    keys: ThresholdKeys<<Sch::SignableTransaction as SignableTransaction>::Ciphersuite>,
  ) -> Self {
    Self { db, keys, attempt_manager: AttemptManager::new() }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for TransactionTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut iterated = false;

    // Check for new transactions to sign
    loop {
      let mut txn = self.db.txn();
      let Some(tx) = TransactionsToSign::try_recv(&mut txn, self.key) else { break };
      iterated = true;

      let mut machines = Vec::with_capacity(self.keys.len());
      for keys in &self.keys {
        machines.push(tx.clone().sign(keys.clone()));
      }
      let messages = self.attempt_manager.register(tx.id(), machines);
      todo!("TODO");
      txn.commit();
    }

    // Check for completed Eventualities (meaning we should no longer sign for these transactions)
    loop {
      let mut txn = self.db.txn();
      let Some(tx) = CompletedEventualities::try_recv(&mut txn, self.key) else { break };
      iterated = true;

      self.attempt_manager.retire(tx);
      txn.commit();
    }

    loop {
      let mut txn = self.db.txn();
      let Some(msg) = TransactionSignMessages::try_recv(&mut txn, self.key) else { break };
      iterated = true;

      match self.attempt_manager.handle(msg) {
        Response::Messages(messages) => todo!("TODO"),
        Response::Signature(signature) => todo!("TODO"),
      }
    }

    Ok(iterated)
  }
}
