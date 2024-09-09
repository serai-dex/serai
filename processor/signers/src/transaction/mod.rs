use std::{
  collections::HashSet,
  time::{Duration, Instant},
};

use frost::dkg::ThresholdKeys;

use serai_validator_sets_primitives::Session;

use serai_db::{DbTxn, Db};

use messages::sign::VariantSignId;

use primitives::task::ContinuallyRan;
use scheduler::{Transaction, SignableTransaction, TransactionFor, TransactionsToSign};
use scanner::CompletedEventualities;

use frost_attempt_manager::*;

use crate::{
  db::{CoordinatorToTransactionSignerMessages, TransactionSignerToCoordinatorMessages},
  TransactionPublisher,
};

mod db;
use db::*;

// Fetches transactions to sign and signs them.
pub(crate) struct TransactionSignerTask<
  D: Db,
  ST: SignableTransaction,
  P: TransactionPublisher<TransactionFor<ST>>,
> {
  db: D,
  publisher: P,

  session: Session,
  keys: Vec<ThresholdKeys<ST::Ciphersuite>>,

  active_signing_protocols: HashSet<[u8; 32]>,
  attempt_manager: AttemptManager<D, <ST as SignableTransaction>::PreprocessMachine>,

  last_publication: Instant,
}

impl<D: Db, ST: SignableTransaction, P: TransactionPublisher<TransactionFor<ST>>>
  TransactionSignerTask<D, ST, P>
{
  pub(crate) fn new(
    db: D,
    publisher: P,
    session: Session,
    keys: Vec<ThresholdKeys<ST::Ciphersuite>>,
  ) -> Self {
    let mut active_signing_protocols = HashSet::new();
    let mut attempt_manager = AttemptManager::new(
      db.clone(),
      session,
      keys.first().expect("creating a transaction signer with 0 keys").params().i(),
    );

    // Re-register all active signing protocols
    for tx in ActiveSigningProtocols::get(&db, session).unwrap_or(vec![]) {
      active_signing_protocols.insert(tx);

      let signable_transaction_buf = SerializedSignableTransactions::get(&db, tx).unwrap();
      let mut signable_transaction_buf = signable_transaction_buf.as_slice();
      let signable_transaction = ST::read(&mut signable_transaction_buf).unwrap();
      assert!(signable_transaction_buf.is_empty());
      assert_eq!(signable_transaction.id(), tx);

      let mut machines = Vec::with_capacity(keys.len());
      for keys in &keys {
        machines.push(signable_transaction.clone().sign(keys.clone()));
      }
      attempt_manager.register(VariantSignId::Transaction(tx), machines);
    }

    Self {
      db,
      publisher,
      session,
      keys,
      active_signing_protocols,
      attempt_manager,
      last_publication: Instant::now(),
    }
  }
}

#[async_trait::async_trait]
impl<D: Db, ST: SignableTransaction, P: TransactionPublisher<TransactionFor<ST>>> ContinuallyRan
  for TransactionSignerTask<D, ST, P>
{
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut iterated = false;

    // Check for new transactions to sign
    loop {
      let mut txn = self.db.txn();
      let Some(tx) = TransactionsToSign::<ST>::try_recv(&mut txn, &self.keys[0].group_key()) else {
        break;
      };
      iterated = true;

      // Save this to the database as a transaction to sign
      self.active_signing_protocols.insert(tx.id());
      ActiveSigningProtocols::set(
        &mut txn,
        self.session,
        &self.active_signing_protocols.iter().copied().collect(),
      );
      {
        let mut buf = Vec::with_capacity(256);
        tx.write(&mut buf).unwrap();
        SerializedSignableTransactions::set(&mut txn, tx.id(), &buf);
      }

      let mut machines = Vec::with_capacity(self.keys.len());
      for keys in &self.keys {
        machines.push(tx.clone().sign(keys.clone()));
      }
      for msg in self.attempt_manager.register(VariantSignId::Transaction(tx.id()), machines) {
        TransactionSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
      }

      txn.commit();
    }

    // Check for completed Eventualities (meaning we should no longer sign for these transactions)
    loop {
      let mut txn = self.db.txn();
      let Some(id) = CompletedEventualities::try_recv(&mut txn, &self.keys[0].group_key()) else {
        break;
      };

      /*
        We may have yet to register this signing protocol.

        While `TransactionsToSign` is populated before `CompletedEventualities`, we could
        theoretically have `TransactionsToSign` populated with a new transaction _while iterating
        over `CompletedEventualities`_, and then have `CompletedEventualities` populated. In that
        edge case, we will see the completion notification before we see the transaction.

        In such a case, we break (dropping the txn, re-queueing the completion notification). On
        the task's next iteration, we'll process the transaction from `TransactionsToSign` and be
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
      SerializedSignableTransactions::del(&mut txn, id);
      SerializedTransactions::del(&mut txn, id);

      // We retire with a txn so we either successfully flag this Eventuality as completed, and
      // won't re-register it (making this retire safe), or we don't flag it, meaning we will
      // re-register it, yet that's safe as we have yet to retire it
      self.attempt_manager.retire(&mut txn, VariantSignId::Transaction(id));

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
        Response::Signature { id, signature: signed_tx } => {
          // Save this transaction to the database
          {
            let mut buf = Vec::with_capacity(256);
            signed_tx.write(&mut buf).unwrap();
            SerializedTransactions::set(
              &mut txn,
              match id {
                VariantSignId::Transaction(id) => id,
                _ => panic!("TransactionSignerTask signed a non-transaction"),
              },
              &buf,
            );
          }

          match self.publisher.publish(signed_tx).await {
            Ok(()) => {}
            Err(e) => log::warn!("couldn't broadcast transaction: {e:?}"),
          }
        }
      }

      txn.commit();
    }

    // If it's been five minutes since the last publication, republish the transactions for all
    // active signing protocols
    if Instant::now().duration_since(self.last_publication) > Duration::from_secs(5 * 60) {
      for tx in &self.active_signing_protocols {
        let Some(tx_buf) = SerializedTransactions::get(&self.db, *tx) else { continue };
        let mut tx_buf = tx_buf.as_slice();
        let tx = TransactionFor::<ST>::read(&mut tx_buf).unwrap();
        assert!(tx_buf.is_empty());

        self
          .publisher
          .publish(tx)
          .await
          .map_err(|e| format!("couldn't re-broadcast transactions: {e:?}"))?;
      }

      self.last_publication = Instant::now();
    }

    Ok(iterated)
  }
}
