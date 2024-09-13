use core::{marker::PhantomData, future::Future};

use ciphersuite::Ristretto;
use frost::dkg::ThresholdKeys;

use scale::Encode;
use serai_primitives::Signature;
use serai_validator_sets_primitives::{
  Session, ValidatorSet, SlashReport as SlashReportStruct, report_slashes_message,
};

use serai_db::{DbTxn, Db};

use messages::sign::VariantSignId;

use primitives::task::ContinuallyRan;
use scanner::ScannerFeed;

use frost_attempt_manager::*;

use crate::{
  db::{
    SlashReport, SlashReportSignature, CoordinatorToSlashReportSignerMessages,
    SlashReportSignerToCoordinatorMessages,
  },
  WrappedSchnorrkelMachine,
};

// Fetches slash reports to sign and signs them.
#[allow(non_snake_case)]
pub(crate) struct SlashReportSignerTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,

  session: Session,
  keys: Vec<ThresholdKeys<Ristretto>>,

  has_slash_report: bool,
  attempt_manager: AttemptManager<D, WrappedSchnorrkelMachine>,
}

impl<D: Db, S: ScannerFeed> SlashReportSignerTask<D, S> {
  pub(crate) fn new(db: D, session: Session, keys: Vec<ThresholdKeys<Ristretto>>) -> Self {
    let attempt_manager = AttemptManager::new(
      db.clone(),
      session,
      keys.first().expect("creating a slash report signer with 0 keys").params().i(),
    );

    Self { db, _S: PhantomData, session, keys, has_slash_report: false, attempt_manager }
  }
}

impl<D: Db, S: ScannerFeed> ContinuallyRan for SlashReportSignerTask<D, S> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut iterated = false;

      // Check for the slash report to sign
      if !self.has_slash_report {
        let mut txn = self.db.txn();
        let Some(slash_report) = SlashReport::try_recv(&mut txn, self.session) else {
          return Ok(false);
        };
        // We only commit this upon successfully signing this slash report
        drop(txn);
        iterated = true;

        self.has_slash_report = true;

        let mut machines = Vec::with_capacity(self.keys.len());
        {
          let message = report_slashes_message(
            &ValidatorSet { network: S::NETWORK, session: self.session },
            &SlashReportStruct(slash_report.try_into().unwrap()),
          );
          for keys in &self.keys {
            machines.push(WrappedSchnorrkelMachine::new(keys.clone(), message.clone()));
          }
        }
        let mut txn = self.db.txn();
        for msg in self.attempt_manager.register(VariantSignId::SlashReport(self.session), machines)
        {
          SlashReportSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
        }
        txn.commit();
      }

      // Handle any messages sent to us
      loop {
        let mut txn = self.db.txn();
        let Some(msg) = CoordinatorToSlashReportSignerMessages::try_recv(&mut txn, self.session)
        else {
          break;
        };
        iterated = true;

        match self.attempt_manager.handle(msg) {
          Response::Messages(msgs) => {
            for msg in msgs {
              SlashReportSignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
            }
          }
          Response::Signature { id, signature } => {
            let VariantSignId::SlashReport(session) = id else {
              panic!("SlashReportSignerTask signed a non-SlashReport")
            };
            assert_eq!(session, self.session);
            // Drain the channel
            SlashReport::try_recv(&mut txn, self.session).unwrap();
            // Send the signature
            SlashReportSignature::send(&mut txn, session, &Signature::from(signature).encode());
          }
        }

        txn.commit();
      }

      Ok(iterated)
    }
  }
}
