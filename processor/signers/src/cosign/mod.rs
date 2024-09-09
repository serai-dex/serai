use ciphersuite::Ristretto;
use frost::dkg::ThresholdKeys;

use scale::Encode;
use serai_primitives::Signature;
use serai_validator_sets_primitives::Session;

use serai_db::{DbTxn, Db};

use messages::{sign::VariantSignId, coordinator::cosign_block_msg};

use primitives::task::ContinuallyRan;

use frost_attempt_manager::*;

use crate::{
  db::{ToCosign, Cosign, CoordinatorToCosignerMessages, CosignerToCoordinatorMessages},
  WrappedSchnorrkelMachine,
};

mod db;
use db::LatestCosigned;

/// Fetches the latest cosign information and works on it.
///
/// Only the latest cosign attempt is kept. We don't work on historical attempts as later cosigns
/// supersede them.
#[allow(non_snake_case)]
pub(crate) struct CosignerTask<D: Db> {
  db: D,

  session: Session,
  keys: Vec<ThresholdKeys<Ristretto>>,

  current_cosign: Option<(u64, [u8; 32])>,
  attempt_manager: AttemptManager<D, WrappedSchnorrkelMachine>,
}

impl<D: Db> CosignerTask<D> {
  pub(crate) fn new(db: D, session: Session, keys: Vec<ThresholdKeys<Ristretto>>) -> Self {
    let attempt_manager = AttemptManager::new(
      db.clone(),
      session,
      keys.first().expect("creating a cosigner with 0 keys").params().i(),
    );

    Self { db, session, keys, current_cosign: None, attempt_manager }
  }
}

#[async_trait::async_trait]
impl<D: Db> ContinuallyRan for CosignerTask<D> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut iterated = false;

    // Check the cosign to work on
    {
      let mut txn = self.db.txn();
      if let Some(cosign) = ToCosign::get(&txn, self.session) {
        // If this wasn't already signed for...
        if LatestCosigned::get(&txn, self.session) < Some(cosign.0) {
          // If this isn't the cosign we're currently working on, meaning it's fresh
          if self.current_cosign != Some(cosign) {
            // Retire the current cosign
            if let Some(current_cosign) = self.current_cosign {
              assert!(current_cosign.0 < cosign.0);
              self.attempt_manager.retire(&mut txn, VariantSignId::Cosign(current_cosign.0));
            }

            // Set the cosign being worked on
            self.current_cosign = Some(cosign);

            let mut machines = Vec::with_capacity(self.keys.len());
            {
              let message = cosign_block_msg(cosign.0, cosign.1);
              for keys in &self.keys {
                machines.push(WrappedSchnorrkelMachine::new(keys.clone(), message.clone()));
              }
            }
            for msg in self.attempt_manager.register(VariantSignId::Cosign(cosign.0), machines) {
              CosignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
            }

            txn.commit();
          }
        }
      }
    }

    // Handle any messages sent to us
    loop {
      let mut txn = self.db.txn();
      let Some(msg) = CoordinatorToCosignerMessages::try_recv(&mut txn, self.session) else {
        break;
      };
      iterated = true;

      match self.attempt_manager.handle(msg) {
        Response::Messages(msgs) => {
          for msg in msgs {
            CosignerToCoordinatorMessages::send(&mut txn, self.session, &msg);
          }
        }
        Response::Signature { id, signature } => {
          let VariantSignId::Cosign(block_number) = id else {
            panic!("CosignerTask signed a non-Cosign")
          };
          assert_eq!(Some(block_number), self.current_cosign.map(|cosign| cosign.0));

          let cosign = self.current_cosign.take().unwrap();
          LatestCosigned::set(&mut txn, self.session, &cosign.0);
          // Send the cosign
          Cosign::send(&mut txn, self.session, &(cosign, Signature::from(signature).encode()));
        }
      }

      txn.commit();
    }

    Ok(iterated)
  }
}
