use core::fmt;
use std::collections::HashMap;

use rand_core::OsRng;

use frost::{
  curve::Ristretto,
  ThresholdKeys, FrostError,
  algorithm::Algorithm,
  sign::{
    Writable, PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine,
    AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};
use frost_schnorrkel::Schnorrkel;

use log::{info, warn};

use serai_client::{
  Public,
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, report_slashes_message},
};

use messages::coordinator::*;
use crate::{Get, DbTxn, create_db};

create_db! {
  SlashReportSignerDb {
    Completed: (session: Session) -> (),
    Attempt: (session: Session, attempt: u32) -> (),
  }
}

type Preprocess = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Preprocess;
type SignatureShare = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<
  <Schnorrkel as Algorithm<Ristretto>>::Signature,
>>::SignatureShare;

pub struct SlashReportSigner {
  network: NetworkId,
  session: Session,
  keys: Vec<ThresholdKeys<Ristretto>>,
  report: Vec<([u8; 32], u32)>,

  attempt: u32,
  #[allow(clippy::type_complexity)]
  preprocessing: Option<(Vec<AlgorithmSignMachine<Ristretto, Schnorrkel>>, Vec<Preprocess>)>,
  #[allow(clippy::type_complexity)]
  signing: Option<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, Vec<SignatureShare>)>,
}

impl fmt::Debug for SlashReportSigner {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("SlashReportSigner")
      .field("session", &self.session)
      .field("report", &self.report)
      .field("attempt", &self.attempt)
      .field("preprocessing", &self.preprocessing.is_some())
      .field("signing", &self.signing.is_some())
      .finish_non_exhaustive()
  }
}

impl SlashReportSigner {
  pub fn new(
    txn: &mut impl DbTxn,
    network: NetworkId,
    session: Session,
    keys: Vec<ThresholdKeys<Ristretto>>,
    report: Vec<([u8; 32], u32)>,
    attempt: u32,
  ) -> Option<(SlashReportSigner, ProcessorMessage)> {
    assert!(!keys.is_empty());

    if Completed::get(txn, session).is_some() {
      return None;
    }

    if Attempt::get(txn, session, attempt).is_some() {
      warn!(
        "already attempted signing slash report for session {:?}, attempt #{}. {}",
        session, attempt, "this is an error if we didn't reboot",
      );
      return None;
    }
    Attempt::set(txn, session, attempt, &());

    info!("signing slash report for session {:?} with attempt #{}", session, attempt);

    let mut machines = vec![];
    let mut preprocesses = vec![];
    let mut serialized_preprocesses = vec![];
    for keys in &keys {
      // b"substrate" is a literal from sp-core
      let machine = AlgorithmMachine::new(Schnorrkel::new(b"substrate"), keys.clone());

      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      machines.push(machine);
      serialized_preprocesses.push(preprocess.serialize().try_into().unwrap());
      preprocesses.push(preprocess);
    }
    let preprocessing = Some((machines, preprocesses));

    let substrate_sign_id =
      SubstrateSignId { session, id: SubstrateSignableId::SlashReport, attempt };

    Some((
      SlashReportSigner { network, session, keys, report, attempt, preprocessing, signing: None },
      ProcessorMessage::SlashReportPreprocess {
        id: substrate_sign_id,
        preprocesses: serialized_preprocesses,
      },
    ))
  }

  #[must_use]
  pub fn handle(
    &mut self,
    txn: &mut impl DbTxn,
    msg: CoordinatorMessage,
  ) -> Option<ProcessorMessage> {
    match msg {
      CoordinatorMessage::CosignSubstrateBlock { .. } => {
        panic!("SlashReportSigner passed CosignSubstrateBlock")
      }

      CoordinatorMessage::SignSlashReport { .. } => {
        panic!("SlashReportSigner passed SignSlashReport")
      }

      CoordinatorMessage::SubstratePreprocesses { id, preprocesses } => {
        assert_eq!(id.session, self.session);
        assert_eq!(id.id, SubstrateSignableId::SlashReport);
        if id.attempt != self.attempt {
          panic!("given preprocesses for a distinct attempt than SlashReportSigner is signing")
        }

        let (machines, our_preprocesses) = match self.preprocessing.take() {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!("not preprocessing. this is an error if we didn't reboot");
            return None;
          }
          Some(preprocess) => preprocess,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = preprocesses.keys().copied().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut preprocess_ref = preprocesses.get(&l).unwrap().as_slice();
          let Ok(res) = machines[0].read_preprocess(&mut preprocess_ref) else {
            return Some(ProcessorMessage::InvalidParticipant { id, participant: l });
          };
          if !preprocess_ref.is_empty() {
            return Some(ProcessorMessage::InvalidParticipant { id, participant: l });
          }
          parsed.insert(l, res);
        }
        let preprocesses = parsed;

        // Only keep a single machine as we only need one to get the signature
        let mut signature_machine = None;
        let mut shares = vec![];
        let mut serialized_shares = vec![];
        for (m, machine) in machines.into_iter().enumerate() {
          let mut preprocesses = preprocesses.clone();
          for (i, our_preprocess) in our_preprocesses.clone().into_iter().enumerate() {
            if i != m {
              assert!(preprocesses.insert(self.keys[i].params().i(), our_preprocess).is_none());
            }
          }

          let (machine, share) = match machine.sign(
            preprocesses,
            &report_slashes_message(
              &ValidatorSet { network: self.network, session: self.session },
              &self
                .report
                .clone()
                .into_iter()
                .map(|(validator, points)| (Public(validator), points))
                .collect::<Vec<_>>(),
            ),
          ) {
            Ok(res) => res,
            Err(e) => match e {
              FrostError::InternalError(_) |
              FrostError::InvalidParticipant(_, _) |
              FrostError::InvalidSigningSet(_) |
              FrostError::InvalidParticipantQuantity(_, _) |
              FrostError::DuplicatedParticipant(_) |
              FrostError::MissingParticipant(_) => unreachable!(),

              FrostError::InvalidPreprocess(l) | FrostError::InvalidShare(l) => {
                return Some(ProcessorMessage::InvalidParticipant { id, participant: l })
              }
            },
          };
          if m == 0 {
            signature_machine = Some(machine);
          }

          let mut share_bytes = [0; 32];
          share_bytes.copy_from_slice(&share.serialize());
          serialized_shares.push(share_bytes);

          shares.push(share);
        }
        self.signing = Some((signature_machine.unwrap(), shares));

        // Broadcast our shares
        Some(ProcessorMessage::SubstrateShare { id, shares: serialized_shares })
      }

      CoordinatorMessage::SubstrateShares { id, shares } => {
        assert_eq!(id.session, self.session);
        assert_eq!(id.id, SubstrateSignableId::SlashReport);
        if id.attempt != self.attempt {
          panic!("given preprocesses for a distinct attempt than SlashReportSigner is signing")
        }

        let (machine, our_shares) = match self.signing.take() {
          // Rebooted, RPC error, or some invariant
          None => {
            // If preprocessing has this ID, it means we were never sent the preprocess by the
            // coordinator
            if self.preprocessing.is_some() {
              panic!("never preprocessed yet signing?");
            }

            warn!("not preprocessing. this is an error if we didn't reboot");
            return None;
          }
          Some(signing) => signing,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = shares.keys().copied().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut share_ref = shares.get(&l).unwrap().as_slice();
          let Ok(res) = machine.read_share(&mut share_ref) else {
            return Some(ProcessorMessage::InvalidParticipant { id, participant: l });
          };
          if !share_ref.is_empty() {
            return Some(ProcessorMessage::InvalidParticipant { id, participant: l });
          }
          parsed.insert(l, res);
        }
        let mut shares = parsed;

        for (i, our_share) in our_shares.into_iter().enumerate().skip(1) {
          assert!(shares.insert(self.keys[i].params().i(), our_share).is_none());
        }

        let sig = match machine.complete(shares) {
          Ok(res) => res,
          Err(e) => match e {
            FrostError::InternalError(_) |
            FrostError::InvalidParticipant(_, _) |
            FrostError::InvalidSigningSet(_) |
            FrostError::InvalidParticipantQuantity(_, _) |
            FrostError::DuplicatedParticipant(_) |
            FrostError::MissingParticipant(_) => unreachable!(),

            FrostError::InvalidPreprocess(l) | FrostError::InvalidShare(l) => {
              return Some(ProcessorMessage::InvalidParticipant { id, participant: l })
            }
          },
        };

        info!("signed slash report for session {:?} with attempt #{}", self.session, id.attempt);

        Completed::set(txn, self.session, &());

        Some(ProcessorMessage::SignedSlashReport {
          session: self.session,
          signature: sig.to_bytes().to_vec(),
        })
      }
      CoordinatorMessage::BatchReattempt { .. } => {
        panic!("BatchReattempt passed to SlashReportSigner")
      }
    }
  }
}
