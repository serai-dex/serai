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

use serai_client::validator_sets::primitives::Session;

use messages::coordinator::*;
use crate::{Get, DbTxn, create_db};

create_db! {
  CosignerDb {
    Completed: (id: [u8; 32]) -> (),
    Attempt: (id: [u8; 32], attempt: u32) -> (),
  }
}

type Preprocess = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Preprocess;
type SignatureShare = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<
  <Schnorrkel as Algorithm<Ristretto>>::Signature,
>>::SignatureShare;

pub struct Cosigner {
  session: Session,
  keys: Vec<ThresholdKeys<Ristretto>>,

  block_number: u64,
  id: [u8; 32],
  attempt: u32,
  #[allow(clippy::type_complexity)]
  preprocessing: Option<(Vec<AlgorithmSignMachine<Ristretto, Schnorrkel>>, Vec<Preprocess>)>,
  #[allow(clippy::type_complexity)]
  signing: Option<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, Vec<SignatureShare>)>,
}

impl fmt::Debug for Cosigner {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("Cosigner")
      .field("session", &self.session)
      .field("block_number", &self.block_number)
      .field("id", &self.id)
      .field("attempt", &self.attempt)
      .field("preprocessing", &self.preprocessing.is_some())
      .field("signing", &self.signing.is_some())
      .finish_non_exhaustive()
  }
}

impl Cosigner {
  pub fn new(
    txn: &mut impl DbTxn,
    session: Session,
    keys: Vec<ThresholdKeys<Ristretto>>,
    block_number: u64,
    id: [u8; 32],
    attempt: u32,
  ) -> Option<(Cosigner, ProcessorMessage)> {
    assert!(!keys.is_empty());

    if Completed::get(txn, id).is_some() {
      return None;
    }

    if Attempt::get(txn, id, attempt).is_some() {
      warn!(
        "already attempted cosigning {}, attempt #{}. this is an error if we didn't reboot",
        hex::encode(id),
        attempt,
      );
      return None;
    }
    Attempt::set(txn, id, attempt, &());

    info!("cosigning block {} with attempt #{}", hex::encode(id), attempt);

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
      SubstrateSignId { session, id: SubstrateSignableId::CosigningSubstrateBlock(id), attempt };

    Some((
      Cosigner { session, keys, block_number, id, attempt, preprocessing, signing: None },
      ProcessorMessage::CosignPreprocess {
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
        panic!("Cosigner passed CosignSubstrateBlock")
      }

      CoordinatorMessage::SubstratePreprocesses { id, preprocesses } => {
        assert_eq!(id.session, self.session);
        let SubstrateSignableId::CosigningSubstrateBlock(block) = id.id else {
          panic!("cosigner passed Batch")
        };
        if block != self.id {
          panic!("given preprocesses for a distinct block than cosigner is signing")
        }
        if id.attempt != self.attempt {
          panic!("given preprocesses for a distinct attempt than cosigner is signing")
        }

        let (machines, our_preprocesses) = match self.preprocessing.take() {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(block),
            );
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

          let (machine, share) =
            match machine.sign(preprocesses, &cosign_block_msg(self.block_number, self.id)) {
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
        let SubstrateSignableId::CosigningSubstrateBlock(block) = id.id else {
          panic!("cosigner passed Batch")
        };
        if block != self.id {
          panic!("given preprocesses for a distinct block than cosigner is signing")
        }
        if id.attempt != self.attempt {
          panic!("given preprocesses for a distinct attempt than cosigner is signing")
        }

        let (machine, our_shares) = match self.signing.take() {
          // Rebooted, RPC error, or some invariant
          None => {
            // If preprocessing has this ID, it means we were never sent the preprocess by the
            // coordinator
            if self.preprocessing.is_some() {
              panic!("never preprocessed yet signing?");
            }

            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(block)
            );
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

        info!("cosigned {} with attempt #{}", hex::encode(block), id.attempt);

        Completed::set(txn, block, &());

        Some(ProcessorMessage::CosignedBlock {
          block_number: self.block_number,
          block,
          signature: sig.to_bytes().to_vec(),
        })
      }
      CoordinatorMessage::BatchReattempt { .. } => panic!("BatchReattempt passed to Cosigner"),
    }
  }
}
