use core::{marker::PhantomData, fmt};
use std::collections::HashMap;

use rand_core::OsRng;
use frost::{
  ThresholdKeys, FrostError,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use log::{info, debug, warn, error};

use serai_client::validator_sets::primitives::Session;
use messages::sign::*;

pub use serai_db::*;

use crate::{
  Get, DbTxn, Db,
  networks::{Eventuality, Network},
};

create_db!(
  SignerDb {
    CompletionsDb: (id: [u8; 32]) -> Vec<u8>,
    EventualityDb: (id: [u8; 32]) -> Vec<u8>,
    AttemptDb: (id: &SignId) -> (),
    CompletionDb: (claim: &[u8]) -> Vec<u8>,
    ActiveSignsDb: () -> Vec<[u8; 32]>,
    CompletedOnChainDb: (id: &[u8; 32]) -> (),
  }
);

impl ActiveSignsDb {
  fn add_active_sign(txn: &mut impl DbTxn, id: &[u8; 32]) {
    if CompletedOnChainDb::get(txn, id).is_some() {
      return;
    }
    let mut active = ActiveSignsDb::get(txn).unwrap_or_default();
    active.push(*id);
    ActiveSignsDb::set(txn, &active);
  }
}

impl CompletedOnChainDb {
  fn complete_on_chain(txn: &mut impl DbTxn, id: &[u8; 32]) {
    CompletedOnChainDb::set(txn, id, &());
    ActiveSignsDb::set(
      txn,
      &ActiveSignsDb::get(txn)
        .unwrap_or_default()
        .into_iter()
        .filter(|active| active != id)
        .collect::<Vec<_>>(),
    );
  }
}
impl CompletionsDb {
  fn completions<N: Network>(
    getter: &impl Get,
    id: [u8; 32],
  ) -> Vec<<N::Eventuality as Eventuality>::Claim> {
    let Some(completions) = Self::get(getter, id) else { return vec![] };

    // If this was set yet is empty, it's because it's the encoding of a claim with a length of 0
    if completions.is_empty() {
      let default = <N::Eventuality as Eventuality>::Claim::default();
      assert_eq!(default.as_ref().len(), 0);
      return vec![default];
    }

    let mut completions_ref = completions.as_slice();
    let mut res = vec![];
    while !completions_ref.is_empty() {
      let mut id = <N::Eventuality as Eventuality>::Claim::default();
      let id_len = id.as_ref().len();
      id.as_mut().copy_from_slice(&completions_ref[.. id_len]);
      completions_ref = &completions_ref[id_len ..];
      res.push(id);
    }
    res
  }

  fn complete<N: Network>(
    txn: &mut impl DbTxn,
    id: [u8; 32],
    completion: &<N::Eventuality as Eventuality>::Completion,
  ) {
    // Completions can be completed by multiple signatures
    // Save every solution in order to be robust
    CompletionDb::save_completion::<N>(txn, completion);

    let claim = N::Eventuality::claim(completion);
    let claim: &[u8] = claim.as_ref();

    // If claim has a 0-byte encoding, the set key, even if empty, is the claim
    if claim.is_empty() {
      Self::set(txn, id, &vec![]);
      return;
    }

    let mut existing = Self::get(txn, id).unwrap_or_default();
    assert_eq!(existing.len() % claim.len(), 0);

    // Don't add this completion if it's already present
    let mut i = 0;
    while i < existing.len() {
      if &existing[i .. (i + claim.len())] == claim {
        return;
      }
      i += claim.len();
    }

    existing.extend(claim);
    Self::set(txn, id, &existing);
  }
}

impl EventualityDb {
  fn save_eventuality<N: Network>(
    txn: &mut impl DbTxn,
    id: [u8; 32],
    eventuality: &N::Eventuality,
  ) {
    txn.put(Self::key(id), eventuality.serialize());
  }

  fn eventuality<N: Network>(getter: &impl Get, id: [u8; 32]) -> Option<N::Eventuality> {
    Some(N::Eventuality::read(&mut getter.get(Self::key(id))?.as_slice()).unwrap())
  }
}

impl CompletionDb {
  fn save_completion<N: Network>(
    txn: &mut impl DbTxn,
    completion: &<N::Eventuality as Eventuality>::Completion,
  ) {
    let claim = N::Eventuality::claim(completion);
    let claim: &[u8] = claim.as_ref();
    Self::set(txn, claim, &N::Eventuality::serialize_completion(completion));
  }

  fn completion<N: Network>(
    getter: &impl Get,
    claim: &<N::Eventuality as Eventuality>::Claim,
  ) -> Option<<N::Eventuality as Eventuality>::Completion> {
    Self::get(getter, claim.as_ref())
      .map(|completion| N::Eventuality::read_completion::<&[u8]>(&mut completion.as_ref()).unwrap())
  }
}

type PreprocessFor<N> = <<N as Network>::TransactionMachine as PreprocessMachine>::Preprocess;
type SignMachineFor<N> = <<N as Network>::TransactionMachine as PreprocessMachine>::SignMachine;
type SignatureShareFor<N> = <SignMachineFor<N> as SignMachine<
  <<N as Network>::Eventuality as Eventuality>::Completion,
>>::SignatureShare;
type SignatureMachineFor<N> = <SignMachineFor<N> as SignMachine<
  <<N as Network>::Eventuality as Eventuality>::Completion,
>>::SignatureMachine;

pub struct Signer<N: Network, D: Db> {
  db: PhantomData<D>,

  network: N,

  session: Session,
  keys: Vec<ThresholdKeys<N::Curve>>,

  signable: HashMap<[u8; 32], N::SignableTransaction>,
  attempt: HashMap<[u8; 32], u32>,
  #[allow(clippy::type_complexity)]
  preprocessing: HashMap<[u8; 32], (Vec<SignMachineFor<N>>, Vec<PreprocessFor<N>>)>,
  #[allow(clippy::type_complexity)]
  signing: HashMap<[u8; 32], (SignatureMachineFor<N>, Vec<SignatureShareFor<N>>)>,
}

impl<N: Network, D: Db> fmt::Debug for Signer<N, D> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("Signer")
      .field("network", &self.network)
      .field("signable", &self.signable)
      .field("attempt", &self.attempt)
      .finish_non_exhaustive()
  }
}

impl<N: Network, D: Db> Signer<N, D> {
  /// Rebroadcast already signed TXs which haven't had their completions mined into a sufficiently
  /// confirmed block.
  pub async fn rebroadcast_task(db: D, network: N) {
    log::info!("rebroadcasting transactions for plans whose completions yet to be confirmed...");
    loop {
      for active in ActiveSignsDb::get(&db).unwrap_or_default() {
        for claim in CompletionsDb::completions::<N>(&db, active) {
          log::info!("rebroadcasting completion with claim {}", hex::encode(claim.as_ref()));
          // TODO: Don't drop the error entirely. Check for invariants
          let _ =
            network.publish_completion(&CompletionDb::completion::<N>(&db, &claim).unwrap()).await;
        }
      }
      // Only run every five minutes so we aren't frequently loading tens to hundreds of KB from
      // the DB
      tokio::time::sleep(core::time::Duration::from_secs(5 * 60)).await;
    }
  }
  pub fn new(network: N, session: Session, keys: Vec<ThresholdKeys<N::Curve>>) -> Signer<N, D> {
    assert!(!keys.is_empty());
    Signer {
      db: PhantomData,

      network,

      session,
      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),
    }
  }

  fn verify_id(&self, id: &SignId) -> Result<(), ()> {
    // Check the attempt lines up
    match self.attempt.get(&id.id) {
      // If we don't have an attempt logged, it's because the coordinator is faulty OR because we
      // rebooted OR we detected the signed transaction on chain, so there's notable network
      // latency/a malicious validator
      None => {
        warn!(
          "not attempting {} #{}. this is an error if we didn't reboot",
          hex::encode(id.id),
          id.attempt
        );
        Err(())?;
      }
      Some(attempt) => {
        if attempt != &id.attempt {
          warn!(
            "sent signing data for {} #{} yet we have attempt #{}",
            hex::encode(id.id),
            id.attempt,
            attempt
          );
          Err(())?;
        }
      }
    }

    Ok(())
  }

  #[must_use]
  fn already_completed(txn: &mut D::Transaction<'_>, id: [u8; 32]) -> bool {
    if !CompletionsDb::completions::<N>(txn, id).is_empty() {
      debug!(
        "SignTransaction/Reattempt order for {}, which we've already completed signing",
        hex::encode(id)
      );

      true
    } else {
      false
    }
  }

  #[must_use]
  fn complete(
    &mut self,
    id: [u8; 32],
    claim: &<N::Eventuality as Eventuality>::Claim,
  ) -> ProcessorMessage {
    // Assert we're actively signing for this TX
    assert!(self.signable.remove(&id).is_some(), "completed a TX we weren't signing for");
    assert!(self.attempt.remove(&id).is_some(), "attempt had an ID signable didn't have");
    // If we weren't selected to participate, we'll have a preprocess
    self.preprocessing.remove(&id);
    // If we were selected, the signature will only go through if we contributed a share
    // Despite this, we then need to get everyone's shares, and we may get a completion before
    // we get everyone's shares
    // This would be if the coordinator fails and we find the eventuality completion on-chain
    self.signing.remove(&id);

    // Emit the event for it
    ProcessorMessage::Completed { session: self.session, id, tx: claim.as_ref().to_vec() }
  }

  #[must_use]
  pub fn completed(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    completion: &<N::Eventuality as Eventuality>::Completion,
  ) -> Option<ProcessorMessage> {
    let first_completion = !Self::already_completed(txn, id);

    // Save this completion to the DB
    CompletedOnChainDb::complete_on_chain(txn, &id);
    CompletionsDb::complete::<N>(txn, id, completion);

    if first_completion {
      Some(self.complete(id, &N::Eventuality::claim(completion)))
    } else {
      None
    }
  }

  /// Returns Some if the first completion.
  // Doesn't use any loops/retries since we'll eventually get this from the Scanner anyways
  #[must_use]
  async fn claimed_eventuality_completion(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    claim: &<N::Eventuality as Eventuality>::Claim,
  ) -> Option<ProcessorMessage> {
    if let Some(eventuality) = EventualityDb::eventuality::<N>(txn, id) {
      match self.network.confirm_completion(&eventuality, claim).await {
        Ok(Some(completion)) => {
          info!(
            "signer eventuality for {} resolved in {}",
            hex::encode(id),
            hex::encode(claim.as_ref())
          );

          let first_completion = !Self::already_completed(txn, id);

          // Save this completion to the DB
          CompletionsDb::complete::<N>(txn, id, &completion);

          if first_completion {
            return Some(self.complete(id, claim));
          }
        }
        Ok(None) => {
          warn!(
            "a validator claimed {} completed {} when it did not",
            hex::encode(claim.as_ref()),
            hex::encode(id),
          );
        }
        Err(_) => {
          // Transaction hasn't hit our mempool/was dropped for a different signature
          // The latter can happen given certain latency conditions/a single malicious signer
          // In the case of a single malicious signer, they can drag multiple honest validators down
          // with them, so we unfortunately can't slash on this case
          warn!(
            "a validator claimed {} completed {} yet we couldn't check that claim",
            hex::encode(claim.as_ref()),
            hex::encode(id),
          );
        }
      }
    } else {
      warn!(
        "informed of completion {} for eventuality {}, when we didn't have that eventuality",
        hex::encode(claim.as_ref()),
        hex::encode(id),
      );
    }
    None
  }

  #[must_use]
  async fn attempt(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    attempt: u32,
  ) -> Option<ProcessorMessage> {
    if Self::already_completed(txn, id) {
      return None;
    }

    // Check if we're already working on this attempt
    if let Some(curr_attempt) = self.attempt.get(&id) {
      if curr_attempt >= &attempt {
        warn!(
          "told to attempt {} #{} yet we're already working on {}",
          hex::encode(id),
          attempt,
          curr_attempt
        );
        return None;
      }
    }

    // Start this attempt
    // Clone the TX so we don't have an immutable borrow preventing the below mutable actions
    // (also because we do need an owned tx anyways)
    let Some(tx) = self.signable.get(&id).cloned() else {
      warn!("told to attempt a TX we aren't currently signing for");
      return None;
    };

    // Delete any existing machines
    self.preprocessing.remove(&id);
    self.signing.remove(&id);

    // Update the attempt number
    self.attempt.insert(id, attempt);

    let id = SignId { session: self.session, id, attempt };

    info!("signing for {} #{}", hex::encode(id.id), id.attempt);

    // If we reboot mid-sign, the current design has us abort all signs and wait for latter
    // attempts/new signing protocols
    // This is distinct from the DKG which will continue DKG sessions, even on reboot
    // This is because signing is tolerant of failures of up to 1/3rd of the group
    // The DKG requires 100% participation
    // While we could apply similar tricks as the DKG (a seeded RNG) to achieve support for
    // reboots, it's not worth the complexity when messing up here leaks our secret share
    //
    // Despite this, on reboot, we'll get told of active signing items, and may be in this
    // branch again for something we've already attempted
    //
    // Only run if this hasn't already been attempted
    // TODO: This isn't complete as this txn may not be committed with the expected timing
    if AttemptDb::get(txn, &id).is_some() {
      warn!(
        "already attempted {} #{}. this is an error if we didn't reboot",
        hex::encode(id.id),
        id.attempt
      );
      return None;
    }
    AttemptDb::set(txn, &id, &());

    // Attempt to create the TX
    let mut machines = vec![];
    let mut preprocesses = vec![];
    let mut serialized_preprocesses = vec![];
    for keys in &self.keys {
      let machine = match self.network.attempt_send(keys.clone(), tx.clone()).await {
        Err(e) => {
          error!("failed to attempt {}, #{}: {:?}", hex::encode(id.id), id.attempt, e);
          return None;
        }
        Ok(machine) => machine,
      };

      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      machines.push(machine);
      serialized_preprocesses.push(preprocess.serialize());
      preprocesses.push(preprocess);
    }

    self.preprocessing.insert(id.id, (machines, preprocesses));

    // Broadcast our preprocess
    Some(ProcessorMessage::Preprocess { id, preprocesses: serialized_preprocesses })
  }

  #[must_use]
  pub async fn sign_transaction(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    tx: N::SignableTransaction,
    eventuality: &N::Eventuality,
  ) -> Option<ProcessorMessage> {
    // The caller is expected to re-issue sign orders on reboot
    // This is solely used by the rebroadcast task
    ActiveSignsDb::add_active_sign(txn, &id);

    if Self::already_completed(txn, id) {
      return None;
    }

    EventualityDb::save_eventuality::<N>(txn, id, eventuality);

    self.signable.insert(id, tx);
    self.attempt(txn, id, 0).await
  }

  #[must_use]
  pub async fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> Option<ProcessorMessage> {
    match msg {
      CoordinatorMessage::Preprocesses { id, preprocesses } => {
        if self.verify_id(&id).is_err() {
          return None;
        }

        let (machines, our_preprocesses) = match self.preprocessing.remove(&id.id) {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id)
            );
            return None;
          }
          Some(machine) => machine,
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

          // Use an empty message, as expected of TransactionMachines
          let (machine, share) = match machine.sign(preprocesses, &[]) {
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
          serialized_shares.push(share.serialize());
          shares.push(share);
        }
        self.signing.insert(id.id, (signature_machine.unwrap(), shares));

        // Broadcast our shares
        Some(ProcessorMessage::Share { id, shares: serialized_shares })
      }

      CoordinatorMessage::Shares { id, shares } => {
        if self.verify_id(&id).is_err() {
          return None;
        }

        let (machine, our_shares) = match self.signing.remove(&id.id) {
          // Rebooted, RPC error, or some invariant
          None => {
            // If preprocessing has this ID, it means we were never sent the preprocess by the
            // coordinator
            if self.preprocessing.contains_key(&id.id) {
              panic!("never preprocessed yet signing?");
            }

            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id)
            );
            return None;
          }
          Some(machine) => machine,
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

        let completion = match machine.complete(shares) {
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

        // Save the completion in case it's needed for recovery
        CompletionsDb::complete::<N>(txn, id.id, &completion);

        // Publish it
        if let Err(e) = self.network.publish_completion(&completion).await {
          error!("couldn't publish completion for plan {}: {:?}", hex::encode(id.id), e);
        } else {
          info!("published completion for plan {}", hex::encode(id.id));
        }

        // Stop trying to sign for this TX
        Some(self.complete(id.id, &N::Eventuality::claim(&completion)))
      }

      CoordinatorMessage::Reattempt { id } => self.attempt(txn, id.id, id.attempt).await,

      CoordinatorMessage::Completed { session: _, id, tx: mut claim_vec } => {
        let mut claim = <N::Eventuality as Eventuality>::Claim::default();
        if claim.as_ref().len() != claim_vec.len() {
          let true_len = claim_vec.len();
          claim_vec.truncate(2 * claim.as_ref().len());
          warn!(
            "a validator claimed {}... (actual length {}) completed {} yet {}",
            hex::encode(&claim_vec),
            true_len,
            hex::encode(id),
            "that's not a valid Claim",
          );
          return None;
        }
        claim.as_mut().copy_from_slice(&claim_vec);

        self.claimed_eventuality_completion(txn, id, &claim).await
      }
    }
  }
}
