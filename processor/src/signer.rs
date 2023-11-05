use core::{marker::PhantomData, fmt};
use std::collections::{VecDeque, HashMap};

use rand_core::OsRng;

use ciphersuite::group::GroupEncoding;
use frost::{
  ThresholdKeys,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use log::{info, debug, warn, error};

use scale::Encode;
use messages::sign::*;
use crate::{
  Get, DbTxn, Db,
  networks::{Transaction, Eventuality, Network},
};

#[derive(Debug)]
pub enum SignerEvent<N: Network> {
  SignedTransaction { id: [u8; 32], tx: <N::Transaction as Transaction<N>>::Id },
  ProcessorMessage(ProcessorMessage),
}

#[derive(Debug)]
struct SignerDb<N: Network, D: Db>(D, PhantomData<N>);
impl<N: Network, D: Db> SignerDb<N, D> {
  fn sign_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SIGNER", dst, key)
  }

  fn active_signs_key() -> Vec<u8> {
    Self::sign_key(b"active_signs", [])
  }
  fn completed_on_chain_key(id: &[u8; 32]) -> Vec<u8> {
    Self::sign_key(b"completed_on_chain", id)
  }
  fn active_signs<G: Get>(getter: &G) -> Vec<[u8; 32]> {
    let active = getter.get(Self::active_signs_key()).unwrap_or(vec![]);
    let mut active_ref = active.as_slice();
    let mut res = vec![];
    while !active_ref.is_empty() {
      res.push(active_ref[.. 32].try_into().unwrap());
      active_ref = &active_ref[32 ..];
    }
    res
  }
  fn add_active_sign(txn: &mut D::Transaction<'_>, id: &[u8; 32]) {
    if txn.get(Self::completed_on_chain_key(id)).is_some() {
      return;
    }
    let key = Self::active_signs_key();
    let mut active = txn.get(&key).unwrap_or(vec![]);
    active.extend(id);
    txn.put(key, active);
  }
  fn complete_on_chain(txn: &mut D::Transaction<'_>, id: &[u8; 32]) {
    txn.put(Self::completed_on_chain_key(id), []);
    txn.put(
      Self::active_signs_key(),
      Self::active_signs(txn)
        .into_iter()
        .filter(|active| active != id)
        .flatten()
        .collect::<Vec<_>>(),
    );
  }

  fn transaction_key(id: &<N::Transaction as Transaction<N>>::Id) -> Vec<u8> {
    Self::sign_key(b"tx", id)
  }
  fn completions_key(id: [u8; 32]) -> Vec<u8> {
    Self::sign_key(b"completed", id)
  }
  fn complete(txn: &mut D::Transaction<'_>, id: [u8; 32], tx: &N::Transaction) {
    // Transactions can be completed by multiple signatures
    // Save every solution in order to be robust
    let tx_id = tx.id();
    txn.put(Self::transaction_key(&tx_id), tx.serialize());

    let mut existing = txn.get(Self::completions_key(id)).unwrap_or(vec![]);

    // Don't add this TX if it's already present
    let tx_len = tx_id.as_ref().len();
    assert_eq!(existing.len() % tx_len, 0);

    let mut i = 0;
    while i < existing.len() {
      if &existing[i .. (i + tx_len)] == tx_id.as_ref() {
        return;
      }
      i += tx_len;
    }

    existing.extend(tx_id.as_ref());
    txn.put(Self::completions_key(id), existing);
  }
  fn completions<G: Get>(getter: &G, id: [u8; 32]) -> Vec<<N::Transaction as Transaction<N>>::Id> {
    let completions = getter.get(Self::completions_key(id)).unwrap_or(vec![]);
    let mut completions_ref = completions.as_slice();
    let mut res = vec![];
    while !completions_ref.is_empty() {
      let mut id = <N::Transaction as Transaction<N>>::Id::default();
      let id_len = id.as_ref().len();
      id.as_mut().copy_from_slice(&completions_ref[.. id_len]);
      completions_ref = &completions_ref[id_len ..];
      res.push(id);
    }
    res
  }
  fn transaction<G: Get>(
    getter: &G,
    id: <N::Transaction as Transaction<N>>::Id,
  ) -> Option<N::Transaction> {
    getter
      .get(Self::transaction_key(&id))
      .map(|tx| N::Transaction::read(&mut tx.as_slice()).unwrap())
  }

  fn eventuality_key(id: [u8; 32]) -> Vec<u8> {
    Self::sign_key(b"eventuality", id)
  }
  fn save_eventuality(txn: &mut D::Transaction<'_>, id: [u8; 32], eventuality: N::Eventuality) {
    txn.put(Self::eventuality_key(id), eventuality.serialize());
  }
  fn eventuality<G: Get>(getter: &G, id: [u8; 32]) -> Option<N::Eventuality> {
    Some(
      N::Eventuality::read::<&[u8]>(&mut getter.get(Self::eventuality_key(id))?.as_ref()).unwrap(),
    )
  }

  fn attempt_key(id: &SignId) -> Vec<u8> {
    Self::sign_key(b"attempt", id.encode())
  }
  fn attempt(txn: &mut D::Transaction<'_>, id: &SignId) {
    txn.put(Self::attempt_key(id), []);
  }
  fn has_attempt<G: Get>(getter: &G, id: &SignId) -> bool {
    getter.get(Self::attempt_key(id)).is_some()
  }
}

type PreprocessFor<N> = <<N as Network>::TransactionMachine as PreprocessMachine>::Preprocess;
type SignMachineFor<N> = <<N as Network>::TransactionMachine as PreprocessMachine>::SignMachine;
type SignatureShareFor<N> =
  <SignMachineFor<N> as SignMachine<<N as Network>::Transaction>>::SignatureShare;
type SignatureMachineFor<N> =
  <SignMachineFor<N> as SignMachine<<N as Network>::Transaction>>::SignatureMachine;

pub struct Signer<N: Network, D: Db> {
  db: PhantomData<D>,

  network: N,

  keys: Vec<ThresholdKeys<N::Curve>>,

  signable: HashMap<[u8; 32], N::SignableTransaction>,
  attempt: HashMap<[u8; 32], u32>,
  #[allow(clippy::type_complexity)]
  preprocessing: HashMap<[u8; 32], (Vec<SignMachineFor<N>>, Vec<PreprocessFor<N>>)>,
  #[allow(clippy::type_complexity)]
  signing: HashMap<[u8; 32], (SignatureMachineFor<N>, Vec<SignatureShareFor<N>>)>,

  pub events: VecDeque<SignerEvent<N>>,
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
      for active in SignerDb::<N, D>::active_signs(&db) {
        for completion in SignerDb::<N, D>::completions(&db, active) {
          log::info!("rebroadcasting {}", hex::encode(&completion));
          // TODO: Don't drop the error entirely. Check for invariants
          let _ = network
            .publish_transaction(&SignerDb::<N, D>::transaction(&db, completion).unwrap())
            .await;
        }
      }
      // Only run every five minutes so we aren't frequently loading tens to hundreds of KB from
      // the DB
      tokio::time::sleep(core::time::Duration::from_secs(5 * 60)).await;
    }
  }
  pub fn new(network: N, keys: Vec<ThresholdKeys<N::Curve>>) -> Signer<N, D> {
    assert!(!keys.is_empty());
    Signer {
      db: PhantomData,

      network,

      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),

      events: VecDeque::new(),
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

  fn already_completed(&self, txn: &mut D::Transaction<'_>, id: [u8; 32]) -> bool {
    if !SignerDb::<N, D>::completions(txn, id).is_empty() {
      debug!(
        "SignTransaction/Reattempt order for {}, which we've already completed signing",
        hex::encode(id)
      );

      true
    } else {
      false
    }
  }

  fn complete(&mut self, id: [u8; 32], tx_id: <N::Transaction as Transaction<N>>::Id) {
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
    self.events.push_back(SignerEvent::SignedTransaction { id, tx: tx_id });
  }

  pub fn completed(&mut self, txn: &mut D::Transaction<'_>, id: [u8; 32], tx: N::Transaction) {
    let first_completion = !self.already_completed(txn, id);

    // Save this completion to the DB
    SignerDb::<N, D>::complete_on_chain(txn, &id);
    SignerDb::<N, D>::complete(txn, id, &tx);

    if first_completion {
      self.complete(id, tx.id());
    }
  }

  // Doesn't use any loops/retries since we'll eventually get this from the Scanner anyways
  async fn claimed_eventuality_completion(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    tx_id: &<N::Transaction as Transaction<N>>::Id,
  ) -> bool {
    if let Some(eventuality) = SignerDb::<N, D>::eventuality(txn, id) {
      // Transaction hasn't hit our mempool/was dropped for a different signature
      // The latter can happen given certain latency conditions/a single malicious signer
      // In the case of a single malicious signer, they can drag multiple honest validators down
      // with them, so we unfortunately can't slash on this case
      let Ok(tx) = self.network.get_transaction(tx_id).await else {
        warn!(
          "a validator claimed {} completed {} yet we didn't have that TX in our mempool {}",
          hex::encode(tx_id),
          hex::encode(id),
          "(or had another connectivity issue)",
        );
        return false;
      };

      if self.network.confirm_completion(&eventuality, &tx) {
        info!("signer eventuality for {} resolved in TX {}", hex::encode(id), hex::encode(tx_id));

        let first_completion = !self.already_completed(txn, id);

        // Save this completion to the DB
        SignerDb::<N, D>::complete(txn, id, &tx);

        if first_completion {
          self.complete(id, tx.id());
          return true;
        }
      } else {
        warn!(
          "a validator claimed {} completed {} when it did not",
          hex::encode(tx_id),
          hex::encode(id)
        );
      }
    } else {
      // If we don't have this in RAM, it should be because we already finished signing it
      assert!(!SignerDb::<N, D>::completions(txn, id).is_empty());
      info!(
        "signer {} informed of the eventuality completion for plan {}, {}",
        hex::encode(self.keys[0].group_key().to_bytes()),
        hex::encode(id),
        "which we already marked as completed",
      );
    }
    false
  }

  async fn attempt(&mut self, txn: &mut D::Transaction<'_>, id: [u8; 32], attempt: u32) {
    if self.already_completed(txn, id) {
      return;
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
        return;
      }
    }

    // Start this attempt
    // Clone the TX so we don't have an immutable borrow preventing the below mutable actions
    // (also because we do need an owned tx anyways)
    let Some(tx) = self.signable.get(&id).cloned() else {
      warn!("told to attempt a TX we aren't currently signing for");
      return;
    };

    // Delete any existing machines
    self.preprocessing.remove(&id);
    self.signing.remove(&id);

    // Update the attempt number
    self.attempt.insert(id, attempt);

    let id = SignId { key: self.keys[0].group_key().to_bytes().as_ref().to_vec(), id, attempt };

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
    if SignerDb::<N, D>::has_attempt(txn, &id) {
      warn!(
        "already attempted {} #{}. this is an error if we didn't reboot",
        hex::encode(id.id),
        id.attempt
      );
      return;
    }

    SignerDb::<N, D>::attempt(txn, &id);

    // Attempt to create the TX
    let mut machines = vec![];
    let mut preprocesses = vec![];
    let mut serialized_preprocesses = vec![];
    for keys in &self.keys {
      let machine = match self.network.attempt_send(keys.clone(), tx.clone()).await {
        Err(e) => {
          error!("failed to attempt {}, #{}: {:?}", hex::encode(id.id), id.attempt, e);
          return;
        }
        Ok(machine) => machine,
      };

      // TODO: Use a seeded RNG here so we don't produce distinct messages with the same intent
      // This is also needed so we don't preprocess, send preprocess, reboot before ack'ing the
      // message, send distinct preprocess, and then attempt a signing session premised on the
      // former with the latter
      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      machines.push(machine);
      serialized_preprocesses.push(preprocess.serialize());
      preprocesses.push(preprocess);
    }

    self.preprocessing.insert(id.id, (machines, preprocesses));

    // Broadcast our preprocess
    self.events.push_back(SignerEvent::ProcessorMessage(ProcessorMessage::Preprocess {
      id,
      preprocesses: serialized_preprocesses,
    }));
  }

  pub async fn sign_transaction(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 32],
    tx: N::SignableTransaction,
    eventuality: N::Eventuality,
  ) {
    // The caller is expected to re-issue sign orders on reboot
    // This is solely used by the rebroadcast task
    SignerDb::<N, D>::add_active_sign(txn, &id);

    if self.already_completed(txn, id) {
      return;
    }

    SignerDb::<N, D>::save_eventuality(txn, id, eventuality);

    self.signable.insert(id, tx);
    self.attempt(txn, id, 0).await;
  }

  pub async fn handle(&mut self, txn: &mut D::Transaction<'_>, msg: CoordinatorMessage) {
    match msg {
      CoordinatorMessage::Preprocesses { id, mut preprocesses } => {
        if self.verify_id(&id).is_err() {
          return;
        }

        let (machines, our_preprocesses) = match self.preprocessing.remove(&id.id) {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id)
            );
            return;
          }
          Some(machine) => machine,
        };

        let preprocesses = match preprocesses
          .drain()
          .map(|(l, preprocess)| {
            let mut preprocess_ref = preprocess.as_ref();
            let res = machines[0]
              .read_preprocess::<&[u8]>(&mut preprocess_ref)
              .map(|preprocess| (l, preprocess));
            if !preprocess_ref.is_empty() {
              todo!("malicious signer: extra bytes");
            }
            res
          })
          .collect::<Result<HashMap<_, _>, _>>()
        {
          Ok(preprocesses) => preprocesses,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

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
            Err(e) => todo!("malicious signer: {:?}", e),
          };
          if m == 0 {
            signature_machine = Some(machine);
          }
          serialized_shares.push(share.serialize());
          shares.push(share);
        }
        self.signing.insert(id.id, (signature_machine.unwrap(), shares));

        // Broadcast our shares
        self.events.push_back(SignerEvent::ProcessorMessage(ProcessorMessage::Share {
          id,
          shares: serialized_shares,
        }));
      }

      CoordinatorMessage::Shares { id, mut shares } => {
        if self.verify_id(&id).is_err() {
          return;
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
            return;
          }
          Some(machine) => machine,
        };

        let mut shares = match shares
          .drain()
          .map(|(l, share)| {
            let mut share_ref = share.as_ref();
            let res = machine.read_share::<&[u8]>(&mut share_ref).map(|share| (l, share));
            if !share_ref.is_empty() {
              todo!("malicious signer: extra bytes");
            }
            res
          })
          .collect::<Result<HashMap<_, _>, _>>()
        {
          Ok(shares) => shares,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        for (i, our_share) in our_shares.into_iter().enumerate().skip(1) {
          assert!(shares.insert(self.keys[i].params().i(), our_share).is_none());
        }

        let tx = match machine.complete(shares) {
          Ok(res) => res,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        // Save the transaction in case it's needed for recovery
        SignerDb::<N, D>::complete(txn, id.id, &tx);

        // Publish it
        let tx_id = tx.id();
        if let Err(e) = self.network.publish_transaction(&tx).await {
          error!("couldn't publish {:?}: {:?}", tx, e);
        } else {
          info!("published {} for plan {}", hex::encode(&tx_id), hex::encode(id.id));
        }

        // Stop trying to sign for this TX
        self.complete(id.id, tx_id);
      }

      CoordinatorMessage::Reattempt { id } => {
        self.attempt(txn, id.id, id.attempt).await;
      }

      CoordinatorMessage::Completed { key: _, id, tx: mut tx_vec } => {
        let mut tx = <N::Transaction as Transaction<N>>::Id::default();
        if tx.as_ref().len() != tx_vec.len() {
          let true_len = tx_vec.len();
          tx_vec.truncate(2 * tx.as_ref().len());
          warn!(
            "a validator claimed {}... (actual length {}) completed {} yet {}",
            hex::encode(&tx_vec),
            true_len,
            hex::encode(id),
            "that's not a valid TX ID",
          );
          return;
        }
        tx.as_mut().copy_from_slice(&tx_vec);

        self.claimed_eventuality_completion(txn, id, &tx).await;
      }
    }
  }
}
