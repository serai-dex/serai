use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{SystemTime, Instant, Duration},
  collections::VecDeque,
};

use log::debug;

use parity_scale_codec::{Encode, Decode};

use futures::{
  FutureExt, StreamExt, SinkExt,
  future::{self, Fuse},
  channel::mpsc,
};
use tokio::time::sleep;

mod time;
use time::{sys_time, CanonicalInstant};

mod round;
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
use round::RoundData;
=======
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs

mod block;
use block::BlockData;
>>>>>>> b7b57ee6 (Move BlockData to a new file):substrate/tendermint/machine/src/lib.rs

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
mod block;
use block::BlockData;

=======
>>>>>>> 4ba469e6 (BlockData::new):substrate/tendermint/machine/src/lib.rs
pub(crate) mod message_log;

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

pub(crate) fn commit_msg(end_time: u64, id: &[u8]) -> Vec<u8> {
  [&end_time.to_le_bytes(), id].concat().to_vec()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
enum Step {
  Propose,
  Prevote,
  Precommit,
}

#[derive(Clone, Debug, Encode, Decode)]
enum Data<B: Block, S: Signature> {
  Proposal(Option<RoundNumber>, B),
  Prevote(Option<B::Id>),
  Precommit(Option<(B::Id, S)>),
}

impl<B: Block, S: Signature> PartialEq for Data<B, S> {
  fn eq(&self, other: &Data<B, S>) -> bool {
    match (self, other) {
      (Data::Proposal(valid_round, block), Data::Proposal(valid_round2, block2)) => {
        (valid_round == valid_round2) && (block == block2)
      }
      (Data::Prevote(id), Data::Prevote(id2)) => id == id2,
      (Data::Precommit(None), Data::Precommit(None)) => true,
      (Data::Precommit(Some((id, _))), Data::Precommit(Some((id2, _)))) => id == id2,
      _ => false,
    }
  }
}

impl<B: Block, S: Signature> Data<B, S> {
  fn step(&self) -> Step {
    match self {
      Data::Proposal(..) => Step::Propose,
      Data::Prevote(..) => Step::Prevote,
      Data::Precommit(..) => Step::Precommit,
    }
  }
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
struct Message<V: ValidatorId, B: Block, S: Signature> {
  sender: V,

  block: BlockNumber,
  round: RoundNumber,

  data: Data<B, S>,
}

/// A signed Tendermint consensus message to be broadcast to the other validators.
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct SignedMessage<V: ValidatorId, B: Block, S: Signature> {
  msg: Message<V, B, S>,
  sig: S,
}

impl<V: ValidatorId, B: Block, S: Signature> SignedMessage<V, B, S> {
  /// Number of the block this message is attempting to add to the chain.
  pub fn block(&self) -> BlockNumber {
    self.msg.block
  }

  #[must_use]
  pub fn verify_signature<Scheme: SignatureScheme<ValidatorId = V, Signature = S>>(
    &self,
    signer: &Scheme,
  ) -> bool {
    signer.verify(self.msg.sender, &self.msg.encode(), &self.sig)
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TendermintError<V: ValidatorId> {
  Malicious(V),
  Temporal,
  AlreadyHandled,
}

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
// Type aliases to abstract over generic hell
pub(crate) type DataFor<N> =
  Data<<N as Network>::Block, <<N as Network>::SignatureScheme as SignatureScheme>::Signature>;
pub(crate) type MessageFor<N> = Message<
  <N as Network>::ValidatorId,
  <N as Network>::Block,
  <<N as Network>::SignatureScheme as SignatureScheme>::Signature,
>;
/// Type alias to the SignedMessage type for a given Network
pub type SignedMessageFor<N> = SignedMessage<
  <N as Network>::ValidatorId,
  <N as Network>::Block,
  <<N as Network>::SignatureScheme as SignatureScheme>::Signature,
>;

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> b7b57ee6 (Move BlockData to a new file):substrate/tendermint/machine/src/lib.rs
=======
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  network: N,
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  validators: N::SignatureScheme,
  weights: Arc<N::Weights>,

  queue: VecDeque<MessageFor<N>>,
  msg_recv: mpsc::UnboundedReceiver<SignedMessageFor<N>>,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
  synced_block_recv: mpsc::UnboundedReceiver<SyncedBlock<N>>,
  synced_block_result_send: mpsc::UnboundedSender<bool>,
=======
  step_recv: mpsc::UnboundedReceiver<(Commit<N::SignatureScheme>, N::Block)>,
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
=======
  step_recv: mpsc::UnboundedReceiver<(BlockNumber, Commit<N::SignatureScheme>, N::Block)>,
>>>>>>> 26ad7c1d (Correct race conditions between add_block and step):substrate/tendermint/machine/src/lib.rs

  block: BlockData<N>,
}

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
pub struct SyncedBlock<N: Network> {
  pub number: BlockNumber,
  pub block: <N as Network>::Block,
  pub commit: Commit<<N as Network>::SignatureScheme>,
}
=======
pub type StepSender<N> = mpsc::UnboundedSender<(
  BlockNumber,
  Commit<<N as Network>::SignatureScheme>,
  <N as Network>::Block,
)>;
>>>>>>> 26ad7c1d (Correct race conditions between add_block and step):substrate/tendermint/machine/src/lib.rs

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
pub type SyncedBlockSender<N> = mpsc::UnboundedSender<SyncedBlock<N>>;
pub type SyncedBlockResultReceiver = mpsc::UnboundedReceiver<bool>;

=======
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
pub type MessageSender<N> = mpsc::UnboundedSender<SignedMessageFor<N>>;

/// A Tendermint machine and its channel to receive messages from the gossip layer over.
pub struct TendermintHandle<N: Network> {
  /// Channel to trigger the machine to move to the next block.
  /// Takes in the the previous block's commit, along with the new proposal.
  pub synced_block: SyncedBlockSender<N>,
  /// A channel to communicate the result of a synced_block message.
  pub synced_block_result: SyncedBlockResultReceiver,
  /// Channel to send messages received from the P2P layer.
  pub messages: MessageSender<N>,
  /// Tendermint machine to be run on an asynchronous task.
  pub machine: TendermintMachine<N>,
}

impl<N: Network + 'static> TendermintMachine<N> {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> 3d20afd2 (Improve documentation):substrate/tendermint/machine/src/lib.rs
  // Broadcast the given piece of data
  // Tendermint messages always specify their block/round, yet Tendermint only ever broadcasts for
  // the current block/round. Accordingly, instead of manually fetching those at every call-site,
  // this function can simply pass the data to the block which can contextualize it
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
  fn broadcast(&mut self, data: DataFor<N>) {
    if let Some(msg) = self.block.message(data) {
      // Push it on to the queue. This is done so we only handle one message at a time, and so we
      // can handle our own message before broadcasting it. That way, we fail before before
      // becoming malicious
      self.queue.push_back(msg);
=======
  fn broadcast(
    &mut self,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) {
    if let Some(validator_id) = self.block.validator_id {
      // 27, 33, 41, 46, 60, 64
      self.block.round_mut().step = data.step();
      self.queue.push_back(Message {
        sender: validator_id,
        number: self.block.number,
        round: self.block.round().number,
        data,
      });
    }
  }

  fn populate_end_time(&mut self, round: RoundNumber) {
    for r in (self.block.round().number.0 + 1) .. round.0 {
      self.block.end_time.insert(
        RoundNumber(r),
        RoundData::<N>::new(RoundNumber(r), self.block.end_time[&RoundNumber(r - 1)]).end_time(),
      );
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
=======
>>>>>>> 3d20afd2 (Improve documentation):substrate/tendermint/machine/src/lib.rs
  fn broadcast(&mut self, data: DataFor<N>) {
    if let Some(msg) = self.block.message(data) {
      // Push it on to the queue. This is done so we only handle one message at a time, and so we
      // can handle our own message before broadcasting it. That way, we fail before before
      // becoming malicious
      self.queue.push_back(msg);
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
    }
  }

  // Start a new round. Returns true if we were the proposer
  fn round(&mut self, round: RoundNumber, time: Option<CanonicalInstant>) -> bool {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
    if let Some(data) =
      self.block.new_round(round, self.weights.proposer(self.block.number, round), time)
=======
    // If skipping rounds, populate end_time
    if round.0 != 0 {
      self.populate_end_time(round);
    }

    // 11-13
    self.block.round = Some(RoundData::<N>::new(
      round,
      time.unwrap_or_else(|| self.block.end_time[&RoundNumber(round.0 - 1)]),
    ));
    self.block.end_time.insert(round, self.block.round().end_time());

    // 14-21
    if Some(self.weights.proposer(self.block.number, self.block.round().number)) ==
      self.block.validator_id
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
    if let Some(data) =
      self.block.new_round(round, self.weights.proposer(self.block.number, round), time)
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
    {
      self.broadcast(data);
      true
    } else {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
      self.block.round_mut().set_timeout(Step::Propose);
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
      false
    }
  }

  // 53-54
  async fn reset(&mut self, end_round: RoundNumber, proposal: Option<N::Block>) {
    // Ensure we have the end time data for the last round
    self.block.populate_end_time(end_round);

    // Sleep until this round ends
    let round_end = self.block.end_time[&end_round];
    sleep(round_end.instant().saturating_duration_since(Instant::now())).await;

    // Clear our outbound message queue
    self.queue = VecDeque::new();

    // Create the new block
    self.block = BlockData::new(
      self.weights.clone(),
      BlockNumber(self.block.number.0 + 1),
      self.signer.validator_id().await,
      proposal,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
    );
=======

      log: MessageLog::new(self.weights.clone()),
      slashes: HashSet::new(),
      end_time: HashMap::new(),

      // This will be populated in the following round() call
      round: None,

      locked: None,
      valid: None,
    };
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
    );
>>>>>>> 4ba469e6 (BlockData::new):substrate/tendermint/machine/src/lib.rs

    // Start the first round
    self.round(RoundNumber(0), Some(round_end));
  }

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
  async fn reset_by_commit(
    &mut self,
    commit: Commit<N::SignatureScheme>,
    proposal: Option<N::Block>,
  ) {
=======
  async fn reset_by_commit(&mut self, commit: Commit<N::SignatureScheme>, proposal: N::Block) {
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
    let mut round = self.block.round().number;
    // If this commit is for a round we don't have, jump up to it
    while self.block.end_time[&round].canonical() < commit.end_time {
      round.0 += 1;
      self.block.populate_end_time(round);
    }
    // If this commit is for a prior round, find it
    while self.block.end_time[&round].canonical() > commit.end_time {
      if round.0 == 0 {
        panic!("commit isn't for this machine's next block");
      }
      round.0 -= 1;
    }
    debug_assert_eq!(self.block.end_time[&round].canonical(), commit.end_time);

    self.reset(round, proposal).await;
  }

  async fn slash(&mut self, validator: N::ValidatorId) {
    if !self.block.slashes.contains(&validator) {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
      log::info!(target: "tendermint", "Slashing validator {:?}", validator);
=======
      debug!(target: "tendermint", "Slashing validator {:?}", validator);
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
      self.block.slashes.insert(validator);
      self.network.slash(validator).await;
    }
  }

  /// Create a new Tendermint machine, from the specified point, with the specified block as the
  /// one to propose next. This will return a channel to send messages from the gossip layer and
  /// the machine itself. The machine should have `run` called from an asynchronous task.
  #[allow(clippy::new_ret_no_self)]
  pub async fn new(
    network: N,
    last_block: BlockNumber,
    last_time: u64,
    proposal: N::Block,
  ) -> TendermintHandle<N> {
    let (msg_send, msg_recv) = mpsc::unbounded();
    let (synced_block_send, synced_block_recv) = mpsc::unbounded();
    let (synced_block_result_send, synced_block_result_recv) = mpsc::unbounded();
    TendermintHandle {
      synced_block: synced_block_send,
      synced_block_result: synced_block_result_recv,
      messages: msg_send,
      machine: {
        let sys_time = sys_time(last_time);
        // If the last block hasn't ended yet, sleep until it has
        sleep(sys_time.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO)).await;

        let signer = network.signer();
        let validators = network.signature_scheme();
        let weights = Arc::new(network.weights());
        let validator_id = signer.validator_id().await;
        // 01-10
        let mut machine = TendermintMachine {
          network,
          signer,
          validators,
          weights: weights.clone(),

          queue: VecDeque::new(),
          msg_recv,
          synced_block_recv,
          synced_block_result_send,

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
          block: BlockData::new(
            weights,
            BlockNumber(last_block.0 + 1),
            validator_id,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
            Some(proposal),
          ),
=======
            proposal,

            log: MessageLog::new(weights),
            slashes: HashSet::new(),
            end_time: HashMap::new(),

            // This will be populated in the following round() call
            round: None,

            locked: None,
            valid: None,
          },
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
          block: BlockData::new(weights, BlockNumber(last.0 .0 + 1), validator_id, proposal),
>>>>>>> 4ba469e6 (BlockData::new):substrate/tendermint/machine/src/lib.rs
=======
          block: BlockData::new(weights, BlockNumber(last_block.0 + 1), validator_id, proposal),
>>>>>>> cd9b9c89 (Resolve low-hanging review comments):substrate/tendermint/machine/src/lib.rs
        };

        // The end time of the last block is the start time for this one
        // The Commit explicitly contains the end time, so loading the last commit will provide
        // this. The only exception is for the genesis block, which doesn't have a commit
        // Using the genesis time in place will cause this block to be created immediately
        // after it, without the standard amount of separation (so their times will be
        // equivalent or minimally offset)
        // For callers wishing to avoid this, they should pass (0, GENESIS + N::block_time())
        machine.round(RoundNumber(0), Some(CanonicalInstant::new(last_time)));
        machine
      },
    }
  }

  pub async fn run(mut self) {
    loop {
      // Also create a future for if the queue has a message
      // Does not pop_front as if another message has higher priority, its future will be handled
      // instead in this loop, and the popped value would be dropped with the next iteration
      // While no other message has a higher priority right now, this is a safer practice
      let mut queue_future =
        if self.queue.is_empty() { Fuse::terminated() } else { future::ready(()).fuse() };

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
      if let Some((our_message, msg, mut sig)) = futures::select_biased! {
        // Handle a new block occuring externally (an external sync loop)
        // Has the highest priority as it makes all other futures here irrelevant
        msg = self.synced_block_recv.next() => {
          if let Some(SyncedBlock { number, block, commit }) = msg {
            // Commit is for a block we've already moved past
            if number != self.block.number {
              self.synced_block_result_send.send(false).await.unwrap();
              continue;
            }

            // Commit is invalid
            if !self.network.verify_commit(block.id(), &commit) {
              self.synced_block_result_send.send(false).await.unwrap();
              continue;
            }

            let proposal = self.network.add_block(block, commit.clone()).await;
=======
      if let Some((broadcast, msg)) = futures::select_biased! {
        // Handle a new block occuring externally (an external sync loop)
        // Has the highest priority as it makes all other futures here irrelevant
        msg = self.step_recv.next() => {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
          if let Some((commit, proposal)) = msg {
>>>>>>> 2de4ab8c (Clear the Queue instead of draining and filtering):substrate/tendermint/machine/src/lib.rs
=======
          if let Some((block_number, commit, proposal)) = msg {
            // Commit is for a block we've already moved past
            if block_number != self.block.number {
              continue;
            }
>>>>>>> 26ad7c1d (Correct race conditions between add_block and step):substrate/tendermint/machine/src/lib.rs
            self.reset_by_commit(commit, proposal).await;
            self.synced_block_result_send.send(true).await.unwrap();
            None
          } else {
            break;
          }
        },

        // Handle our messages
        _ = queue_future => {
          Some((true, self.queue.pop_front().unwrap(), None))
        },

        // Handle any timeouts
        step = self.block.round().timeout_future().fuse() => {
          // Remove the timeout so it doesn't persist, always being the selected future due to bias
          // While this does enable the timeout to be entered again, the timeout setting code will
          // never attempt to add a timeout after its timeout has expired
          self.block.round_mut().timeouts.remove(&step);
          // Only run if it's still the step in question
          if self.block.round().step == step {
            match step {
              Step::Propose => {
                // Slash the validator for not proposing when they should've
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
                log::debug!(target: "tendermint", "Validator didn't propose when they should have");
=======
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
                debug!(target: "tendermint", "Validator didn't propose when they should have");
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
                self.slash(
                  self.weights.proposer(self.block.number, self.block.round().number)
                ).await;
                self.broadcast(Data::Prevote(None));
              },
              Step::Prevote => self.broadcast(Data::Precommit(None)),
              Step::Precommit => {
                self.round(RoundNumber(self.block.round().number.0 + 1), None);
                continue;
              }
            }
          }
          None
        },

        // Handle any received messages
        msg = self.msg_recv.next() => {
          if let Some(msg) = msg {
            if !msg.verify_signature(&self.validators) {
              continue;
            }
            Some((false, msg.msg, Some(msg.sig)))
          } else {
            break;
          }
        }
      } {
        let res = self.message(msg.clone()).await;
        if res.is_err() && our_message {
          panic!("honest node (ourselves) had invalid behavior");
        }

        match res {
          Ok(None) => {
            if let Some(sig) = sig.take() {
              // If it's our own message, it shouldn't already be signed
              assert!(!our_message);

              // Re-broadcast this since it's an original consensus message
              self.network.broadcast(SignedMessage { msg: msg.clone(), sig }).await;
            }
          }
          Ok(Some(block)) => {
            let mut validators = vec![];
            let mut sigs = vec![];
            // Get all precommits for this round
            for (validator, msgs) in &self.block.log.log[&msg.round] {
              if let Some(Data::Precommit(Some((id, sig)))) = msgs.get(&Step::Precommit) {
                // If this precommit was for this block, include it
                if id == &block.id() {
                  validators.push(*validator);
                  sigs.push(sig.clone());
                }
              }
            }

            let commit = Commit {
              end_time: self.block.end_time[&msg.round].canonical(),
              validators,
              signature: N::SignatureScheme::aggregate(&sigs),
            };
            debug_assert!(self.network.verify_commit(block.id(), &commit));

            let proposal = self.network.add_block(block, commit).await;
            self.reset(msg.round, proposal).await;
          }
          Err(TendermintError::Malicious(validator)) => self.slash(validator).await,
          Err(TendermintError::Temporal) => (),
          Err(TendermintError::AlreadyHandled) => (),
        }

        if our_message {
          assert!(sig.is_none());
          let sig = self.signer.sign(&msg.encode()).await;
          self.network.broadcast(SignedMessage { msg, sig }).await;
        }
      }
    }
  }

  // Returns Ok(true) if this was a Precommit which had its signature validated
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
  // Returns Ok(false) if it wasn't a Precommit or the signature wasn't validated yet
=======
  // Returns Ok(false) if the signature wasn't validated yet
>>>>>>> b7502a7f (Have verify_precommit_signature return if it verified the signature):substrate/tendermint/machine/src/lib.rs
=======
  // Returns Ok(false) if it wasn't a Precommit or the signature wasn't validated yet
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
  // Returns Err if the signature was invalid
  fn verify_precommit_signature(
    &self,
    sender: N::ValidatorId,
    round: RoundNumber,
    data: &DataFor<N>,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
  ) -> Result<bool, TendermintError<N::ValidatorId>> {
=======
  ) -> Result<(), TendermintError<N::ValidatorId>> {
>>>>>>> c13e0c75 (Move more code into block.rs):substrate/tendermint/machine/src/lib.rs
    if let Data::Precommit(Some((id, sig))) = data {
=======
  ) -> Result<bool, TendermintError<N::ValidatorId>> {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
    Ok(if let Data::Precommit(Some((id, sig))) = data {
>>>>>>> b7502a7f (Have verify_precommit_signature return if it verified the signature):substrate/tendermint/machine/src/lib.rs
=======
    if let Data::Precommit(Some((id, sig))) = data {
>>>>>>> cd9b9c89 (Resolve low-hanging review comments):substrate/tendermint/machine/src/lib.rs
      // Also verify the end_time of the commit
      // Only perform this verification if we already have the end_time
      // Else, there's a DoS where we receive a precommit for some round infinitely in the future
      // which forces us to calculate every end time
      if let Some(end_time) = self.block.end_time.get(&round) {
        if !self.validators.verify(sender, &commit_msg(end_time.canonical(), id.as_ref()), sig) {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
          log::warn!(target: "tendermint", "Validator produced an invalid commit signature");
=======
          debug!(target: "tendermint", "Validator produced an invalid commit signature");
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
          Err(TendermintError::Malicious(sender))?;
        }
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
        return Ok(true);
      }
    }
    Ok(false)
=======
        true
      } else {
        false
      }
    } else {
      false
    })
>>>>>>> b7502a7f (Have verify_precommit_signature return if it verified the signature):substrate/tendermint/machine/src/lib.rs
=======
        return Ok(true);
      }
    }
    Ok(false)
>>>>>>> cd9b9c89 (Resolve low-hanging review comments):substrate/tendermint/machine/src/lib.rs
  }

  async fn message(
    &mut self,
    msg: MessageFor<N>,
  ) -> Result<Option<N::Block>, TendermintError<N::ValidatorId>> {
    if msg.block != self.block.number {
      Err(TendermintError::Temporal)?;
    }

    // If this is a precommit, verify its signature
    self.verify_precommit_signature(msg.sender, msg.round, &msg.data)?;

    // Only let the proposer propose
    if matches!(msg.data, Data::Proposal(..)) &&
      (msg.sender != self.weights.proposer(msg.block, msg.round))
    {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
      log::warn!(target: "tendermint", "Validator who wasn't the proposer proposed");
=======
      debug!(target: "tendermint", "Validator who wasn't the proposer proposed");
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
      Err(TendermintError::Malicious(msg.sender))?;
    };

    if !self.block.log.log(msg.clone())? {
      return Err(TendermintError::AlreadyHandled);
    }
    log::debug!(target: "tendermint", "received new tendermint message");

    // All functions, except for the finalizer and the jump, are locked to the current round

    // Run the finalizer to see if it applies
    // 49-52
    if matches!(msg.data, Data::Proposal(..)) || matches!(msg.data, Data::Precommit(_)) {
      let proposer = self.weights.proposer(self.block.number, msg.round);

      // Get the proposal
      if let Some(Data::Proposal(_, block)) = self.block.log.get(msg.round, proposer, Step::Propose)
      {
        // Check if it has gotten a sufficient amount of precommits
        // Use a junk signature since message equality disregards the signature
        if self.block.log.has_consensus(
          msg.round,
          Data::Precommit(Some((block.id(), self.signer.sign(&[]).await))),
        ) {
          log::debug!(target: "tendermint", "block {} has consensus", msg.block.0);
          return Ok(Some(block.clone()));
        }
      }
    }

    // Else, check if we need to jump ahead
    #[allow(clippy::comparison_chain)]
    if msg.round.0 < self.block.round().number.0 {
      // Prior round, disregard if not finalizing
      return Ok(None);
    } else if msg.round.0 > self.block.round().number.0 {
      // 55-56
      // Jump, enabling processing by the below code
      if self.block.log.round_participation(msg.round) > self.weights.fault_thresold() {
        // If this round already has precommit messages, verify their signatures
        let round_msgs = self.block.log.log[&msg.round].clone();
        for (validator, msgs) in &round_msgs {
          if let Some(data) = msgs.get(&Step::Precommit) {
            if let Ok(res) = self.verify_precommit_signature(*validator, msg.round, data) {
              // Ensure this actually verified the signature instead of believing it shouldn't yet
              debug_assert!(res);
            } else {
              // Remove the message so it isn't counted towards forming a commit/included in one
              // This won't remove the fact the precommitted for this block hash in the MessageLog
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
              // TODO: Don't even log these in the first place until we jump, preventing needing
              // to do this in the first place
=======
>>>>>>> b7502a7f (Have verify_precommit_signature return if it verified the signature):substrate/tendermint/machine/src/lib.rs
=======
              // TODO: Don't even log these in the first place until we jump, preventing needing
              // to do this in the first place
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
              self
                .block
                .log
                .log
                .get_mut(&msg.round)
                .unwrap()
                .get_mut(validator)
                .unwrap()
                .remove(&Step::Precommit);
              self.slash(*validator).await;
            }
          }
        }
        // If we're the proposer, return now so we re-run processing with our proposal
        // If we continue now, it'd just be wasted ops
        if self.round(msg.round, None) {
          return Ok(None);
        }
      } else {
        // Future round which we aren't ready to jump to, so return for now
        return Ok(None);
      }
    }

    // The paper executes these checks when the step is prevote. Making sure this message warrants
    // rerunning these checks is a sane optimization since message instances is a full iteration
    // of the round map
    if (self.block.round().step == Step::Prevote) && matches!(msg.data, Data::Prevote(_)) {
      let (participation, weight) =
        self.block.log.message_instances(self.block.round().number, Data::Prevote(None));
      // 34-35
      if participation >= self.weights.threshold() {
        self.block.round_mut().set_timeout(Step::Prevote);
      }

      // 44-46
      if weight >= self.weights.threshold() {
        self.broadcast(Data::Precommit(None));
        return Ok(None);
      }
    }

    // 47-48
    if matches!(msg.data, Data::Precommit(_)) &&
      self.block.log.has_participation(self.block.round().number, Step::Precommit)
    {
      self.block.round_mut().set_timeout(Step::Precommit);
    }

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
    // All further operations require actually having the proposal in question
    let proposer = self.weights.proposer(self.block.number, self.block.round().number);
    let (vr, block) = if let Some(Data::Proposal(vr, block)) =
      self.block.log.get(self.block.round().number, proposer, Step::Propose)
    {
      (vr, block)
    } else {
      return Ok(None);
    };
=======
=======
    // All further operations require actually having the proposal in question
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
    let proposer = self.weights.proposer(self.block.number, self.block.round().number);
    let (vr, block) = if let Some(Data::Proposal(vr, block)) =
      self.block.log.get(self.block.round().number, proposer, Step::Propose)
    {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
      // 22-33
      if self.block.round().step == Step::Propose {
        // Delay error handling (triggering a slash) until after we vote.
        let (valid, err) = match self.network.validate(block).await {
          Ok(_) => (true, Ok(None)),
          Err(BlockError::Temporal) => (false, Ok(None)),
          Err(BlockError::Fatal) => (false, Err(TendermintError::Malicious(proposer))),
        };
        // Create a raw vote which only requires block validity as a basis for the actual vote.
        let raw_vote = Some(block.id()).filter(|_| valid);
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
      (vr, block)
    } else {
      return Ok(None);
    };
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs

    // 22-33
    if self.block.round().step == Step::Propose {
      // Delay error handling (triggering a slash) until after we vote.
      let (valid, err) = match self.network.validate(block).await {
        Ok(_) => (true, Ok(None)),
        Err(BlockError::Temporal) => (false, Ok(None)),
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
        Err(BlockError::Fatal) => (false, {
          log::warn!(target: "tendermint", "Validator proposed a fatally invalid block");
          Err(TendermintError::Malicious(proposer))
        }),
=======
        Err(BlockError::Fatal) => (false, Err(TendermintError::Malicious(proposer))),
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
=======
        Err(BlockError::Fatal) => (false, {
          debug!(target: "tendermint", "Validator proposed a fatally invalid block");
          Err(TendermintError::Malicious(proposer))
        }),
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
      };
      // Create a raw vote which only requires block validity as a basis for the actual vote.
      let raw_vote = Some(block.id()).filter(|_| valid);

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
      // If locked is none, it has a round of -1 according to the protocol. That satisfies
      // 23 and 29. If it's some, both are satisfied if they're for the same ID. If it's some
      // with different IDs, the function on 22 rejects yet the function on 28 has one other
      // condition
      let locked = self.block.locked.as_ref().map(|(_, id)| id == &block.id()).unwrap_or(true);
      let mut vote = raw_vote.filter(|_| locked);

      if let Some(vr) = vr {
        // Malformed message
        if vr.0 >= self.block.round().number.0 {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
          log::warn!(target: "tendermint", "Validator claimed a round from the future was valid");
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
=======
          debug!(target: "tendermint", "Validator claimed a round from the future was valid");
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
          Err(TendermintError::Malicious(msg.sender))?;
        }

        if self.block.log.has_consensus(*vr, Data::Prevote(Some(block.id()))) {
          // Allow differing locked values if the proposal has a newer valid round
          // This is the other condition described above
          if let Some((locked_round, _)) = self.block.locked.as_ref() {
            vote = vote.or_else(|| raw_vote.filter(|_| locked_round.0 <= vr.0));
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
        if let Some(vr) = vr {
          // Malformed message
          if vr.0 >= self.block.round().number.0 {
            Err(TendermintError::Malicious(msg.sender))?;
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
          }

          self.broadcast(Data::Prevote(vote));
          return err;
        }
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
      } else {
        self.broadcast(Data::Prevote(vote));
        return err;
      }
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
      } else if self
        .block
        .valid
        .as_ref()
        .map(|(round, _)| round != &self.block.round().number)
        .unwrap_or(true)
      {
        // 36-43
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs

      return Ok(None);
    }

<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
=======
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
    if self
      .block
      .valid
      .as_ref()
      .map(|(round, _)| round != &self.block.round().number)
      .unwrap_or(true)
    {
      // 36-43
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs

      // The run once condition is implemented above. Since valid will always be set by this, it
      // not being set, or only being set historically, means this has yet to be run

      if self.block.log.has_consensus(self.block.round().number, Data::Prevote(Some(block.id()))) {
        match self.network.validate(block).await {
          Ok(_) => (),
          Err(BlockError::Temporal) => (),
          Err(BlockError::Fatal) => {
            log::warn!(target: "tendermint", "Validator proposed a fatally invalid block");
            Err(TendermintError::Malicious(proposer))?
=======
        if self.block.log.has_consensus(self.block.round().number, Data::Prevote(Some(block.id())))
        {
          match self.network.validate(block).await {
            Ok(_) => (),
            Err(BlockError::Temporal) => (),
            Err(BlockError::Fatal) => Err(TendermintError::Malicious(proposer))?,
          };

          self.block.valid = Some((self.block.round().number, block.clone()));
          if self.block.round().step == Step::Prevote {
            self.block.locked = Some((self.block.round().number, block.id()));
            self.broadcast(Data::Precommit(Some((
              block.id(),
              self
                .signer
                .sign(&commit_msg(
                  self.block.end_time[&self.block.round().number].canonical(),
                  block.id().as_ref(),
                ))
                .await,
            ))));
            return Ok(None);
>>>>>>> 85087833 (Move Round to an Option due to the pseudo-uninitialized state we create):substrate/tendermint/machine/src/lib.rs
          }
=======

      // The run once condition is implemented above. Since valid will always be set by this, it
      // not being set, or only being set historically, means this has yet to be run

      if self.block.log.has_consensus(self.block.round().number, Data::Prevote(Some(block.id()))) {
        match self.network.validate(block).await {
          Ok(_) => (),
          Err(BlockError::Temporal) => (),
<<<<<<< HEAD:coordinator/tributary/tendermint/src/lib.rs
          Err(BlockError::Fatal) => Err(TendermintError::Malicious(proposer))?,
>>>>>>> 48b4b685 (Slight doc changes):substrate/tendermint/machine/src/lib.rs
=======
          Err(BlockError::Fatal) => {
            debug!(target: "tendermint", "Validator proposed a fatally invalid block");
            Err(TendermintError::Malicious(proposer))?
          }
>>>>>>> 32129420 (Add log statements):substrate/tendermint/machine/src/lib.rs
        };

        self.block.valid = Some((self.block.round().number, block.clone()));
        if self.block.round().step == Step::Prevote {
          self.block.locked = Some((self.block.round().number, block.id()));
          self.broadcast(Data::Precommit(Some((
            block.id(),
            self
              .signer
              .sign(&commit_msg(
                self.block.end_time[&self.block.round().number].canonical(),
                block.id().as_ref(),
              ))
              .await,
          ))));
        }
      }
    }

    Ok(None)
  }
}
