use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{SystemTime, Instant, Duration},
  collections::VecDeque,
};

use parity_scale_codec::{Encode, Decode};

use futures_channel::mpsc;
use futures_util::{
  FutureExt, StreamExt, SinkExt,
  future::{self, Fuse},
};
use tokio::time::sleep;

pub mod time;
use time::{sys_time, CanonicalInstant};

pub mod round;

mod block;
use block::BlockData;

pub(crate) mod message_log;

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

pub fn commit_msg(end_time: u64, id: &[u8]) -> Vec<u8> {
  [&end_time.to_le_bytes(), id].concat().to_vec()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub enum Step {
  Propose,
  Prevote,
  Precommit,
}

#[derive(Clone, Eq, Debug, Encode, Decode)]
pub enum Data<B: Block, S: Signature> {
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
  pub fn step(&self) -> Step {
    match self {
      Data::Proposal(..) => Step::Propose,
      Data::Prevote(..) => Step::Prevote,
      Data::Precommit(..) => Step::Precommit,
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct Message<V: ValidatorId, B: Block, S: Signature> {
  pub sender: V,
  pub block: BlockNumber,
  pub round: RoundNumber,

  pub data: Data<B, S>,
}

/// A signed Tendermint consensus message to be broadcast to the other validators.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct SignedMessage<V: ValidatorId, B: Block, S: Signature> {
  pub msg: Message<V, B, S>,
  pub sig: S,
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

#[derive(Clone, PartialEq, Eq, Debug)]
enum TendermintError<N: Network> {
  Malicious(N::ValidatorId, Option<Evidence>),
  Temporal,
  AlreadyHandled,
}

// Type aliases to abstract over generic hell
pub type DataFor<N> =
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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum SlashReason {
  FailToPropose,
  InvalidBlock,
  InvalidMessage,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub enum Evidence {
  ConflictingMessages(Vec<u8>, Vec<u8>),
  ConflictingPrecommit(Vec<u8>, Vec<u8>),
  InvalidPrecommit(Vec<u8>),
  InvalidValidRound(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SlashEvent {
  Id(SlashReason, u64, u32),
  WithEvidence(Evidence),
}

/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  network: N,
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  validators: N::SignatureScheme,
  weights: Arc<N::Weights>,

  queue: VecDeque<MessageFor<N>>,
  msg_recv: mpsc::UnboundedReceiver<SignedMessageFor<N>>,
  synced_block_recv: mpsc::UnboundedReceiver<SyncedBlock<N>>,
  synced_block_result_send: mpsc::UnboundedSender<bool>,

  block: BlockData<N>,
}

pub struct SyncedBlock<N: Network> {
  pub number: BlockNumber,
  pub block: <N as Network>::Block,
  pub commit: Commit<<N as Network>::SignatureScheme>,
}

pub type SyncedBlockSender<N> = mpsc::UnboundedSender<SyncedBlock<N>>;
pub type SyncedBlockResultReceiver = mpsc::UnboundedReceiver<bool>;

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
  // Broadcast the given piece of data
  // Tendermint messages always specify their block/round, yet Tendermint only ever broadcasts for
  // the current block/round. Accordingly, instead of manually fetching those at every call-site,
  // this function can simply pass the data to the block which can contextualize it
  fn broadcast(&mut self, data: DataFor<N>) {
    if let Some(msg) = self.block.message(data) {
      // Push it on to the queue. This is done so we only handle one message at a time, and so we
      // can handle our own message before broadcasting it. That way, we fail before before
      // becoming malicious
      self.queue.push_back(msg);
    }
  }

  // Start a new round. Returns true if we were the proposer
  fn round(&mut self, round: RoundNumber, time: Option<CanonicalInstant>) -> bool {
    let proposer = self.weights.proposer(self.block.number, round);
    let res = if let Some(data) = self.block.new_round(round, proposer, time) {
      self.broadcast(data);
      true
    } else {
      false
    };
    log::debug!(
      target: "tendermint",
      "proposer for block {}, round {round:?} was {} (me: {res})",
      self.block.number.0,
      hex::encode(proposer.encode()),
    );
    res
  }

  // 53-54
  async fn reset(&mut self, end_round: RoundNumber, proposal: Option<N::Block>) {
    // Ensure we have the end time data for the last round
    self.block.populate_end_time(end_round);

    // Sleep until this round ends
    let round_end = self.block.end_time[&end_round];
    let time_until_round_end = round_end.instant().saturating_duration_since(Instant::now());
    if time_until_round_end == Duration::ZERO {
      log::trace!(
        "resetting when prior round ended {}ms ago",
        Instant::now().saturating_duration_since(round_end.instant()).as_millis(),
      );
    }
    log::trace!("sleeping until round ends in {}ms", time_until_round_end.as_millis());
    sleep(time_until_round_end).await;

    // Clear our outbound message queue
    self.queue = VecDeque::new();

    // Create the new block
    self.block = BlockData::new(
      self.weights.clone(),
      BlockNumber(self.block.number.0 + 1),
      self.signer.validator_id().await,
      proposal,
    );

    // Start the first round
    self.round(RoundNumber(0), Some(round_end));
  }

  async fn reset_by_commit(
    &mut self,
    commit: Commit<N::SignatureScheme>,
    proposal: Option<N::Block>,
  ) {
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

  async fn slash(&mut self, validator: N::ValidatorId, slash_event: SlashEvent) {
    // TODO: If the new slash event has evidence, emit to prevent a low-importance slash from
    // cancelling emission of high-importance slashes
    if !self.block.slashes.contains(&validator) {
      log::info!(target: "tendermint", "Slashing validator {}", hex::encode(validator.encode()));
      self.block.slashes.insert(validator);
      self.network.slash(validator, slash_event).await;
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
        let now = SystemTime::now();
        let sys_time = sys_time(last_time);
        let mut negative = false;
        let time_until = sys_time.duration_since(now).unwrap_or_else(|_| {
          negative = true;
          now.duration_since(sys_time).unwrap_or(Duration::ZERO)
        });
        log::info!(
          target: "tendermint",
          "new TendermintMachine building off block {} is scheduled to start in {}{}s",
          last_block.0,
          if negative { "-" } else { "" },
          time_until.as_secs(),
        );

        // If the last block hasn't ended yet, sleep until it has
        if !negative {
          sleep(time_until).await;
        }

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

          block: BlockData::new(
            weights,
            BlockNumber(last_block.0 + 1),
            validator_id,
            Some(proposal),
          ),
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
    log::debug!(target: "tendermint", "running TendermintMachine");

    loop {
      // Also create a future for if the queue has a message
      // Does not pop_front as if another message has higher priority, its future will be handled
      // instead in this loop, and the popped value would be dropped with the next iteration
      // While no other message has a higher priority right now, this is a safer practice
      let mut queue_future =
        if self.queue.is_empty() { Fuse::terminated() } else { future::ready(()).fuse() };

      if let Some((our_message, msg, mut sig)) = futures_util::select_biased! {
        // Handle a new block occurring externally (an external sync loop)
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

            log::debug!(
              target: "tendermint",
              "TendermintMachine received a block from the external sync loop",
            );
            let proposal = self.network.add_block(block, commit.clone()).await;
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
                log::debug!(target: "tendermint", "Validator didn't propose when they should have");
                // this slash will be voted on.
                self.slash(
                  self.weights.proposer(self.block.number, self.block.round().number),
                  SlashEvent::Id(
                    SlashReason::FailToPropose,
                    self.block.number.0,
                    self.block.round().number.0
                  ),
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
        if our_message {
          assert!(sig.is_none());
          sig = Some(self.signer.sign(&msg.encode()).await);
        }
        let sig = sig.unwrap();

        // TODO: message may internally call broadcast. We should check within broadcast it's not
        // broadcasting our own message at this time.
        let signed_msg = SignedMessage { msg: msg.clone(), sig: sig.clone() };
        let res = self.message(&signed_msg).await;
        if res.is_err() && our_message {
          panic!("honest node (ourselves) had invalid behavior");
        }
        // Only now should we allow broadcasts since we're sure an invariant wasn't reached causing
        // us to have invalid messages.

        if res.is_ok() {
          // Re-broadcast this since it's an original consensus message
          self.network.broadcast(signed_msg).await;
        }

        match res {
          Ok(None) => {}
          Ok(Some(block)) => {
            let mut validators = vec![];
            let mut sigs = vec![];
            // Get all precommits for this round
            for (validator, msgs) in &self.block.log.log[&msg.round] {
              if let Some(signed) = msgs.get(&Step::Precommit) {
                if let Data::Precommit(Some((id, sig))) = &signed.msg.data {
                  // If this precommit was for this block, include it
                  if *id == block.id() {
                    validators.push(*validator);
                    sigs.push(sig.clone());
                  }
                }
              }
            }

            let commit_msg =
              commit_msg(self.block.end_time[&msg.round].canonical(), block.id().as_ref());
            let commit = Commit {
              end_time: self.block.end_time[&msg.round].canonical(),
              validators: validators.clone(),
              signature: self.network.signature_scheme().aggregate(&validators, &commit_msg, &sigs),
            };
            debug_assert!(self.network.verify_commit(block.id(), &commit));

            log::info!(
              target: "tendermint",
              "TendermintMachine produced block {}",
              hex::encode(block.id().as_ref()),
            );
            let id = block.id();
            let proposal = self.network.add_block(block, commit).await;
            log::trace!("added block {} (produced by machine)", hex::encode(id.as_ref()));
            self.reset(msg.round, proposal).await;
          }
          Err(TendermintError::Malicious(sender, evidence)) => {
            let current_msg = SignedMessage { msg: msg.clone(), sig: sig.clone() };

            let slash = if let Some(ev) = evidence {
              // if the malicious message contains a block, only vote to slash
              // TODO: Should this decision be made at a higher level?
              // A higher-level system may be able to verify if the contained block is fatally
              // invalid
              // A higher-level system may accept the bandwidth size of this, even if the issue is
              // just the valid round field
              if let Data::Proposal(_, _) = &current_msg.msg.data {
                SlashEvent::Id(
                  SlashReason::InvalidBlock,
                  self.block.number.0,
                  self.block.round().number.0,
                )
              } else {
                // slash with evidence otherwise
                SlashEvent::WithEvidence(ev)
              }
            } else {
              // we don't have evidence. Slash with vote.
              SlashEvent::Id(
                SlashReason::InvalidMessage,
                self.block.number.0,
                self.block.round().number.0,
              )
            };

            // Each message that we're voting to slash over needs to be re-broadcasted so other
            // validators also trigger their own votes
            // TODO: should this be inside slash function?
            if let SlashEvent::Id(_, _, _) = slash {
              self.network.broadcast(current_msg).await;
            }

            self.slash(sender, slash).await
          }
          Err(TendermintError::Temporal) => (),
          Err(TendermintError::AlreadyHandled) => (),
        }
      }
    }
  }

  // Returns Ok(true) if this was a Precommit which had either no signature or its signature
  // validated
  // Returns Ok(false) if it wasn't a Precommit or the signature wasn't validated yet
  // Returns Err if the signature was invalid
  fn verify_precommit_signature(
    &self,
    signed: &SignedMessageFor<N>,
  ) -> Result<bool, TendermintError<N>> {
    let msg = &signed.msg;
    if let Data::Precommit(precommit) = &msg.data {
      let Some((id, sig)) = precommit else { return Ok(true) };
      // Also verify the end_time of the commit
      // Only perform this verification if we already have the end_time
      // Else, there's a DoS where we receive a precommit for some round infinitely in the future
      // which forces us to calculate every end time
      if let Some(end_time) = self.block.end_time.get(&msg.round) {
        if !self.validators.verify(msg.sender, &commit_msg(end_time.canonical(), id.as_ref()), sig)
        {
          log::warn!(target: "tendermint", "Validator produced an invalid commit signature");
          Err(TendermintError::Malicious(
            msg.sender,
            Some(Evidence::InvalidPrecommit(signed.encode())),
          ))?;
        }
        return Ok(true);
      }
    }
    Ok(false)
  }

  async fn message(
    &mut self,
    signed: &SignedMessageFor<N>,
  ) -> Result<Option<N::Block>, TendermintError<N>> {
    let msg = &signed.msg;
    if msg.block != self.block.number {
      Err(TendermintError::Temporal)?;
    }

    if (msg.block == self.block.number) &&
      (msg.round == self.block.round().number) &&
      (msg.data.step() == Step::Propose)
    {
      log::trace!("received Propose for block {}, round {}", msg.block.0, msg.round.0);
    }

    // If this is a precommit, verify its signature
    self.verify_precommit_signature(signed)?;

    // Only let the proposer propose
    if matches!(msg.data, Data::Proposal(..)) &&
      (msg.sender != self.weights.proposer(msg.block, msg.round))
    {
      log::warn!(target: "tendermint", "Validator who wasn't the proposer proposed");
      // TODO: This should have evidence
      Err(TendermintError::Malicious(msg.sender, None))?;
    };

    if !self.block.log.log(signed.clone())? {
      return Err(TendermintError::AlreadyHandled);
    }
    log::debug!(target: "tendermint", "received new tendermint message");

    // All functions, except for the finalizer and the jump, are locked to the current round

    // Run the finalizer to see if it applies
    // 49-52
    if matches!(msg.data, Data::Proposal(..)) || matches!(msg.data, Data::Precommit(_)) {
      let proposer = self.weights.proposer(self.block.number, msg.round);

      // Get the proposal
      if let Some(proposal_signed) = self.block.log.get(msg.round, proposer, Step::Propose) {
        if let Data::Proposal(_, block) = &proposal_signed.msg.data {
          // Check if it has gotten a sufficient amount of precommits
          // Uses a junk signature since message equality disregards the signature
          if self.block.log.has_consensus(
            msg.round,
            Data::Precommit(Some((block.id(), self.signer.sign(&[]).await))),
          ) {
            // If msg.round is in the future, these Precommits won't have their inner signatures
            // verified
            // It should be impossible for msg.round to be in the future however, as this requires
            // 67% of validators to Precommit, and we jump on 34% participating in the new round
            // The one exception would be if a validator had 34%, and could cause participation to
            // go from 33% (not enough to jump) to 67%, without executing the below code
            // This also would require the local machine to be outside of allowed time tolerances,
            // or the validator with 34% to not be publishing Prevotes (as those would cause a
            // a jump)
            // Both are invariants
            // TODO: Replace this panic with an inner signature check
            assert!(msg.round.0 <= self.block.round().number.0);

            log::debug!(target: "tendermint", "block {} has consensus", msg.block.0);
            return Ok(Some(block.clone()));
          }
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
      if self.block.log.round_participation(msg.round) > self.weights.fault_threshold() {
        // Jump to the new round.
        let proposer = self.round(msg.round, None);

        // If this round already has precommit messages, verify their signatures
        let round_msgs = self.block.log.log[&msg.round].clone();
        for (validator, msgs) in &round_msgs {
          if let Some(existing) = msgs.get(&Step::Precommit) {
            if let Ok(res) = self.verify_precommit_signature(existing) {
              // Ensure this actually verified the signature instead of believing it shouldn't yet
              assert!(res);
            } else {
              // Remove the message so it isn't counted towards forming a commit/included in one
              // This won't remove the fact they precommitted for this block hash in the MessageLog
              // TODO: Don't even log these in the first place until we jump, preventing needing
              // to do this in the first place
              let msg = self
                .block
                .log
                .log
                .get_mut(&msg.round)
                .unwrap()
                .get_mut(validator)
                .unwrap()
                .remove(&Step::Precommit)
                .unwrap();

              // Slash the validator for publishing an invalid commit signature
              self
                .slash(
                  *validator,
                  SlashEvent::WithEvidence(Evidence::InvalidPrecommit(msg.encode())),
                )
                .await;
            }
          }
        }

        // If we're the proposer, return now we don't waste time on the current round
        // (as it doesn't have a proposal, since we didn't propose, and cannot complete)
        if proposer {
          return Ok(None);
        }
      } else {
        // Future round which we aren't ready to jump to, so return for now
        return Ok(None);
      }
    }

    // msg.round is now guaranteed to be equal to self.block.round().number
    debug_assert_eq!(msg.round, self.block.round().number);

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

    // All further operations require actually having the proposal in question
    let proposer = self.weights.proposer(self.block.number, self.block.round().number);
    let (vr, block) = if let Some(proposal_signed) =
      self.block.log.get(self.block.round().number, proposer, Step::Propose)
    {
      if let Data::Proposal(vr, block) = &proposal_signed.msg.data {
        (vr, block)
      } else {
        panic!("message for Step::Propose didn't have Data::Proposal");
      }
    } else {
      return Ok(None);
    };

    // 22-33
    if self.block.round().step == Step::Propose {
      // Delay error handling (triggering a slash) until after we vote.
      let (valid, err) = match self.network.validate(block).await {
        Ok(_) => (true, Ok(None)),
        Err(BlockError::Temporal) => (false, Ok(None)),
        Err(BlockError::Fatal) => (false, {
          log::warn!(target: "tendermint", "Validator proposed a fatally invalid block");
          // TODO: Produce evidence of this for the higher level code to decide what to do with
          Err(TendermintError::Malicious(proposer, None))
        }),
      };
      // Create a raw vote which only requires block validity as a basis for the actual vote.
      let raw_vote = Some(block.id()).filter(|_| valid);

      // If locked is none, it has a round of -1 according to the protocol. That satisfies
      // 23 and 29. If it's some, both are satisfied if they're for the same ID. If it's some
      // with different IDs, the function on 22 rejects yet the function on 28 has one other
      // condition
      let locked = self.block.locked.as_ref().map(|(_, id)| id == &block.id()).unwrap_or(true);
      let mut vote = raw_vote.filter(|_| locked);

      if let Some(vr) = vr {
        // Malformed message
        if vr.0 >= self.block.round().number.0 {
          log::warn!(target: "tendermint", "Validator claimed a round from the future was valid");
          Err(TendermintError::Malicious(
            msg.sender,
            Some(Evidence::InvalidValidRound(signed.encode())),
          ))?;
        }

        if self.block.log.has_consensus(*vr, Data::Prevote(Some(block.id()))) {
          // Allow differing locked values if the proposal has a newer valid round
          // This is the other condition described above
          if let Some((locked_round, _)) = self.block.locked.as_ref() {
            vote = vote.or_else(|| raw_vote.filter(|_| locked_round.0 <= vr.0));
          }

          self.broadcast(Data::Prevote(vote));
          return err;
        }
      } else {
        self.broadcast(Data::Prevote(vote));
        return err;
      }

      return Ok(None);
    }

    if self
      .block
      .valid
      .as_ref()
      .map(|(round, _)| round != &self.block.round().number)
      .unwrap_or(true)
    {
      // 36-43

      // The run once condition is implemented above. Since valid will always be set by this, it
      // not being set, or only being set historically, means this has yet to be run

      if self.block.log.has_consensus(self.block.round().number, Data::Prevote(Some(block.id()))) {
        match self.network.validate(block).await {
          Ok(_) => (),
          // BlockError::Temporal is due to a temporal error we have, yet a supermajority of the
          // network does not, Because we do not believe this block to be fatally invalid, and
          // because a supermajority deems it valid, accept it.
          Err(BlockError::Temporal) => (),
          Err(BlockError::Fatal) => {
            log::warn!(target: "tendermint", "Validator proposed a fatally invalid block");
            // TODO: Produce evidence of this for the higher level code to decide what to do with
            Err(TendermintError::Malicious(proposer, None))?
          }
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
