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
use round::RoundData;

mod block;
use block::BlockData;

pub(crate) mod message_log;

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

pub fn commit_msg(end_time: u64, id: &[u8]) -> Vec<u8> {
  [&end_time.to_le_bytes(), id].concat()
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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum SlashReason {
  FailToPropose,
  InvalidBlock,
  InvalidProposer,
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub enum Evidence {
  ConflictingMessages(Vec<u8>, Vec<u8>),
  InvalidPrecommit(Vec<u8>),
  InvalidValidRound(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TendermintError {
  Malicious,
  Temporal,
  AlreadyHandled,
  InvalidEvidence,
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

pub fn decode_signed_message<N: Network>(mut data: &[u8]) -> Option<SignedMessageFor<N>> {
  SignedMessageFor::<N>::decode(&mut data).ok()
}

fn decode_and_verify_signed_message<N: Network>(
  data: &[u8],
  schema: &N::SignatureScheme,
) -> Result<SignedMessageFor<N>, TendermintError> {
  let msg = decode_signed_message::<N>(data).ok_or(TendermintError::InvalidEvidence)?;

  // verify that evidence messages are signed correctly
  if !msg.verify_signature(schema) {
    Err(TendermintError::InvalidEvidence)?;
  }

  Ok(msg)
}

pub fn verify_tendermint_evience<N: Network>(
  evidence: &Evidence,
  schema: &N::SignatureScheme,
  commit: impl Fn(u64) -> Option<Commit<N::SignatureScheme>>,
) -> Result<(), TendermintError> {
  match evidence {
    Evidence::ConflictingMessages(first, second) => {
      let first = decode_and_verify_signed_message::<N>(first, schema)?.msg;
      let second = decode_and_verify_signed_message::<N>(second, schema)?.msg;

      // Make sure they're distinct messages, from the same sender, within the same block
      if (first == second) || (first.sender != second.sender) || (first.block != second.block) {
        Err(TendermintError::InvalidEvidence)?;
      }

      // Distinct messages within the same step
      if !((first.round == second.round) && (first.data.step() == second.data.step())) {
        Err(TendermintError::InvalidEvidence)?;
      }
    }
    Evidence::InvalidPrecommit(msg) => {
      let msg = decode_and_verify_signed_message::<N>(msg, schema)?.msg;

      let Data::Precommit(Some((id, sig))) = &msg.data else {
        Err(TendermintError::InvalidEvidence)?
      };
      // TODO: We need to be passed in the genesis time to handle this edge case
      if msg.block.0 == 0 {
        Err(TendermintError::InvalidEvidence)?
        // todo!("invalid precommit signature on first block")
      }

      // get the last commit
      let prior_commit = match commit(msg.block.0 - 1) {
        Some(c) => c,
        // If we have yet to sync the block in question, we will return InvalidEvidence based
        // on our own temporal ambiguity
        // This will also cause an InvalidEvidence for anything using a non-existent block,
        // yet that's valid behavior
        // TODO: Double check the ramifications of this
        _ => Err(TendermintError::InvalidEvidence)?,
      };

      // calculate the end time till the msg round
      let mut last_end_time = CanonicalInstant::new(prior_commit.end_time);
      for r in 0 ..= msg.round.0 {
        last_end_time = RoundData::<N>::new(RoundNumber(r), last_end_time).end_time();
      }

      // verify that the commit was actually invalid
      if schema.verify(msg.sender, &commit_msg(last_end_time.canonical(), id.as_ref()), sig) {
        Err(TendermintError::InvalidEvidence)?
      }
    }
    Evidence::InvalidValidRound(msg) => {
      let msg = decode_and_verify_signed_message::<N>(msg, schema)?.msg;

      let Data::Proposal(Some(vr), _) = &msg.data else { Err(TendermintError::InvalidEvidence)? };
      if vr.0 < msg.round.0 {
        Err(TendermintError::InvalidEvidence)?
      }
    }
  }
  Ok(())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SlashEvent {
  Id(SlashReason, u64, u32),
  WithEvidence(Evidence),
}

// Struct for if various upon handlers have been triggered to ensure they don't trigger multiple
// times.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Upons {
  upon_prevotes: bool,
  upon_successful_current_round_prevotes: bool,
  upon_negative_current_round_prevotes: bool,
  upon_precommits: bool,
}

/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  db: N::Db,
  genesis: [u8; 32],

  network: N,
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  validators: N::SignatureScheme,
  weights: Arc<N::Weights>,

  queue: VecDeque<MessageFor<N>>,
  msg_recv: mpsc::UnboundedReceiver<SignedMessageFor<N>>,
  synced_block_recv: mpsc::UnboundedReceiver<SyncedBlock<N>>,
  synced_block_result_send: mpsc::UnboundedSender<bool>,

  block: BlockData<N>,
  upons: Upons,
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
        target: "tendermint",
        "resetting when prior round ended {}ms ago",
        Instant::now().saturating_duration_since(round_end.instant()).as_millis(),
      );
    }
    log::trace!(
      target: "tendermint",
      "sleeping until round ends in {}ms",
      time_until_round_end.as_millis(),
    );
    sleep(time_until_round_end).await;

    // Clear our outbound message queue
    self.queue = VecDeque::new();

    // Create the new block
    self.block = BlockData::new(
      self.db.clone(),
      self.genesis,
      self.weights.clone(),
      BlockNumber(self.block.number.0 + 1),
      self.signer.validator_id().await,
      proposal,
    );

    // Clear upons
    self.upons = Upons {
      upon_prevotes: false,
      upon_successful_current_round_prevotes: false,
      upon_negative_current_round_prevotes: false,
      upon_precommits: false,
    };

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

  fn proposal_for_round(&self, round: RoundNumber) -> Option<(Option<RoundNumber>, &N::Block)> {
    let proposer = self.weights.proposer(self.block.number, round);
    if let Some(proposal_signed) = self.block.log.get(round, proposer, Step::Propose) {
      if let Data::Proposal(vr, block) = &proposal_signed.msg.data {
        Some((*vr, block))
      } else {
        panic!("message for Step::Propose didn't have Data::Proposal");
      }
    } else {
      None?
    }
  }

  // L22-27
  fn upon_proposal_without_valid_round(&mut self) {
    if self.block.round().step != Step::Propose {
      return;
    }

    // If we have the proposal message...
    let Some((None, block)) = self.proposal_for_round(self.block.round().number) else {
      return;
    };

    // There either needs to not be a locked value or it must be equivalent
    #[allow(clippy::map_unwrap_or)]
    if self
      .block
      .locked
      .as_ref()
      .map(|(_round, locked_block)| block.id() == *locked_block)
      .unwrap_or(true)
    {
      self.broadcast(Data::Prevote(Some(block.id())));
    } else {
      self.broadcast(Data::Prevote(None));
    }
  }

  // L28-33
  fn upon_proposal_with_valid_round(&mut self) {
    if self.block.round().step != Step::Propose {
      return;
    }

    // If we have the proposal message...
    let Some((Some(proposal_valid_round), block)) =
      self.proposal_for_round(self.block.round().number)
    else {
      return;
    };

    // Check we have the necessary prevotes
    if !self.block.log.has_consensus(proposal_valid_round, &Data::Prevote(Some(block.id()))) {
      return;
    }

    // We don't check valid round < current round as the `message` function does

    // If locked is None, lockedRoundp is -1 and less than valid round
    #[allow(clippy::map_unwrap_or)]
    let locked_clause_1 = self
      .block
      .locked
      .as_ref()
      .map(|(locked_round, _block)| locked_round.0 <= proposal_valid_round.0)
      .unwrap_or(true);
    // The second clause is if the locked values are equivalent. If no value is locked, they aren't
    #[allow(clippy::map_unwrap_or)]
    let locked_clause_2 = self
      .block
      .locked
      .as_ref()
      .map(|(_round, locked_block)| block.id() == *locked_block)
      .unwrap_or(false);

    if locked_clause_1 || locked_clause_2 {
      self.broadcast(Data::Prevote(Some(block.id())));
    } else {
      self.broadcast(Data::Prevote(None));
    }
  }

  // L34-35
  fn upon_prevotes(&mut self) {
    if self.upons.upon_prevotes || (self.block.round().step != Step::Prevote) {
      return;
    }

    if self.block.log.has_participation(self.block.round().number, Step::Prevote) {
      self.block.round_mut().set_timeout(Step::Prevote);
      self.upons.upon_prevotes = true;
    }
  }

  // L36-43
  async fn upon_successful_current_round_prevotes(&mut self) {
    // Returning if `self.step == Step::Propose` is equivalent to guarding `step >= prevote`
    if self.upons.upon_successful_current_round_prevotes ||
      (self.block.round().step == Step::Propose)
    {
      return;
    }

    // If we have the proposal message...
    let Some((_, block)) = self.proposal_for_round(self.block.round().number) else {
      return;
    };

    // Check we have the necessary prevotes
    if !self.block.log.has_consensus(self.block.round().number, &Data::Prevote(Some(block.id()))) {
      return;
    }

    let block = block.clone();
    self.upons.upon_successful_current_round_prevotes = true;

    if self.block.round().step == Step::Prevote {
      self.block.locked = Some((self.block.round().number, block.id()));
      let signature = self
        .signer
        .sign(&commit_msg(
          self.block.end_time[&self.block.round().number].canonical(),
          block.id().as_ref(),
        ))
        .await;
      self.broadcast(Data::Precommit(Some((block.id(), signature))));
    }
    self.block.valid = Some((self.block.round().number, block));
  }

  // L44-46
  fn upon_negative_current_round_prevotes(&mut self) {
    if self.upons.upon_negative_current_round_prevotes || (self.block.round().step != Step::Prevote)
    {
      return;
    }

    if self.block.log.has_consensus(self.block.round().number, &Data::Prevote(None)) {
      self.broadcast(Data::Precommit(None));
    }

    self.upons.upon_negative_current_round_prevotes = true;
  }

  // L47-48
  fn upon_precommits(&mut self) {
    if self.upons.upon_precommits {
      return;
    }

    if self.block.log.has_participation(self.block.round().number, Step::Precommit) {
      self.block.round_mut().set_timeout(Step::Precommit);
      self.upons.upon_precommits = true;
    }
  }

  // L22-48
  async fn all_current_round_upons(&mut self) {
    self.upon_proposal_without_valid_round();
    self.upon_proposal_with_valid_round();
    self.upon_prevotes();
    self.upon_successful_current_round_prevotes().await;
    self.upon_negative_current_round_prevotes();
    self.upon_precommits();
  }

  // L49-54
  async fn upon_successful_precommits(&mut self, round: RoundNumber) -> bool {
    // If we have the proposal message...
    let Some((_, block)) = self.proposal_for_round(round) else { return false };

    // Check we have the necessary precommits
    // The precommit we check we have consensus upon uses a junk signature since message equality
    // disregards the signature
    if !self
      .block
      .log
      .has_consensus(round, &Data::Precommit(Some((block.id(), self.signer.sign(&[]).await))))
    {
      return false;
    }

    // Get all participants in this commit
    let mut validators = vec![];
    let mut sigs = vec![];
    // Get all precommits for this round
    for (validator, msgs) in &self.block.log.log[&round] {
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

    // Form the commit itself
    let commit_msg = commit_msg(self.block.end_time[&round].canonical(), block.id().as_ref());
    let commit = Commit {
      end_time: self.block.end_time[&round].canonical(),
      validators: validators.clone(),
      signature: self.network.signature_scheme().aggregate(&validators, &commit_msg, &sigs),
    };
    debug_assert!(self.network.verify_commit(block.id(), &commit));

    // Add the block and reset the machine
    log::info!(
      target: "tendermint",
      "TendermintMachine produced block {}",
      hex::encode(block.id().as_ref()),
    );
    let id = block.id();
    let proposal = self.network.add_block(block.clone(), commit).await;
    log::trace!(
      target: "tendermint",
      "added block {} (produced by machine)",
      hex::encode(id.as_ref()),
    );
    self.reset(round, proposal).await;

    true
  }

  // L49-54
  async fn all_any_round_upons(&mut self, round: RoundNumber) -> bool {
    self.upon_successful_precommits(round).await
  }

  // Returns Ok(true) if this was a Precommit which had either no signature or its signature
  // validated
  // Returns Ok(false) if it wasn't a Precommit or the signature wasn't validated yet
  // Returns Err if the signature was invalid
  async fn verify_precommit_signature(
    &mut self,
    signed: &SignedMessageFor<N>,
  ) -> Result<bool, TendermintError> {
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
          log::warn!(target: "tendermint", "validator produced an invalid commit signature");
          self
            .slash(
              msg.sender,
              SlashEvent::WithEvidence(Evidence::InvalidPrecommit(signed.encode())),
            )
            .await;
          Err(TendermintError::Malicious)?;
        }
        return Ok(true);
      }
    }
    Ok(false)
  }

  async fn message(&mut self, signed: &SignedMessageFor<N>) -> Result<(), TendermintError> {
    let msg = &signed.msg;
    if msg.block != self.block.number {
      Err(TendermintError::Temporal)?;
    }

    if (msg.block == self.block.number) &&
      (msg.round == self.block.round().number) &&
      (msg.data.step() == Step::Propose)
    {
      log::trace!(
        target: "tendermint",
        "received Propose for block {}, round {}",
        msg.block.0,
        msg.round.0,
      );
    }

    // If this is a precommit, verify its signature
    self.verify_precommit_signature(signed).await?;

    // Only let the proposer propose
    if matches!(msg.data, Data::Proposal(..)) &&
      (msg.sender != self.weights.proposer(msg.block, msg.round))
    {
      log::warn!(target: "tendermint", "Validator who wasn't the proposer proposed");
      // TODO: This should have evidence
      self
        .slash(msg.sender, SlashEvent::Id(SlashReason::InvalidProposer, msg.block.0, msg.round.0))
        .await;
      Err(TendermintError::Malicious)?;
    };

    // If this is a proposal, verify the block
    // If the block is invalid, drop the message, letting the timeout cover it
    // This prevents needing to check if valid inside every `upon` block
    if let Data::Proposal(_, block) = &msg.data {
      match self.network.validate(block).await {
        Ok(()) => {}
        Err(BlockError::Temporal) => return Err(TendermintError::Temporal),
        Err(BlockError::Fatal) => {
          log::warn!(target: "tendermint", "validator proposed a fatally invalid block");
          self
            .slash(
              msg.sender,
              SlashEvent::Id(SlashReason::InvalidBlock, self.block.number.0, msg.round.0),
            )
            .await;
          Err(TendermintError::Malicious)?;
        }
      };
    }

    // If this is a proposal, verify the valid round isn't fundamentally invalid
    if let Data::Proposal(Some(valid_round), _) = msg.data {
      if valid_round.0 >= msg.round.0 {
        log::warn!(
          target: "tendermint",
          "proposed proposed with a syntactically invalid valid round",
        );
        self
          .slash(msg.sender, SlashEvent::WithEvidence(Evidence::InvalidValidRound(msg.encode())))
          .await;
        Err(TendermintError::Malicious)?;
      }
    }

    // Add it to the log, returning if it was already handled
    match self.block.log.log(signed.clone()) {
      Ok(true) => {}
      Ok(false) => Err(TendermintError::AlreadyHandled)?,
      Err(evidence) => {
        self.slash(msg.sender, SlashEvent::WithEvidence(evidence)).await;
        Err(TendermintError::Malicious)?;
      }
    }
    log::debug!(
      target: "tendermint",
      "received new tendermint message (block: {}, round: {}, step: {:?})",
      msg.block.0,
      msg.round.0,
      msg.data.step(),
    );

    // Run all `upons` run for any round
    // If it returned true, we added a new block, so return
    if self.all_any_round_upons(msg.round).await {
      return Ok(());
    }

    // Check if we need to jump ahead
    #[allow(clippy::comparison_chain)]
    if msg.round.0 < self.block.round().number.0 {
      // Prior round, disregard if not finalizing
      return Ok(());
    } else if msg.round.0 > self.block.round().number.0 {
      // 55-56
      // Jump, enabling processing by the below code
      if self.block.log.round_participation(msg.round) > self.weights.fault_threshold() {
        log::debug!(
          target: "tendermint",
          "jumping from round {} to round {}",
          self.block.round().number.0,
          msg.round.0,
        );

        // Jump to the new round.
        self.round(msg.round, None);

        // If this round already has precommit messages, verify their signatures
        let round_msgs = self.block.log.log[&msg.round].clone();
        for (validator, msgs) in &round_msgs {
          if let Some(existing) = msgs.get(&Step::Precommit) {
            if let Ok(res) = self.verify_precommit_signature(existing).await {
              // Ensure this actually verified the signature instead of believing it shouldn't yet
              assert!(res);
            } else {
              // Remove the message so it isn't counted towards forming a commit/included in one
              // This won't remove the fact they precommitted for this block hash in the MessageLog
              // TODO: Don't even log these in the first place until we jump, preventing needing
              // to do this in the first place
              self
                .block
                .log
                .log
                .get_mut(&msg.round)
                .unwrap()
                .get_mut(validator)
                .unwrap()
                .remove(&Step::Precommit)
                .unwrap();
            }
          }
        }
      } else {
        // Future round which we aren't ready to jump to, so return for now
        return Ok(());
      }
    }

    // msg.round is now guaranteed to be equal to self.block.round().number
    debug_assert_eq!(msg.round, self.block.round().number);

    // Run all `upons` run for the current round
    self.all_current_round_upons().await;

    Ok(())
  }

  /// Create a new Tendermint machine, from the specified point, with the specified block as the
  /// one to propose next. This will return a channel to send messages from the gossip layer and
  /// the machine itself. The machine should have `run` called from an asynchronous task.
  #[allow(clippy::new_ret_no_self)]
  pub async fn new(
    db: N::Db,
    network: N,
    genesis: [u8; 32],
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
        // L01-10
        let mut machine = TendermintMachine {
          db: db.clone(),
          genesis,

          network,
          signer,
          validators,
          weights: weights.clone(),

          queue: VecDeque::new(),
          msg_recv,
          synced_block_recv,
          synced_block_result_send,

          block: BlockData::new(
            db,
            genesis,
            weights,
            BlockNumber(last_block.0 + 1),
            validator_id,
            Some(proposal),
          ),

          upons: Upons {
            upon_prevotes: false,
            upon_successful_current_round_prevotes: false,
            upon_negative_current_round_prevotes: false,
            upon_precommits: false,
          },
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
      let mut queue_future =
        if self.queue.is_empty() { Fuse::terminated() } else { future::ready(()).fuse() };

      if let Some((our_message, msg, mut sig)) = futures_util::select_biased! {
        // Handle a new block occurring externally (from an external sync loop)
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
        () = queue_future => {
          Some((true, self.queue.pop_front().unwrap(), None))
        },

        // L57-67
        // Handle any timeouts
        step = self.block.round().timeout_future().fuse() => {
          // Remove the timeout so it doesn't persist, always being the selected future due to bias
          // While this does enable the timeout to be entered again, the timeout setting code will
          // never attempt to add a timeout after its timeout has expired
          // (due to it setting an `upon` boolean)
          self.block.round_mut().timeouts.remove(&step);

          match step {
            Step::Propose => {
              // Only run if it's still the step in question
              if self.block.round().step == step {
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
              }
            },
            Step::Prevote => {
              // Only run if it's still the step in question
              if self.block.round().step == step {
                self.broadcast(Data::Precommit(None))
              }
            },
            Step::Precommit => {
              self.round(RoundNumber(self.block.round().number.0 + 1), None);
            }
          };

          // Execute the upons now that the state has changed
          self.all_any_round_upons(self.block.round().number).await;
          self.all_current_round_upons().await;

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

        let signed_msg = SignedMessage { msg: msg.clone(), sig: sig.clone() };
        let res = self.message(&signed_msg).await;
        // If this is our message, and we hit an invariant, we could be slashed.
        // We only broadcast our message after running it ourselves, to ensure it doesn't error, to
        // ensure we don't get slashed on invariants.
        if res.is_err() && our_message {
          panic!("honest node (ourselves) had invalid behavior");
        }

        // Re-broadcast this since it's an original consensus message
        self.network.broadcast(signed_msg).await;
      }
    }
  }
}
