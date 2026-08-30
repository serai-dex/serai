use core::{
  sync::atomic::{Ordering, AtomicU64},
  pin::Pin,
  time::Duration,
};
use alloc::{boxed::Box, sync::Arc};
use std::time::Instant;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::Transaction;

use crate::{
  SignatureScheme, ValidatorSet as _, BlockNumber, RoundNumber, Block, CommitFor, Blockchain,
  Signer, ValidRound, Data, MessageFor, MessageError, Network,
};

mod block_proposal;
use block_proposal::*;

mod round_messages;
use round_messages::*;

mod round_metrics;
use round_metrics::*;

mod observed_block_numbers;
use observed_block_numbers::*;

mod db;

pub(super) trait Borshy: borsh::BorshSerialize + borsh::BorshDeserialize {}
impl<B: borsh::BorshSerialize + borsh::BorshDeserialize> Borshy for B {}

pub(super) trait BorshyBlockchain:
  Blockchain<
    Validator: Borshy,
    SignatureScheme: SignatureScheme<Signature: Borshy, AggregateSignature: Borshy>,
    Block: Borshy + Block<Hash: Borshy>,
  >
{
}
impl<
  B: Blockchain<
      Validator: Borshy,
      SignatureScheme: SignatureScheme<Signature: Borshy, AggregateSignature: Borshy>,
      Block: Borshy + Block<Hash: Borshy>,
    >,
> BorshyBlockchain for B
{
}

/// The current step within the round.
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) enum Step {
  Propose,
  Prevote,
  Precommit,
}

/// The state for the Tendermint consensus protocol.
///
/// This is intertwined with participating in consensus and can not be used for third-party
/// observation.
pub(super) struct State<B: Blockchain> {
  /// The current block number.
  block_number: BlockNumber,
  /// A public reference to the block number.
  ///
  /// This is updated approximately as the state's block number is.
  block_number_ref: Arc<AtomicU64>,

  /// A tracker for which block numbers we've observed validators attempting consensus for.
  observed_block_numbers: ObservedBlockNumbers<B::Validator>,
  /// A public reference to the greatest observed block number.
  observed_block_number_ref: Arc<AtomicU64>,

  /// Our proposal for this block.
  proposal: Pin<Box<BlockProposal<B::Block, B::BlockProposal>>>,

  /// The current round number.
  round_number: RoundNumber,
  /// The pending timeout for the current step.
  ///
  /// This is represented as its start time and duration.
  ///
  /// This is only used for the proposal/prevote steps' timeouts as:
  /// - The proposal timeout is only scheduled on L21, after assigning the step to propose
  /// - The prevote timeout is only scheduled on L35, while the step is prevote
  ///
  /// and therefore the preposal/prevote timeouts are specific to the _current_ step.
  pending_step_timeout: Option<(Instant, Duration)>,
  /// The pending precommit timeout.
  ///
  /// This is represented as its start time and duration.
  ///
  /// This is explicitly used for the precommit step as the precommit timeout is scheduled on L48
  /// _regardless of the current step_.
  pending_precommit_timeout: Option<(Instant, Duration)>,
  /// The current step.
  step: Step,

  /// The valid value and round, if one has been decided.
  ///
  /// The formal description initializes this to `(-1, null)`, though we represent such a case as
  /// `None`.
  #[expect(clippy::type_complexity)]
  valid:
    Option<(ValidRound<<B::SignatureScheme as SignatureScheme>::AggregateSignature>, B::Block)>,

  /// The locked value and round, if one has been decided.
  ///
  /// The formal description initializes this to `(-1, null)`, though we represent such a case as
  /// `None`. We additionally only store the locked block's ID, not the locked block in its entity,
  /// as we solely need this to perform comparison checks with. Per the definition of
  /// [`Block::id`], the equality of IDs is equal to the equality of the blocks themselves.
  locked: Option<(RoundNumber, <B::Block as Block>::Hash)>,

  /// The metrics from this round.
  round_metrics: RoundMetrics<B>,

  /// The messages from validators for the rounds we're actively tracking.
  round_messages: TrackedRounds<B>,

  /// Our latest prevote messages.
  ///
  /// We rebroadcast this with the assumption all other validators will be doing the same for their
  /// own messages. This will cause a latent peer to jump to the current round, get past the
  /// prevote phase, and send their own precommit.
  ///
  /// We keep the latest _two_ prevotes as if we send our own prevote for round #n+1, there may
  /// only be `f` such validators doing so, while the remaining `f + 1` validators who have been
  /// online may be stuck on round #n. If `f` of these validators then go offline, replaced by `f`
  /// validators who have been offline the entire time, those validators will see `f+1` precommits
  /// for round #n (which is insufficient to make progress, requiring observing `2 f + 1`). By
  /// keeping our prevote for the prior round as well, the validators who were offline the entire
  /// time may be handheld through the prevote step, then sending their own precommits, finally
  /// achieving the necessary precommits for _everyone_ to move to the next round.
  our_latest_prevotes: [Option<MessageFor<B>>; 2],

  /// Our latest precommit message.
  ///
  /// We rebroadcast this with the assumption all other validators will be doing the same for their
  /// own messages. This will cause a latent peer to jump to the current round, and once we have
  /// `2 f + 1` precommits, start the next round.
  ///
  /// We only store our latest precommit as this implies the existence of `2 f + 1` prevotes for
  /// this round, as sufficient for everyone to jump to this round even if `f` validators are
  /// substituted.
  our_latest_precommit: Option<MessageFor<B>>,
}

impl<B: BorshyBlockchain> State<B> {
  /// The current block number.
  #[must_use]
  pub(super) fn block_number(&self) -> BlockNumber {
    self.block_number
  }

  /// Create a new reference to the number for the block we're currently attempting to achieve
  /// consensus over.
  ///
  /// This reference is an atomic which is updated after a block is added to the underlying
  /// blockchain. Accordingly, it may desynchronize from the underlying blockchain for a brief
  /// moment. For the exact current block number, [`State::block_number`] MUST be used.
  ///
  /// This MAY be invalidated, as possible if any reference is used to write to it (other than the
  /// one internal to the state). This is accepted as this is solely an internal API.
  pub(super) fn block_number_ref(&self) -> Arc<AtomicU64> {
    self.block_number_ref.clone()
  }

  /// Create a new reference to the greatest block number we've observed validators attempting to
  /// achieve consensus over.
  ///
  /// This reference is an atomic which is updated after observing `f + 1` validators attempting to
  /// achieve consensus over this block number. Accordingly, it may desynchronize from related
  /// state for a brief moment. It is only intended as a guideline, though it will not have a block
  /// number _higher_ than the actually greatest observed block number.
  ///
  /// This MAY be invalidated, as possible if any reference is used to write to it (other than the
  /// one internal to the state). This is accepted as this is solely an internal API.
  pub(super) fn observed_block_number_ref(&self) -> Arc<AtomicU64> {
    self.observed_block_number_ref.clone()
  }

  /// Yield a proposal message if we are the proposer.
  ///
  /// This MUST only be called once when the round starts.
  ///
  /// This corresponds to L14-L19.
  #[must_use]
  async fn proposal_message<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
  ) -> Option<MessageFor<B>> {
    let validator_set = blockchain.validator_set();

    // L14
    let proposer = validator_set.proposer(self.block_number, self.round_number);
    if proposer != signer.validator() {
      None?;
    }

    let (valid_round, proposal) = match &self.valid {
      // L15-L16
      Some((valid_round, block)) => (Some(valid_round.clone()), block.clone()),
      // L17-L18
      None => {
        match crate::timeout::<crate::SleepForNetwork<_, _, _, _, N>, _>(
          self.proposal.as_mut(),
          N::BLOCK_PROCESSING_TIME,
        )
        .await
        {
          // We did not have a valid round but we do have a proposal
          Ok(proposal) => (None, proposal),
          // We have no proposal and therefore cannot yield a proposal message
          Err(crate::TimeoutExpired) => None?,
        }
      }
    };

    // L19
    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();
    self.round_metrics.accumulate_proposal(
      genesis,
      validator_set,
      txn,
      proposer,
      valid_round.as_ref().map(|ValidRound { round_number, aggregate_signature: _ }| *round_number),
      proposal.clone(),
    );
    Some(
      MessageFor::<B>::sign(
        signer,
        genesis,
        self.block_number,
        self.round_number,
        Data::Proposal { valid_round, proposal },
      )
      .await,
    )
  }

  // L24-L27, L30-L33, L59-L60
  #[must_use]
  async fn prevote_message(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    block: Option<<B::Block as Block>::Hash>,
  ) -> MessageFor<B> {
    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();
    let validator = signer.validator();

    let result = MessageFor::<B>::sign(
      signer,
      genesis,
      self.block_number,
      self.round_number,
      Data::Prevote { block },
    )
    .await;

    assert!(self.round_metrics.accumulate_prevote(
      genesis,
      blockchain.validator_set(),
      txn,
      validator,
      block,
      result.signature.clone()
    ));

    let _ = self.pending_step_timeout.take();
    db::PendingStepTimeout::del(txn, genesis);
    self.step = Step::Prevote;
    db::Step::set(txn, genesis, &self.step);

    self.our_latest_prevotes = [self.our_latest_prevotes[1].take(), Some(result.clone())];
    db::OurLatestPrevotes::<B>::set(txn, genesis, &self.our_latest_prevotes);
    result
  }

  /// Yield a prevote message, if we should.
  ///
  /// This corresponds to L22-L33 and does not cover the case where the timeout occurs.
  #[must_use]
  async fn prevote_upon_proposal_message(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
  ) -> Option<MessageFor<B>> {
    if !matches!(self.step, Step::Propose) {
      None?;
    }

    let ObservedProposal { proposer, valid_round, proposal } =
      self.round_metrics.observed_proposal()?;

    let block = ((blockchain.validate(proposer, proposal).await.is_ok()) &&
      (match valid_round {
        /*
          L22-L23, where we've already checked:
          - the step
          - we have the proposal
          - the metrics bound that we only accumulate proposals from the right proposer
          - `valid(v)`
        */
        None => match &self.locked {
          None => true,
          Some((_locked_round, locked_value)) => proposal.hash() == (*locked_value),
        },
        /*
          L28, where we've already checked:
          - the step
          - we have the proposal
          - the metrics bound that we only accumulate proposals from the right proposer and with a
            syntactically correct `valid_round`
          - the `ValidRound` contains evidence of sufficient prevotes having existed for this
            round, and block, and was already verified
          leaving this with nothing further to check in order to correspond to this line.
        */
        Some(round_number) => {
          // L29, where we've already checked `valid(v)`
          match &self.locked {
            Some((locked_round, locked_value)) => {
              ((*locked_round) <= round_number) || (proposal.hash() == (*locked_value))
            }
            None => true,
          }
        }
      }))
    .then(|| proposal.hash());

    // L24-L27, L30-L33
    Some(self.prevote_message(blockchain, signer, txn, block).await)
  }

  // L40-L41, L45-L46, L63-L64
  #[expect(clippy::type_complexity)]
  #[must_use]
  async fn precommit_message(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    block_and_precommit_signature: Option<(
      <B::Block as Block>::Hash,
      <B::SignatureScheme as SignatureScheme>::Signature,
    )>,
  ) -> MessageFor<B> {
    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();
    assert!(self.round_metrics.accumulate_precommit(
      genesis,
      blockchain.validator_set(),
      txn,
      signer.validator(),
      block_and_precommit_signature.clone()
    ));
    let _ = self.pending_step_timeout.take();
    db::PendingStepTimeout::del(txn, genesis);
    self.step = Step::Precommit;
    db::Step::set(txn, genesis, &self.step);
    let result = MessageFor::<B>::sign(
      signer,
      genesis,
      self.block_number,
      self.round_number,
      Data::Precommit { block_and_precommit_signature },
    )
    .await;
    /*
      Because we've observed `2 f + 1` prevotes in this round, we don't need to keep messages from
      the prior round around to ensure every validator eventually participates in this round.
    */
    self.our_latest_prevotes[0] = None;
    self.our_latest_precommit = Some(result.clone());
    db::OurLatestPrecommit::<B>::set(txn, genesis, &result);
    result
  }

  /// Yield a precommit message, if we should.
  ///
  /// This corresponds to L36-43 and does not cover L44-L46 nor the case where the timeout occurs.
  #[must_use]
  async fn precommit_some_message(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
  ) -> Option<MessageFor<B>> {
    /*
      L36

      Note this defers `valid(v)` to if a supermajority of validators have prevoted for it and
      therefore believe this value is valid.
    */
    let (proposal, valid_round) = {
      if !matches!(self.step, Step::Prevote | Step::Precommit) {
        None?;
      }

      /*
        "for the first time", implemented via checking if we've already written to `self.valid`
        (as we always will whenever we execute this hook)
      */
      if self.valid.as_ref().is_some_and(
        |(ValidRound { round_number, aggregate_signature: _ }, _block)| {
          (*round_number) >= self.round_number
        },
      ) {
        None?;
      }

      // [`RoundMetrics`] is bounded to only observe this if it is from the correct proposer
      let ObservedProposal { proposer: _, valid_round: _, proposal } =
        self.round_metrics.observed_proposal()?;

      let valid_round = self.round_metrics.observed_prevotes_for_proposal(blockchain)?;

      (proposal, valid_round)
    };

    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();

    // L42-L43
    {
      let valid = (valid_round, proposal.clone());
      db::Valid::<B>::set(txn, genesis, &valid);
      self.valid = Some(valid);
    }

    // L37
    if !matches!(self.step, Step::Prevote) {
      None?;
    }

    // L38-L39
    let proposal = proposal.hash();
    {
      let locked = (self.round_number, proposal);
      db::Locked::set(txn, genesis, &locked);
      self.locked = Some(locked);
    }

    // L40-L41
    let precommit_signature = CommitFor::<B>::sign::<B::SignatureScheme>(
      signer,
      genesis,
      self.block_number,
      self.round_number,
      proposal.as_ref(),
    )
    .await;
    Some(
      self.precommit_message(blockchain, signer, txn, Some((proposal, precommit_signature))).await,
    )
  }

  /// Respond to the accumulated messages.
  ///
  /// This corresponds to L22-L48.
  async fn respond<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
  ) -> RoundMessages<B> {
    let prevote_message = {
      // L22-L33
      let prevote_upon_proposal_message =
        self.prevote_upon_proposal_message(blockchain, signer, txn).await;

      // L57-L60
      let prevote_upon_timeout_message = if matches!(self.step, Step::Propose) &&
        self.pending_step_timeout.is_some_and(|(start, duration)| start.elapsed() >= duration)
      {
        blockchain.missed_proposal(
          blockchain.validator_set().proposer(self.block_number, self.round_number),
        );
        Some(self.prevote_message(blockchain, signer, txn, None).await)
      } else {
        None
      };

      // As these are mutually exclusive, we can represent both with a single `Option`
      prevote_upon_proposal_message.or(prevote_upon_timeout_message)
    };

    // L34-L35
    if matches!(self.step, Step::Prevote) &&
      self.pending_step_timeout.is_none() &&
      (self.round_metrics.observed_prevotes() >= blockchain.validator_set().threshold())
    {
      let duration = N::LATENCY_TIME
        .saturating_mul(u32::try_from(u64::from(self.round_number)).unwrap_or(u32::MAX));
      db::PendingStepTimeout::set(
        txn,
        blockchain.genesis().as_ref(),
        &db::timeout_in_ms_since_epoch(duration),
      );
      self.pending_step_timeout = Some((Instant::now(), duration));
    }

    let precommit_message = {
      // L36-L43
      let precommit_some_message = self.precommit_some_message(blockchain, signer, txn).await;

      // L44-L46, L61-L64
      let precommit_none_message = if matches!(self.step, Step::Prevote) &&
        ((self.round_metrics.observed_prevotes_for_none() >=
          blockchain.validator_set().threshold()) ||
          self
            .pending_step_timeout
            .is_some_and(|(start, duration)| start.elapsed() >= duration))
      {
        Some(self.precommit_message(blockchain, signer, txn, None).await)
      } else {
        None
      };

      precommit_some_message.or(precommit_none_message)
    };

    // L47-L48
    if self.pending_precommit_timeout.is_none() &&
      (self.round_metrics.observed_precommits() >= blockchain.validator_set().threshold())
    {
      let duration = N::LATENCY_TIME
        .saturating_mul(u32::try_from(u64::from(self.round_number)).unwrap_or(u32::MAX));
      db::PendingPrecommitTimeout::set(
        txn,
        blockchain.genesis().as_ref(),
        &db::timeout_in_ms_since_epoch(duration),
      );
      self.pending_precommit_timeout = Some((Instant::now(), duration));
    }

    let mut round_messages = RoundMessages::NONE;
    round_messages.insert(prevote_message);
    round_messages.insert(precommit_message);
    round_messages
  }

  // L11-L21
  async fn start_round<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    round: RoundNumber,
  ) -> RoundMessages<B> {
    debug_assert!(
      ((self.round_number == RoundNumber::ONE) && (self.round_number == round)) ||
        (self.round_number < round)
    );

    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();

    {
      let Self {
        block_number,
        round_number,
        pending_step_timeout,
        pending_precommit_timeout,
        step,

        round_metrics,

        // These values are consistent across rounds
        block_number_ref: _,
        observed_block_numbers: _,
        observed_block_number_ref: _,
        proposal: _,
        valid: _,
        locked: _,

        // This is independent of the round, used for detecting equivocations and if we're behind
        round_messages: _,
        // These are used for convincing other validators of the current round
        our_latest_prevotes: _,
        our_latest_precommit: _,
      } = self;
      // This is used to reset the `round_metrics` but is not mutated across rounds
      let block_number = *block_number;

      // L11-L13
      *round_number = round;
      db::RoundNumber::set(txn, genesis, round_number);
      *step = Step::Propose;
      db::Step::set(txn, genesis, &self.step);

      /*
        L20-L21

        This timeout is always set, even if this validator is the proposer, as it's unnecessarily
        set, it'll be immediately cleared when the proposer responds to their own proposal, and is
        a non-issue.
      */
      {
        let duration =
          N::BLOCK_DOWNLOADING_TIME.saturating_add(N::BLOCK_PROCESSING_TIME).saturating_add(
            N::LATENCY_TIME
              .saturating_mul(u32::try_from(u64::from(*round_number)).unwrap_or(u32::MAX)),
          );
        db::PendingStepTimeout::set(txn, genesis, &db::timeout_in_ms_since_epoch(duration));
        *pending_step_timeout = Some((Instant::now(), duration));
      }
      *pending_precommit_timeout = None;
      db::PendingPrecommitTimeout::del(txn, genesis);

      round_metrics.reset(block_number, *round_number);
    }

    // L14-L19
    let proposal_message = self.proposal_message::<N>(blockchain, signer, txn).await;

    // Accumulate all messages we've already seen for this round
    for message in self.round_messages.messages_for_round(self.round_number) {
      self.round_metrics.accumulate(genesis, blockchain.validator_set(), txn, message.clone());
    }

    let mut round_messages = self.respond::<N>(blockchain, signer, txn).await;
    round_messages.insert(proposal_message);
    round_messages
  }

  // L01-L10
  pub(super) async fn new<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    proposal: B::Block,
  ) -> (Self, RoundMessages<B>) {
    let genesis = blockchain.genesis();
    let genesis = genesis.as_ref();

    let (init, mut state) = {
      let validator_set = blockchain.validator_set();

      let getter = &*txn;

      let (init, block_number, round_number, step) = {
        let block_number = db::BlockNumber::get(getter, genesis);
        let round_number = db::RoundNumber::get(getter, genesis);
        let step = db::Step::get(getter, genesis);

        // All of these should be `None` upon initialization or `Some` otherwise
        debug_assert_eq!(block_number.is_some(), round_number.is_some());
        debug_assert_eq!(block_number.is_some(), step.is_some());

        let init = block_number.is_none();
        // We consider the genesis block, a constant outside of consensus, as block #0
        let block_number = block_number.unwrap_or(BlockNumber::ONE);
        // As [`RoundNumber`] documents, we count from `1`, not `0`
        let round_number = round_number.unwrap_or(RoundNumber::ONE);
        (init, block_number, round_number, step.unwrap_or(Step::Propose))
      };
      let block_number_ref = Arc::new(AtomicU64::new(u64::from(block_number)));

      let observed_block_number_ref = Arc::new(AtomicU64::new(u64::from(block_number)));

      let validators = validator_set.validators().into_iter().count();
      let state = State {
        block_number,
        block_number_ref,

        // This isn't DB backed as it's observational and will repopulate based on active messages
        observed_block_numbers: ObservedBlockNumbers::new(validators),
        observed_block_number_ref,

        proposal: Box::pin(BlockProposal::Ready { proposal }),

        round_number,
        pending_step_timeout: db::PendingStepTimeout::get(getter, genesis)
          .map(db::timeout_from_ms_since_epoch),
        pending_precommit_timeout: db::PendingPrecommitTimeout::get(getter, genesis)
          .map(db::timeout_from_ms_since_epoch),
        step,

        valid: db::Valid::<B>::get(getter, genesis),
        locked: db::Locked::get(getter, genesis),

        round_metrics: RoundMetrics::new(
          genesis,
          validator_set,
          getter,
          block_number,
          round_number,
        ),

        /*
          We do not save or reload `round_messages` as it's solely used for detecting equivocations
          (not necessary) and for determining when to jump ahead to a future round. We expect our
          fellow validators to rebroadcast their latest message however, meaning on reboot, we just
          have to wait for them to do so for us to repopulate this (and jump ahead as desired).
        */
        round_messages: TrackedRounds::new(validators),

        our_latest_prevotes: db::OurLatestPrevotes::<B>::get(getter, genesis)
          .unwrap_or([const { None }; 2]),
        our_latest_precommit: db::OurLatestPrecommit::<B>::get(getter, genesis),
      };

      (init, state)
    };

    let messages = if init {
      db::BlockNumber::set(txn, genesis, &BlockNumber::ONE);
      state.start_round::<N>(blockchain, signer, txn, state.round_number).await
    } else {
      RoundMessages::NONE
    };

    (state, messages)
  }

  /// React to a message received over the network.
  ///
  /// This returns either an iterator of the messages created in response _or_ an error regarding
  /// the message. if an error is returned, the internal state of this will have
  /// _no meaningful changes_ and will behave identically to a machine which did not handle this
  /// message in the first place.
  ///
  /// This future is NOT cancel-safe.
  pub(super) async fn message<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    message: MessageFor<B>,
  ) -> Result<
    RoundMessages<B>,
    MessageError<
      <B::SignatureScheme as SignatureScheme>::Signature,
      <B::SignatureScheme as SignatureScheme>::AggregateSignature,
      <B::Block as Block>::Hash,
    >,
  > {
    let validator_set = blockchain.validator_set();

    // If this is historic or for a future block, ignore this message
    if (message.block_number < self.block_number) || (message.round_number < self.round_number) {
      Err(MessageError::Stale)?;
    }
    if message.block_number > self.block_number {
      if let Some(observed_block_number) =
        self.observed_block_numbers.update(validator_set, message.validator, message.block_number)
      {
        let _ = self
          .observed_block_number_ref
          .fetch_max(u64::from(observed_block_number), Ordering::SeqCst);
      }
      Err(MessageError::Future)?;
    }
    debug_assert_eq!(message.block_number, self.block_number);
    debug_assert!(message.round_number >= self.round_number);

    // Verify this message's static properties
    message.static_verificiation(
      blockchain.genesis(),
      validator_set,
      blockchain.signature_scheme(),
    )?;

    // Update `round_messages`
    match self.round_messages.update(validator_set, message.validator, self.round_number, &message)
    {
      Updated::Fresh => {}
      /*
        This is for a round greater than or equal to the current round, but it's not the current
        round nor is it approximate to the latest round we've observed for this validator. It's a
        historic round (according to the view for the validator who sent it) being needlessly
        communicated at this time.
      */
      Updated::NotTracked => Err(MessageError::Stale)?,
      Updated::AlreadyHandled => return Err(MessageError::AlreadyHandled),
      Updated::Equivocation(slash_reason) => {
        blockchain.slash(message.validator, slash_reason);
        // TODO: Should we have an error for this, that this message was an equivocation?
        return Ok(RoundMessages::NONE);
      }
    }

    // If this message is for a future round, with sufficient participation, jump to this round
    // L55-L56
    Ok(
      if (message.round_number > self.round_number) &&
        self.round_messages.should_jump_ahead(validator_set, message.round_number)
      {
        // Start the round we're jumping ahead to
        self.start_round::<N>(blockchain, signer, txn, message.round_number).await
      } else if message.round_number == self.round_number {
        self.round_metrics.accumulate(blockchain.genesis(), validator_set, txn, message);
        self.respond::<N>(blockchain, signer, txn).await
      } else {
        // If this isn't for the current round, we have no messages to reply with
        RoundMessages::NONE
      },
    )
  }
}

pub(super) struct TimeoutExpired<'state, 'blockchain, 'signer, B: Blockchain, S: ?Sized> {
  state: &'state mut State<B>,
  blockchain: &'blockchain B,
  signer: &'signer S,
}

type SignatureForBlockchain<B> = <<B as Blockchain>::SignatureScheme as SignatureScheme>::Signature;
impl<
  B: BorshyBlockchain,
  S: ?Sized + Signer<Validator = B::Validator, Signature = SignatureForBlockchain<B>>,
> TimeoutExpired<'_, '_, '_, B, S>
{
  /// This future is NOT cancel-safe.
  pub(super) async fn respond<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    self,
    txn: &mut impl Transaction,
  ) -> <RoundMessages<B> as IntoIterator>::IntoIter {
    let Self { state, blockchain, signer } = self;

    if state.pending_step_timeout.is_none() && state.pending_precommit_timeout.is_none() {
      /*
        If asked to respond, and we have nothing to respond to, rebroadcast our latest messages to
        try and get any validators who were outside of the synchrony bound to catch up to where we
        are now, so we do begin receiving new messages to respond to again.
      */

      /*
        Except if we know _we_ are the ones behind, and therefore we know this won't be helpful and
        will instead just cause us to be marked as stale by our peers.
      */
      if state.observed_block_numbers.observed_block_number() > Some(state.block_number) {
        return RoundMessages::<B>::NONE.into_iter();
      }

      let mut to_rebroadcast = {
        let [prevote_0, prevote_1] = &state.our_latest_prevotes;
        [prevote_0.clone(), state.our_latest_precommit.clone(), prevote_1.clone()]
      };

      // If the precommit is after the prevote, swap them so we don't broadcast them out-of-order
      if to_rebroadcast[1].as_ref().map(|message| message.round_number) >
        to_rebroadcast[2].as_ref().map(|message| message.round_number)
      {
        to_rebroadcast.swap(1, 2);
      }

      to_rebroadcast.into_iter().flatten()
    } else if state
      .pending_precommit_timeout
      .is_some_and(|(start, duration)| start.elapsed() >= duration)
    {
      if let Some(next_round) = state.round_number.0.checked_add(1) {
        state.start_round::<N>(blockchain, signer, txn, RoundNumber(next_round)).await.into_iter()
      } else {
        /*
          This signifies a permanent stall, but `u64::MAX` is effectively unreachable unless the
          fault threshold was broken by a group of validators who forced us to jump up to here.
          Accordingly, it's accepted.
        */
        RoundMessages::<B>::NONE.into_iter()
      }
    } else {
      state.respond::<N>(blockchain, signer, txn).await.into_iter()
    }
  }
}

impl<B: BorshyBlockchain> State<B> {
  /// A future representing the current timeout.
  ///
  /// This function is cancel-safe, but has an output whose future is _not_ cancel-safe. It MUST be
  /// dropped without being polled _or_ polled until ready.
  ///
  /// This corresponds to L57-L67.
  #[must_use]
  pub(super) async fn timeout<
    'state,
    'blockchain,
    'signer,
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
    S: ?Sized
      + Signer<
        Validator = B::Validator,
        Signature = <B::SignatureScheme as SignatureScheme>::Signature,
      >,
  >(
    &'state mut self,
    blockchain: &'blockchain B,
    signer: &'signer S,
  ) -> TimeoutExpired<'state, 'blockchain, 'signer, B, S> {
    let time_remaining = |(start, duration): (Instant, Duration)| {
      let time_elapsed = start.elapsed();
      duration.saturating_sub(time_elapsed)
    };
    (match (self.pending_step_timeout, self.pending_precommit_timeout) {
      (Some(step_timeout), Some(precommit_timeout)) => {
        N::sleep(time_remaining(step_timeout).min(time_remaining(precommit_timeout)))
      }
      (Some(timeout), None) | (None, Some(timeout)) => N::sleep(time_remaining(timeout)),
      /*
        If there's no timeout pending, we are missing the necessary messages to set the timeout. If
        we do not receive _any_ messages within the current latency bound, we will rebroadcast our
        own latest message, as potentially necessary to convince the other validators of the
        current round.

        We know we didn't receive any other messages as this future wasn't cancelled to drop its
        mutable borrow, as necessary to have this state process a message.
      */
      (None, None) => N::sleep(
        N::LATENCY_TIME
          .saturating_mul(u32::try_from(u64::from(self.round_number)).unwrap_or(u32::MAX)),
      ),
    })
    .await;

    TimeoutExpired::<B, S> { state: self, blockchain, signer }
  }

  /// Handle a commit.
  // L51-L54
  pub(super) async fn commit<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &mut B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
    block: B::Block,
    commit: CommitFor<B>,
  ) -> RoundMessages<B> {
    let Some(next_block_number) = self.block_number.0.checked_add(1) else {
      // Stall if the block number is at the maximum, as we can't represent further blocks
      return RoundMessages::NONE;
    };

    {
      let Self {
        block_number,
        block_number_ref,

        // This is preserved across blocks
        observed_block_numbers: _,
        observed_block_number_ref,

        proposal,

        round_number,
        pending_step_timeout,
        pending_precommit_timeout,
        step,

        round_metrics,
        valid,
        locked,

        round_messages,
        our_latest_prevotes,
        our_latest_precommit,
      } = self;

      proposal.set(BlockProposal::new(blockchain.add_block(block, commit).await));

      let genesis = blockchain.genesis();
      let genesis = genesis.as_ref();

      *block_number = BlockNumber(next_block_number);
      db::BlockNumber::set(txn, genesis, block_number);
      let _ = observed_block_number_ref.fetch_max(u64::from(*block_number), Ordering::SeqCst);
      block_number_ref.store(u64::from(*block_number), Ordering::SeqCst);

      // These are saved to the database by the following call to `start_round`
      *round_number = RoundNumber::ONE;
      *pending_step_timeout = None;
      *pending_precommit_timeout = None;
      *step = Step::Propose;
      round_metrics.reset(*block_number, *round_number);

      *valid = None;
      db::Valid::<B>::del(txn, genesis);
      *locked = None;
      db::Locked::<<B::Block as Block>::Hash>::del(txn, genesis);

      round_messages.reset();

      // We expect the commit to be sent around to convince validator's of the current _block_
      *our_latest_prevotes = [const { None }; 2];
      db::OurLatestPrevotes::<B>::del(txn, genesis);
      let _ = our_latest_precommit.take();
      db::OurLatestPrecommit::<B>::del(txn, genesis);
    }

    self.start_round::<N>(blockchain, signer, txn, RoundNumber::ONE).await
  }

  /// Attempt to create a commit.
  ///
  /// This SHOULD be called after every message/timeout.
  // L49-L54
  pub(super) async fn attempt_commit<
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &mut self,
    blockchain: &mut B,
    signer: &(
       impl ?Sized
       + Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >
     ),
    txn: &mut impl Transaction,
  ) -> RoundMessages<B> {
    let Some((block, commit)) = self.round_metrics.commit(blockchain) else {
      return RoundMessages::NONE;
    };

    self.commit::<N>(blockchain, signer, txn, block, commit).await
  }
}
