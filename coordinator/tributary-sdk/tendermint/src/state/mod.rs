use core::{
  sync::atomic::{Ordering, AtomicU64},
  pin::Pin,
  iter::Flatten,
  time::Duration,
};
use alloc::{boxed::Box, sync::Arc};
use std::{collections::HashMap, time::Instant};

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::Transaction;

use crate::{
  SignatureScheme, ValidatorSet as _, BlockNumber, RoundNumber, Block, CommitFor, Blockchain,
  Signer, ValidRound, Data, MessageFor, MessageError, EquivocatingData, Evidence, SlashReason,
  Network,
};

mod block_proposal;
use block_proposal::*;

mod round_metrics;
use round_metrics::*;

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

/// The messages by a validator within a round.
///
/// This is used both as part of the local view, to detect equivocations with, and also as the
/// result for many of the functions below. This as, within any single round, a validator will only
/// send at most one message of each type. This means the following functions, which only send
/// messages for one round at a time, can be bounded to sending at most three messages at once.
/// This struct represents the container for those three messages, while allowing merging different
/// functions' results into a single unified result.
///
/// The fields of this are weakly typed and left to the user to ensure the accuracy of.
#[must_use]
pub(super) struct RoundMessages<B: Blockchain> {
  /// The proposal message.
  proposal: Option<MessageFor<B>>,
  /// The prevote message.
  prevote: Option<MessageFor<B>>,
  /// The precommit message.
  precommit: Option<MessageFor<B>>,
}

impl<B: Blockchain> RoundMessages<B> {
  const NONE: Self = RoundMessages { proposal: None, prevote: None, precommit: None };

  /// The round number these messages are for.
  ///
  /// This assumes all messages within this container are part of the same round. This will not
  /// return `None` so long as at least one message is set.
  #[must_use]
  fn round_number(&self) -> Option<RoundNumber> {
    self
      .proposal
      .as_ref()
      .or(self.prevote.as_ref())
      .or(self.precommit.as_ref())
      .map(|message| message.round_number)
  }

  /// Insert a message.
  ///
  /// If there is no message present at the corresponding slot, this will insert the message and
  /// return `None`. If there is already a message present at the corresponding slot, this will
  /// perform no mutations and return a reference to the existing message.
  ///
  /// This does not check the round number of this message is consistent with the other messages in
  /// this container.
  #[must_use]
  fn insert(&mut self, message: &MessageFor<B>) -> Option<&MessageFor<B>> {
    let slot = match message.data {
      Data::Proposal { .. } => &mut self.proposal,
      Data::Prevote { .. } => &mut self.prevote,
      Data::Precommit { .. } => &mut self.precommit,
    };
    if let Some(existing_message) = slot {
      return Some(existing_message);
    }
    *slot = Some(message.clone());
    None
  }
}

impl<B: Blockchain> IntoIterator for RoundMessages<B> {
  type IntoIter = Flatten<<[Option<MessageFor<B>>; 3] as IntoIterator>::IntoIter>;
  type Item = MessageFor<B>;
  fn into_iter(self) -> Self::IntoIter {
    let Self { proposal, prevote, precommit } = self;
    [proposal, prevote, precommit].into_iter().flatten()
  }
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
  /// This is updated as the state's block number is.
  block_number_ref: Arc<AtomicU64>,

  /// Our proposal for this block.
  proposal: Pin<Box<BlockProposal<B::Block, B::BlockProposal>>>,

  /// The current round number.
  round_number: RoundNumber,
  /// The pending timeout for the current step.
  ///
  /// This is represented as its start time and duration.
  pending_step_timeout: Option<(Instant, Duration)>,
  /// The pending precommit timeout.
  ///
  /// This is represented as its start time and duration.
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

  /// The messages from the latest rounds each of the validators are performing.
  ///
  /// This is used to jump ahead to a future round and for detecting equivocations. In order to
  /// maintain our (approximately) linear memory use, only the messages for the latest round a
  /// validator has been observed to be performing will be kept.
  round_messages: HashMap<B::Validator, RoundMessages<B>>,

  /// Our latest prevote message.
  ///
  /// We rebroadcast this with the assumption all other validators will be doing the same for their
  /// own messages. This will cause a latent peer to jump to the current round, get past the
  /// prevote phase, and send their own precommit.
  our_latest_prevote: Option<MessageFor<B>>,

  /// Our latest precommit message.
  ///
  /// We rebroadcast this with the assumption all other validators will be doing the same for their
  /// own messages. This will cause a latent peer to jump to the current round, and once we have
  /// `2 f + 1` precommits, start the next round.
  our_latest_precommit: Option<MessageFor<B>>,
}

impl<B: BorshyBlockchain> State<B> {
  /// The current block number.
  #[must_use]
  pub(super) fn block_number(&self) -> BlockNumber {
    self.block_number
  }

  /// Create a new reference to the current block number.
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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

    self.our_latest_prevote = Some(result.clone());
    db::OurLatestPrevote::<B>::set(txn, genesis, &result);
    result
  }

  /// Yield a prevote message, if we should.
  ///
  /// This corresponds to L22-L33 and does not cover the case where the timeout occurs.
  #[must_use]
  async fn prevote_upon_proposal_message(
    &mut self,
    blockchain: &B,
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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

    RoundMessages { proposal: None, prevote: prevote_message, precommit: precommit_message }
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
    txn: &mut impl Transaction,
    round: RoundNumber,
  ) -> RoundMessages<B> {
    debug_assert!(
      ((self.round_number == RoundNumber::ONE) && (self.round_number == round)) ||
        (self.round_number < round)
    );

    {
      let genesis = blockchain.genesis();
      let genesis = genesis.as_ref();

      let Self {
        block_number,
        round_number,
        pending_step_timeout,
        pending_precommit_timeout,
        step,

        round_metrics,

        // These values are consistent across rounds
        block_number_ref: _,
        proposal: _,
        valid: _,
        locked: _,

        // This is independent of the round, used for detecting equivocations and if we're behind
        round_messages: _,

        our_latest_prevote,
        our_latest_precommit,
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

      /*
        Because we are starting a new round, we will eventually send a prevote (either in response
        to a proposal or as the proposal timeout expires). This means we do not need our historic
        messages to ensure we make progress, as we know we will, and when we do, it's that progress
        which is our latest and we actually want to rebroadcast.
      */
      let _ = our_latest_prevote.take();
      db::OurLatestPrevote::<B>::del(txn, genesis);
      let _ = our_latest_precommit.take();
      db::OurLatestPrecommit::<B>::del(txn, genesis);
    }

    // L14-L19
    let proposal_message = self.proposal_message::<N>(blockchain, signer, txn).await;
    let mut round_messages = self.respond::<N>(blockchain, signer, txn).await;
    // [`State::respond`] does not emit proposal messages
    debug_assert!(round_messages.proposal.is_none());
    round_messages.proposal = proposal_message;
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
      let block_number_ref = Arc::new(AtomicU64::new(u64::from(block_number.0)));

      let state = State {
        block_number,
        block_number_ref,
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
        round_messages: HashMap::with_capacity(validator_set.validators().into_iter().count()),

        our_latest_prevote: db::OurLatestPrevote::<B>::get(getter, genesis),
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
    txn: &mut impl Transaction,
    message: MessageFor<B>,
  ) -> Result<RoundMessages<B>, MessageError> {
    // If this is historic or for a future block, ignore this message
    if (message.block_number < self.block_number) || (message.round_number < self.round_number) {
      Err(MessageError::Stale)?;
    }
    if message.block_number > self.block_number {
      Err(MessageError::Future)?;
    }
    debug_assert_eq!(message.block_number, self.block_number);

    // Verify this message's signature(s)
    message.verify_signatures(blockchain)?;

    // Update `round_messages`
    {
      let round_messages =
        self.round_messages.entry(message.validator).or_insert(RoundMessages::NONE);
      // If these round messages are historic to this message's round, move on
      if round_messages
        .round_number()
        .is_some_and(|round_number| round_number < message.round_number)
      {
        *round_messages = RoundMessages::NONE;
      }
      debug_assert!(round_messages
        .round_number()
        .is_none_or(|round_number| round_number >= message.round_number));

      // Write this message into this validator's messages for this round
      if round_messages
        .round_number()
        .is_none_or(|round_number| round_number == message.round_number)
      {
        if let Some(existing_message) = round_messages.insert(&message) {
          // If we've already handled this message, ignore it
          if existing_message == &message {
            Err(MessageError::AlreadyHandled)?;
          }

          // Slash this validator for equivocating (there is a different existing message)
          blockchain.slash(
            message.validator,
            SlashReason {
              block_number: message.block_number,
              round_number: message.round_number,
              evidence: Evidence::Equivocation {
                data: match (existing_message.data.clone(), message.data.clone()) {
                  (
                    Data::Proposal { valid_round: first_valid_round, proposal: first_proposal },
                    Data::Proposal { valid_round: second_valid_round, proposal: second_proposal },
                  ) => EquivocatingData::Proposal {
                    first_valid_round,
                    first_proposal: first_proposal.hash(),
                    second_valid_round,
                    second_proposal: second_proposal.hash(),
                  },
                  (Data::Prevote { block: first_block }, Data::Prevote { block: second_block }) => {
                    EquivocatingData::Prevote { first_block, second_block }
                  }
                  (
                    Data::Precommit {
                      block_and_precommit_signature: first_block_and_precommit_signature,
                    },
                    Data::Precommit {
                      block_and_precommit_signature: second_block_and_precommit_signature,
                    },
                  ) => EquivocatingData::Precommit {
                    first_block_and_precommit_signature,
                    second_block_and_precommit_signature,
                  },
                  _ => unreachable!("`RoundMessages` had a mismatch between message and slot"),
                },
                first_signature: existing_message.signature.clone(),
                second_signature: message.signature.clone(),
              },
            },
          );

          // TODO: Should we have an error for this?
          return Ok(RoundMessages::NONE);
        }
      }
    }

    // If this message is for a future round, with sufficient participation, jump to this round
    // TODO: Use a tally for it instead of doing a full iteration upon every message
    // L55-L56
    let validator_set = blockchain.validator_set();
    let mut round_messages = if (message.round_number > self.round_number) && {
      let mut weight = 0u16;
      for (validator, round_messages) in &self.round_messages {
        if round_messages
          .round_number()
          .is_some_and(|round_number| round_number == message.round_number)
        {
          weight += validator_set.weight(validator).map(u16::from).unwrap_or(0);
        }
      }
      weight > validator_set.fault_threshold()
    } {
      let round_messages =
        self.start_round::<N>(blockchain, signer, txn, message.round_number).await;
      // Accumulate every message from this round
      for (_validator, round_messages) in
        self.round_messages.extract_if(|_validator, round_messages| {
          round_messages.round_number() == Some(message.round_number)
        })
      {
        for message in round_messages {
          if structurally_validate_if_proposal::<B>(blockchain, &message) {
            self.round_metrics.accumulate(blockchain.genesis(), validator_set, txn, message);
          }
        }
      }
      round_messages
    } else {
      RoundMessages::NONE
    };

    // This MAY accumulate this message twice if we just jumped ahead, but this is fine
    if (message.round_number == self.round_number) &&
      structurally_validate_if_proposal::<B>(blockchain, &message)
    {
      self.round_metrics.accumulate(blockchain.genesis(), validator_set, txn, message);
    }

    // Merge the two `RoundMessages`
    let RoundMessages { proposal, prevote, precommit } =
      self.respond::<N>(blockchain, signer, txn).await;
    // [`State::respond`] does not emit proposal messages
    debug_assert!(proposal.is_none());
    // These hold as else we'd be equivocating, a violation of our state machine
    debug_assert!(round_messages.prevote.is_none() || prevote.is_none());
    debug_assert!(round_messages.precommit.is_none() || precommit.is_none());
    round_messages.prevote = round_messages.prevote.or(prevote);
    round_messages.precommit = round_messages.precommit.or(precommit);
    Ok(round_messages)
  }
}

pub(super) struct TimeoutExpired<'state, 'blockchain, 'signer, B: Blockchain, S> {
  state: &'state mut State<B>,
  blockchain: &'blockchain B,
  signer: &'signer S,
}

impl<
    B: BorshyBlockchain,
    S: Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
  ) -> RoundMessages<B> {
    let Self { state, blockchain, signer } = self;

    if state.pending_step_timeout.is_none() && state.pending_precommit_timeout.is_none() {
      /*
        If asked to respond, and we have nothing to respond to, rebroadcast our latest messages to
        try and get any validators who were outside of the synchrony bound to catch up to where we
        are now, so we do begin receiving new messages to respond to again.
      */
      let mut round_messages = RoundMessages::NONE;
      if let Some(our_latest_prevote) = state.our_latest_prevote.as_ref() {
        let existing = round_messages.insert(our_latest_prevote);
        debug_assert!(existing.is_none());
      }
      if let Some(our_latest_precommit) = state.our_latest_precommit.as_ref() {
        let existing = round_messages.insert(our_latest_precommit);
        debug_assert!(existing.is_none());
      }
      round_messages
    } else if state
      .pending_precommit_timeout
      .is_some_and(|(start, duration)| start.elapsed() >= duration)
    {
      if let Some(next_round) = state.round_number.0.checked_add(1) {
        state.start_round::<N>(blockchain, signer, txn, RoundNumber(next_round)).await
      } else {
        /*
          This signifies a permanent stall, but `u64::MAX` is effectively unreachable unless the
          fault threshold was broken by a group of validators who forced us to jump up to here.
          Accordingly, it's accepted.
        */
        RoundMessages::NONE
      }
    } else {
      state.respond::<N>(blockchain, signer, txn).await
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
    S: Signer<
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
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
        proposal,

        round_number,
        pending_step_timeout,
        pending_precommit_timeout,
        step,

        round_metrics,
        valid,
        locked,

        round_messages,
        our_latest_prevote,
        our_latest_precommit,
      } = self;

      proposal.set(BlockProposal::new(blockchain.add_block(block, commit).await));

      let genesis = blockchain.genesis();
      let genesis = genesis.as_ref();

      *block_number = BlockNumber(next_block_number);
      db::BlockNumber::set(txn, genesis, block_number);
      block_number_ref.store(u64::from(block_number.0), Ordering::Relaxed);

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

      round_messages.clear();

      // We expect the commit to be sent around to convince validator's of the current _block_
      let _ = our_latest_prevote.take();
      db::OurLatestPrevote::<B>::del(txn, genesis);
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
    signer: &impl Signer<
      Validator = B::Validator,
      Signature = <B::SignatureScheme as SignatureScheme>::Signature,
    >,
    txn: &mut impl Transaction,
  ) -> RoundMessages<B> {
    let Some((block, commit)) = self.round_metrics.commit(blockchain) else {
      return RoundMessages::NONE;
    };

    self.commit::<N>(blockchain, signer, txn, block, commit).await
  }
}
