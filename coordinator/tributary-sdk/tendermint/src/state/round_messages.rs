use core::{num::NonZero, iter::Flatten};
use std::collections::{
  hash_map::{Entry, Values as HashMapValues},
  HashMap,
};

use crate::{
  RoundNumber, ValidatorSet, Signature, AggregateSignature, SignatureScheme, BlockHash, Block,
  Data, SlashReason, Blockchain, MessageFor,
};

/// The messages by a validator within a round.
///
/// This is a very multi-purposed container. It's used as:
/// - Part of the local view, to detect when to jump ahead
/// - Part of the local view, to detect equivocations
/// - The container used as the result for many methods of [`State`]
///
/// This is as, within any single round, a validator will only send at most one message of each
/// type. This means it serves both as a bounded representation for the honest validators within
/// our view, and as a bounded container for many of our own methods (which generally send only one
/// type of message for the _current_ round at any given moment). When multiple methods may or may
/// not return a message of a specific type, the fields within this container allow easily merging
/// different results into a single unified result.
#[must_use]
pub(crate) struct RoundMessages<B: Blockchain> {
  proposal: Option<MessageFor<B>>,
  prevote: Option<MessageFor<B>>,
  precommit: Option<MessageFor<B>>,
}

impl<B: Blockchain> Clone for RoundMessages<B> {
  fn clone(&self) -> Self {
    let Self { proposal, prevote, precommit } = self;
    Self { proposal: proposal.clone(), prevote: prevote.clone(), precommit: precommit.clone() }
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

impl<'messages, B: Blockchain> IntoIterator for &'messages RoundMessages<B> {
  type IntoIter = Flatten<<[&'messages Option<MessageFor<B>>; 3] as IntoIterator>::IntoIter>;
  type Item = &'messages MessageFor<B>;
  fn into_iter(self) -> Self::IntoIter {
    let RoundMessages { proposal, prevote, precommit } = self;
    [proposal, prevote, precommit].into_iter().flatten()
  }
}

impl<B: Blockchain> RoundMessages<B> {
  /// A [`RoundMessages`] container with no messages.
  pub(super) const NONE: Self = RoundMessages { proposal: None, prevote: None, precommit: None };

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

  /// Return the slot for a message.
  #[must_use]
  fn slot(&mut self, message: &MessageFor<B>) -> &mut Option<MessageFor<B>> {
    match message.data {
      Data::Proposal { .. } => &mut self.proposal,
      Data::Prevote { .. } => &mut self.prevote,
      Data::Precommit { .. } => &mut self.precommit,
    }
  }

  /// Insert a message.
  ///
  /// If the message is `Some`, this assumes there is no message already present at the
  /// corresponding slot. This MAY panic or silently replace the existing message if so.
  ///
  /// This does not check the round number of this message is consistent with the other messages in
  /// this container.
  pub(super) fn insert(&mut self, message: Option<MessageFor<B>>) {
    let Some(message) = message else { return };
    let slot = self.slot(&message);
    debug_assert!(slot.is_none());
    *slot = Some(message);
  }

  /// Maybe insert a message.
  ///
  /// If there is no message present at the corresponding slot, this will insert the message and
  /// return `None`. If there is already a message present at the corresponding slot, this will
  /// perform no mutations and return a reference to the existing message.
  ///
  /// This does not check the round number of this message is consistent with the other messages in
  /// this container.
  #[must_use]
  fn maybe_insert(&mut self, message: &MessageFor<B>) -> Option<&MessageFor<B>> {
    let slot = self.slot(message);
    if let Some(existing_message) = slot {
      return Some(existing_message);
    }
    *slot = Some(message.clone());
    None
  }
}

/// [`RoundMessages`] for `N` rounds.
///
/// This allows indexing into the round messages for a specific round, akin to a
/// `HashMap<RoundNumber, MessageFor<B>>` type.
///
/// This requires `N` is constant, as our use-case has (due to its fixed bound on memory usage).
/// This presumes `N` is so small that a [`HashMap`] should not be used and instead, a contiguous
/// list should be used.
#[doc(hidden)]
pub(super) struct NRoundMessages<B: Blockchain, const N: usize>([RoundMessages<B>; N]);

impl<B: Blockchain, const N: usize> NRoundMessages<B, N> {
  /// A [`NRoundMessages`] container with no messages.
  const NONE: Self = Self([RoundMessages::NONE; N]);

  /// The highest round number within this container.
  #[must_use]
  fn highest_round_number(&self) -> Option<RoundNumber> {
    self.0.iter().filter_map(RoundMessages::round_number).max()
  }

  /// Index the round messages for a round number.
  ///
  /// If this container does not have a [`RoundMessages`] corresponding to this [`RoundNumber`], it
  /// will return [`None`].
  #[must_use]
  fn get(&self, round_number: RoundNumber) -> Option<&RoundMessages<B>> {
    self.0.iter().find(|round_messages| round_messages.round_number() == Some(round_number))
  }

  /// Only retain the [`RoundMessages`] for the tracked rounds.
  ///
  /// This returns an iterator over the rounds which were pruned due to no longer being tracked.
  fn retain<'rounds>(
    &'rounds mut self,
    tracked_rounds: &'rounds [Option<RoundNumber>; N],
  ) -> impl use<'rounds, B, N> + Iterator<Item = RoundNumber> {
    self.0.iter_mut().filter_map(|round_messages| {
      let round_number = round_messages.round_number()?;
      if tracked_rounds.contains(&Some(round_number)) {
        None?;
      }
      *round_messages = RoundMessages::NONE;
      Some(round_number)
    })
  }
}

/// A view of validators and their messages for the rounds we're actively tracking.
///
/// This container has memory which is bounded to be approximately linear to the set size.
///
/// We track the messages for what we believe to be the current round, as to help detect
/// equivocations. While tracking _every_ message would increase our ability to detect
/// equivocations, equivocations can fundamentally only be detected under certain synchrony bounds,
/// so we only attempt to do so on a best effort basis. Tracking every message would violate our
/// memory bounds and enable a Denial of Service, hence why we only keep the messages for the
/// current round.
///
/// We also track, on a per validator basis, the latest round observed for them and the round prior
/// to it. This is necessary to detect if we have to jump ahead.
pub(super) struct TrackedRounds<B: Blockchain> {
  /// The literal messages within this container.
  messages: HashMap<B::Validator, NRoundMessages<B, 3>>,

  /// The tallies for how many validators (by weight) have participated in a round.
  ///
  /// This is updated in sync with `messages` to determine if we have to jump ahead or not. The
  /// key, `NonZero<u64>`, represents the `RoundNumber` yet `NonZero<u64>: Hash` and
  /// `RoundNumber: !Hash`.
  round_tallies: HashMap<NonZero<u64>, u16>,
}

#[doc(hidden)]
pub(super) struct NRoundMessagesToRoundMessages<I> {
  round_number: RoundNumber,
  iterator: I,
}
impl<
    'messages,
    B: 'messages + Blockchain,
    const N: usize,
    I: Iterator<Item = &'messages NRoundMessages<B, N>>,
  > Iterator for NRoundMessagesToRoundMessages<I>
{
  type Item = &'messages RoundMessages<B>;
  fn next(&mut self) -> Option<Self::Item> {
    self.iterator.next().and_then(|messages| messages.get(self.round_number))
  }
}

/// The result of updating the tracked rounds' messages via [`TrackedRounds::update`].
pub(super) enum Updated<S: Signature, A: AggregateSignature, H: BlockHash> {
  /// The message was fresh.
  Fresh,
  /// The message is for a round we are not currently tracking.
  NotTracked,
  /// The message has already been handled.
  AlreadyHandled,
  /// This message forms an equivocation.
  Equivocation(SlashReason<S, A, H>),
}

type UpdatedFor<B> = Updated<
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::Signature,
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::AggregateSignature,
  <<B as Blockchain>::Block as Block>::Hash,
>;

type MessagesForRound<'messages, B> = Flatten<
  NRoundMessagesToRoundMessages<
    HashMapValues<'messages, <B as Blockchain>::Validator, NRoundMessages<B, 3>>,
  >,
>;

impl<B: Blockchain> TrackedRounds<B> {
  /// Create a new instance with a specified capacity.
  #[must_use]
  pub(super) fn new(capacity: usize) -> Self {
    Self {
      messages: HashMap::with_capacity(capacity),
      round_tallies: HashMap::with_capacity(3 * capacity),
    }
  }

  /// Reset this container.
  ///
  /// This allows using a single [`TrackedRounds`] container, with its already allocated capacity,
  /// across blocks.
  pub(super) fn reset(&mut self) {
    let Self { messages, round_tallies } = self;
    messages.clear();
    round_tallies.clear();
  }

  /// Update the messages for the tracked rounds.
  ///
  /// If this validator is not already present within this container, an entry will be inserted.
  /// While this increases the memory usage, it's presumed the validator set is constant and
  /// therefore the bound is maintained.
  #[must_use]
  pub(super) fn update(
    &mut self,
    validator_set: &(impl ?Sized + ValidatorSet<Validator = B::Validator>),
    validator: B::Validator,
    current_round_number: RoundNumber,
    message: &MessageFor<B>,
  ) -> UpdatedFor<B> {
    let all_round_messages = self.messages.entry(validator).or_insert(NRoundMessages::NONE);

    // These are the only rounds we track messages for
    let tracked_rounds = {
      let highest_observed_round_number = all_round_messages
        .highest_round_number()
        .unwrap_or(message.round_number)
        .max(message.round_number);
      let prior_observed_round_number = u64::from(highest_observed_round_number)
        .checked_sub(1)
        .and_then(NonZero::new)
        .map(RoundNumber);
      [Some(highest_observed_round_number), prior_observed_round_number, Some(current_round_number)]
    };

    // If we have round messages for distinct rounds, clear them now
    let validator_weight = validator_set.weight(&validator).map(u16::from).unwrap_or(0);
    for pruned_round in all_round_messages.retain(&tracked_rounds) {
      let Entry::Occupied(mut entry) = self.round_tallies.entry(pruned_round.0) else {
        panic!("round present in messages but no corresponding tally?")
      };
      *entry.get_mut() -= validator_weight;
      if (*entry.get()) == 0 {
        entry.remove();
      }
    }

    if !tracked_rounds.contains(&Some(message.round_number)) {
      return Updated::NotTracked;
    }

    /*
      This is guaranteed to find a `RoundMessages` as:
      - We have `N` slots and are tracking `N` rounds
      - We used to `retain` to prune slots not corresponding to a tracked round
      - This round number corresponds to a tracked round
      - Therefore, this round number corresponds to an existing slot _or_ there is an empty slot
    */
    match all_round_messages
      .0
      .iter_mut()
      .find(|round_messages| round_messages.round_number() == Some(message.round_number))
    {
      Some(round_messages) => {
        if let Some(existing_message) = round_messages.maybe_insert(message) {
          if existing_message == message {
            return Updated::AlreadyHandled;
          }

          // Slash this validator for equivocating (there is a different existing message)
          return Updated::Equivocation(
            SlashReason::equivocation(existing_message.clone(), message.clone())
              .expect("`RoundMessages` had a mismatch between message and slot"),
          );
        }
      }
      None => {
        let round_messages = all_round_messages
          .0
          .iter_mut()
          .find(|round_messages| round_messages.round_number().is_none())
          .expect(
            "`round_number` in retained `tracked_rounds` but no corresponding or empty slot?",
          );
        let existing_message = round_messages.maybe_insert(message);
        debug_assert!(existing_message.is_none());

        /*
          Because this validator is _newly_ participating in this round (per our local view), add
          this validator's weight to the round's tally.
        */
        self
          .round_tallies
          .entry(message.round_number.0)
          .and_modify(|weight| *weight += validator_weight)
          .or_insert(validator_weight);
        debug_assert!(self.round_tallies.len() <= (3 * self.messages.len()));
      }
    }

    Updated::Fresh
  }

  /// If the Tendermint state machine should jump ahead to a future round.
  ///
  /// This returns `true` if the machine should jump ahead to the specified round.
  #[must_use]
  pub(super) fn should_jump_ahead(
    &self,
    validator_set: &(impl ?Sized + ValidatorSet<Validator = B::Validator>),
    round_number: RoundNumber,
  ) -> bool {
    self
      .round_tallies
      .get(&round_number.0)
      .is_some_and(|weight| (*weight) > validator_set.fault_threshold())
  }

  /// An iterator over every message for the specified round.
  pub(super) fn messages_for_round(&self, round_number: RoundNumber) -> MessagesForRound<'_, B> {
    (NRoundMessagesToRoundMessages { round_number, iterator: self.messages.values() }).flatten()
  }
}
