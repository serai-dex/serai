use alloc::vec::Vec;
use std::collections::HashMap;

use serai_db::{Get, DbTxn};

use crate::{
  Borshy, SignatureScheme, ValidatorSet, BlockNumber, RoundNumber, Block, Commit, Blockchain,
  ValidRound, Data, Evidence, SlashReason, Message, MessageFor,
};

/*
  The database for this module.

  The first key is _always_ the genesis hash, in order to domain-separate multiple instances of the
  Tendermint process within the same database. The values are always saved with the block, round
  numbers as a form of time-to-live. If a value is loaded with disparate block, round numbers, it
  is considered stale and ignored.
*/
serai_db::create_db!(TendermintRoundMetrics {
  Proposal: <Block: Borshy>(genesis: &[u8]) -> (
    (BlockNumber, RoundNumber),
    (Option<RoundNumber>, Block)
  ),

  Prevote: <
    Validator: Borshy,
    Hash: Borshy,
    Signature: Borshy
  >(genesis: &[u8], validator: &Validator) -> (
    (BlockNumber, RoundNumber),
    (Option<Hash>, Signature)
  ),

  Precommit: <
    Validator: Borshy,
    Hash: Borshy,
    Signature: Borshy
  >(genesis: &[u8], validator: &Validator) -> (
    (BlockNumber, RoundNumber),
    Option<(
      Hash,
      Signature,
    )>
  ),
});

/// The metrics for a round.
///
/// This accumulates messages from the current round into the necessary tallies for participating
/// in Tendermint.
pub(super) struct RoundMetrics<B: Blockchain> {
  /// The current block number.
  ///
  /// This is used to timestamp values in the database, allowing detecting if they're stale, and
  /// for forming the commit.
  block_number: BlockNumber,
  /// The current round number.
  ///
  /// This is used to timestamp values in the database, allowing detecting if they're stale, and
  /// for forming the commit.
  round_number: RoundNumber,

  /// The observed proposal for this round.
  observed_proposal: Option<(B::Validator, Option<RoundNumber>, B::Block)>,

  /// The weight of the prevotes which have been observed this round.
  observed_prevotes_weight: u16,
  /// The weight of the prevotes which have been observed for the proposal this round.
  observed_prevotes_for_proposal: u16,
  /// The weight of the prevotes which have been observed for `None` this round.
  observed_prevotes_for_none: u16,
  /// The prevotes which have been observed for this round.
  #[expect(clippy::type_complexity)]
  observed_prevotes: HashMap<
    B::Validator,
    (Option<<B::Block as Block>::Hash>, <B::SignatureScheme as SignatureScheme>::Signature),
  >,

  /// The weight of the precommits which have been observed this round.
  observed_precommits_weight: u16,
  /// The weight of the precommits which have been observed for the proposal this round.
  observed_precommits_for_proposal: u16,
  /// The precommits which have been observed for this round.
  #[expect(clippy::type_complexity)]
  observed_precommits: HashMap<
    B::Validator,
    Option<(<B::Block as Block>::Hash, <B::SignatureScheme as SignatureScheme>::Signature)>,
  >,
}

pub(super) struct ObservedProposal<'block, B: Blockchain> {
  pub(super) proposer: B::Validator,
  pub(super) valid_round: Option<RoundNumber>,
  pub(super) proposal: &'block B::Block,
}

impl<B: Blockchain> RoundMetrics<B> {
  /// The observed proposal for this round.
  #[must_use]
  pub(super) fn observed_proposal(&self) -> Option<ObservedProposal<'_, B>> {
    self.observed_proposal.as_ref().map(|(proposer, valid_round, proposal)| ObservedProposal {
      proposer: *proposer,
      valid_round: *valid_round,
      proposal,
    })
  }
  /// The prevotes which have been observed for the proposal this round.
  ///
  /// This returns `Some(ValidRound { .. })` if the amount of observed prevotes satisfy the
  /// threshold and `None` otherwise.
  #[must_use]
  pub(super) fn observed_prevotes_for_proposal(
    &self,
    blockchain: &B,
  ) -> Option<ValidRound<<B::SignatureScheme as SignatureScheme>::AggregateSignature>> {
    if self.observed_prevotes_for_proposal < blockchain.validator_set().threshold() {
      None?;
    }

    let (_proposer, _valid_round, proposal) = self
      .observed_proposal
      .as_ref()
      .expect("observed prevotes for a proposal but didn't have the proposal?");
    let proposal = proposal.hash();

    Some(ValidRound {
      round_number: self.round_number,
      aggregate_signature: blockchain.signature_scheme().aggregate(
        MessageFor::<B>::signature_message(
          blockchain.genesis(),
          self.block_number,
          self.round_number,
          &Data::Prevote { block: Some(proposal) },
        ),
        self.observed_prevotes.iter().filter_map(|(validator, (block, signature))| {
          ((*block) == Some(proposal)).then_some((validator, signature))
        }),
      ),
    })
  }
  /// The weight of the prevotes which have been observed for `None` this round.
  #[must_use]
  pub(super) fn observed_prevotes_for_none(&self) -> u16 {
    self.observed_prevotes_for_none
  }
  /// The weight of the prevotes which have been observed this round.
  #[must_use]
  pub(super) fn observed_prevotes(&self) -> u16 {
    self.observed_prevotes_weight
  }
  /// The weight of the precommits which have been observed this round.
  #[must_use]
  pub(super) fn observed_precommits(&self) -> u16 {
    self.observed_precommits_weight
  }
  /// The commit, if one is ready.
  ///
  /// This assumes all accumulated precommits had valid signatures.
  #[must_use]
  pub(super) fn commit(&self, blockchain: &B) -> Option<(B::Block, Commit<B::SignatureScheme>)> {
    let ObservedProposal { proposer: _, valid_round: _, proposal } = self.observed_proposal()?;

    let validator_set = blockchain.validator_set();
    let weight = self.observed_precommits_for_proposal;
    let threshold = validator_set.threshold();
    if weight < threshold {
      None?;
    }

    let proposal_hash = proposal.hash();
    let mut weight = weight;
    let weight = &mut weight;
    let mut validators = alloc::vec![];
    let aggregate_signature = blockchain.signature_scheme().aggregate(
      Commit::<B::SignatureScheme>::signature_message(
        blockchain.genesis().as_ref(),
        self.block_number,
        self.round_number,
        proposal_hash.as_ref(),
      ),
      self
        .observed_precommits
        .iter()
        .filter_map(|(validator, block_and_precommit_signature)| {
          // Only include signatures actually to this block
          block_and_precommit_signature
            .as_ref()
            .and_then(|(block, signature)| {
              ((*block) == proposal_hash).then_some((validator, signature))
            })
            .filter(|(validator, _signature)| {
              /*
                Additionally filter out any unnecessary validators.

                This reduces the size of the resulting commit, making it marginally cheaper to work
                with, at the cost of re-fetching every weight here when we form the commit. As this
                branch is only run when we have enough weight for a commit, which should only
                happen once for block, this cost is fine and the result pleasant.

                Note that this still is expected to trigger as soon as possible, and even smaller
                commits may be possible by waiting for further participants (which would definitely
                not be worth considering). Additionally, this trimming works with a single-pass
                algorithm, but sorting the validators by weight would ensure this result is
                minimal for the current validators we have (that we would remove lower-weight
                validators before removing any higher-weight validators).
              */
              let validator_weight = validator_set.weight(validator).map(u16::from).unwrap_or(0);
              if ((*weight) - threshold) >= validator_weight {
                *weight -= validator_weight;
                return false;
              }
              true
            })
        })
        .inspect(|(validator, _signature)| {
          validators.push(**validator);
        }),
    );

    Some((
      proposal.clone(),
      Commit {
        block_number: self.block_number,
        round_number: self.round_number,
        aggregate_signature,
      },
    ))
  }

  /// Reset the metrics for a round.
  ///
  /// This allows using a single [`RoundMetrics`] container, with its already allocated capacity,
  /// across rounds.
  pub(super) fn reset(&mut self, block_number: BlockNumber, round_number: RoundNumber) {
    let Self {
      block_number: block_number_mut,
      round_number: round_number_mut,
      observed_proposal,
      observed_prevotes_weight,
      observed_prevotes_for_proposal,
      observed_prevotes_for_none,
      observed_prevotes,
      observed_precommits_weight,
      observed_precommits_for_proposal,
      observed_precommits,
    } = self;
    *block_number_mut = block_number;
    *round_number_mut = round_number;
    *observed_proposal = None;
    *observed_prevotes_weight = 0;
    *observed_prevotes_for_proposal = 0;
    *observed_prevotes_for_none = 0;
    observed_prevotes.clear();
    *observed_precommits_weight = 0;
    *observed_precommits_for_proposal = 0;
    observed_precommits.clear();
  }

  /// Directly set the observed proposal.
  ///
  /// This, with the visibility `pub(super)`, is intended for when the local process _is_ the
  /// proposer. It WILL panic if the proposal was already set.
  pub(super) fn accumulate_proposal(
    &mut self,
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = B::Validator>,
    txn: &mut impl DbTxn,
    proposer: B::Validator,
    valid_round: Option<RoundNumber>,
    proposal: B::Block,
  ) {
    assert!(self.observed_proposal.is_none());
    let proposal_hash = proposal.hash();
    Proposal::set(
      txn,
      genesis.as_ref(),
      &((self.block_number, self.round_number), (valid_round, proposal.clone())),
    );
    self.observed_proposal = Some((proposer, valid_round, proposal));

    /*
      If we've already accumulated prevotes for this proposal, tally them now.

      Note we wouldn't have tallied them already as these prevotes, now for the observed proposal,
      weren't for the observed proposal prior to it being set just now (as it was `None`).
    */
    for (validator, (block, _signature)) in &self.observed_prevotes {
      if (*block) == Some(proposal_hash) {
        self.observed_prevotes_for_proposal +=
          validator_set.weight(validator).map(u16::from).unwrap_or(0);
      }
    }

    // Do the same for precommits
    for (validator, block_and_precommit_signature) in &self.observed_precommits {
      if block_and_precommit_signature.as_ref().map(|(block, _precommit_signature)| *block) ==
        Some(proposal_hash)
      {
        self.observed_precommits_for_proposal +=
          validator_set.weight(validator).map(u16::from).unwrap_or(0);
      }
    }
  }

  /// Directly accumulate a prevote.
  ///
  /// This, with the visibility `pub(super)`, is intended for when the local process _is_
  /// prevoting. This returns `true` if no prevote for this validator was prior accumulated.
  /// If a prevote for this validator was prior accumulated, this returns `false`
  /// _and performs no mutations to the metrics_.
  #[must_use]
  pub(super) fn accumulate_prevote(
    &mut self,
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = B::Validator>,
    txn: &mut impl DbTxn,
    validator: B::Validator,
    block: Option<<B::Block as Block>::Hash>,
    signature: <B::SignatureScheme as SignatureScheme>::Signature,
  ) -> bool {
    match self.observed_prevotes.entry(validator) {
      // If this validator already had a prevote accumulated, return immediately
      std::collections::hash_map::Entry::Occupied(_) => return false,
      // Insert this as this validator's prevote
      std::collections::hash_map::Entry::Vacant(entry) => {
        let _ = entry.insert((block, signature.clone()));
        Prevote::set(
          txn,
          genesis.as_ref(),
          &validator,
          &((self.block_number, self.round_number), (block, signature)),
        );
      }
    }

    let weight = validator_set.weight(&validator).map(u16::from).unwrap_or(0);
    self.observed_prevotes_weight += weight;

    match block {
      Some(block)
        if self.observed_proposal().is_some_and(
          |ObservedProposal { proposer: _, valid_round: _, proposal }| block == proposal.hash(),
        ) =>
      {
        self.observed_prevotes_for_proposal += weight;
      }
      None => {
        self.observed_prevotes_for_none += weight;
      }
      // This was a prevote but not for the proposal we've observed
      Some(_) => {}
    }

    true
  }

  /// Directly accumulate a precommit.
  ///
  /// This, with the visibility `pub(super)`, is intended for when the local process _is_
  /// precommitting. This returns `true` if no precommit for this validator was prior accumulated.
  /// If a precommit for this validator was prior accumulated, this returns `false`
  /// _and performs no mutations_.
  #[must_use]
  #[expect(clippy::type_complexity)]
  pub(super) fn accumulate_precommit(
    &mut self,
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = B::Validator>,
    txn: &mut impl DbTxn,
    validator: B::Validator,
    block_and_precommit_signature: Option<(
      <B::Block as Block>::Hash,
      <B::SignatureScheme as SignatureScheme>::Signature,
    )>,
  ) -> bool {
    match self.observed_precommits.entry(validator) {
      // If this validator already had a precommit accumulated, return immediately
      std::collections::hash_map::Entry::Occupied(_) => return false,
      // Insert this as this validator's precommit
      std::collections::hash_map::Entry::Vacant(entry) => {
        let _ = entry.insert(block_and_precommit_signature.clone());
        Precommit::set(
          txn,
          genesis.as_ref(),
          &validator,
          &((self.block_number, self.round_number), block_and_precommit_signature.clone()),
        );
      }
    }

    let weight = validator_set.weight(&validator).map(u16::from).unwrap_or(0);
    self.observed_precommits_weight += weight;

    match block_and_precommit_signature {
      Some((block, _precommit_signature))
        if self.observed_proposal().is_some_and(
          |ObservedProposal { proposer: _, valid_round: _, proposal }| block == proposal.hash(),
        ) =>
      {
        self.observed_precommits_for_proposal += weight;
      }
      // This was a precommit for `None`/not for the proposal we've observed
      None | Some(_) => {}
    }

    true
  }

  /// Accumulate a message into the round's metrics.
  ///
  /// The message MUST be for the current block, round numbers.
  ///
  /// Messages with `Data::Proposal` MUST have been validated to have the correct proposer AND a
  /// valid `locked_round` value.
  ///
  /// This explicitly does not handle equivocations, which would require a full log of this round's
  /// messages to do so with evidence, and instead solely updates the metrics when there would not
  /// be a conflict. If there would be a conflict, the existing message is left as-is to ensure
  /// consistent metrics. This means accumulating a message multiple times is safe.
  pub(super) fn accumulate(
    &mut self,
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = B::Validator>,
    txn: &mut impl DbTxn,
    message: MessageFor<B>,
  ) {
    let Message { validator, block_number, round_number, data, signature } = message;
    debug_assert_eq!(self.block_number, block_number);
    debug_assert_eq!(self.round_number, round_number);

    match data {
      Data::Proposal { valid_round, proposal } => {
        if self.observed_proposal.is_none() {
          self.accumulate_proposal(
            genesis,
            validator_set,
            txn,
            validator,
            valid_round.map(|ValidRound { round_number, aggregate_signature: _ }| round_number),
            proposal,
          );
        }
      }
      Data::Prevote { block } => {
        let _ = self.accumulate_prevote(genesis, validator_set, txn, validator, block, signature);
      }
      Data::Precommit { block_and_precommit_signature } => {
        let _ = self.accumulate_precommit(
          genesis,
          validator_set,
          txn,
          validator,
          block_and_precommit_signature,
        );
      }
    }
  }

  pub(super) fn new(
    genesis: impl AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = B::Validator>,
    getter: &impl Get,
    block_number: BlockNumber,
    round_number: RoundNumber,
  ) -> Self {
    /*
      Our accumulation methods will write what we accumulate, so we pass them a `DummyTxn` to
      affect a NOP (as we're accumulating what we just read, so writing it back again would be
      pointless).
    */
    struct DummyTxn;
    impl Get for DummyTxn {
      fn get(&self, _key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
        unimplemented!()
      }
    }
    impl DbTxn for DummyTxn {
      fn put(&mut self, _key: impl AsRef<[u8]>, _value: impl AsRef<[u8]>) {}
      fn del(&mut self, _key: impl AsRef<[u8]>) {}
      fn commit(self) {}
    }

    let mut result = RoundMetrics {
      block_number,
      round_number,
      observed_proposal: None,
      observed_prevotes_weight: 0,
      observed_prevotes_for_proposal: 0,
      observed_prevotes_for_none: 0,
      observed_prevotes: HashMap::new(),
      observed_precommits_weight: 0,
      observed_precommits_for_proposal: 0,
      observed_precommits: HashMap::new(),
    };

    if let Some((ttl, (valid_round, proposal))) =
      Proposal::<B::Block>::get(getter, genesis.as_ref())
    {
      if ttl == (block_number, round_number) {
        result.accumulate_proposal(
          genesis.as_ref(),
          validator_set,
          &mut DummyTxn,
          validator_set.proposer(block_number, round_number),
          valid_round,
          proposal,
        );
      }
    }

    for validator in validator_set.validators() {
      if let Some((ttl, (block, signature))) = Prevote::<
        B::Validator,
        <B::Block as Block>::Hash,
        <B::SignatureScheme as SignatureScheme>::Signature,
      >::get(getter, genesis.as_ref(), validator)
      {
        if ttl == (block_number, round_number) {
          assert!(result.accumulate_prevote(
            genesis.as_ref(),
            validator_set,
            &mut DummyTxn,
            *validator,
            block,
            signature
          ));
        }
      }
      if let Some((ttl, block_and_precommit_signature)) =
        Precommit::<
          B::Validator,
          <B::Block as Block>::Hash,
          <B::SignatureScheme as SignatureScheme>::Signature,
        >::get(getter, genesis.as_ref(), validator)
      {
        if ttl == (block_number, round_number) {
          assert!(result.accumulate_precommit(
            genesis.as_ref(),
            validator_set,
            &mut DummyTxn,
            *validator,
            block_and_precommit_signature,
          ));
        }
      }
    }

    result
  }
}

/// Validate a message with `Data::Proposal`'s structure.
///
/// This returns `true` so long as:
/// - If the message contains a `Data::Proposal`, it is by the expected proposer
/// - If the message contains a `Data::Proposal`, it has a valid round less than the current round
///
/// This returns `false` otherwise and emits a slash for the validator who sent this message.
///
/// This satisfies the requirements specifically necessary for proposals before invoking
/// [`RoundMetrics::accumulate`].
#[must_use]
pub(super) fn structurally_validate_if_proposal<B: Blockchain>(
  blockchain: &B,
  message: &MessageFor<B>,
) -> bool {
  match &message.data {
    Data::Proposal { valid_round, proposal } => {
      let structurally_valid = (valid_round
        .as_ref()
        .map(|ValidRound { round_number, aggregate_signature: _ }| *round_number) <
        Some(message.round_number)) &&
        (message.validator ==
          blockchain.validator_set().proposer(message.block_number, message.round_number));
      if !structurally_valid {
        blockchain.slash(
          message.validator,
          SlashReason {
            block_number: message.block_number,
            round_number: message.round_number,
            evidence: Evidence::InvalidProposal {
              valid_round: valid_round.clone(),
              proposal: proposal.hash(),
              signature: message.signature.clone(),
            },
          },
        );
      }
      structurally_valid
    }
    Data::Prevote { .. } | Data::Precommit { .. } => true,
  }
}
