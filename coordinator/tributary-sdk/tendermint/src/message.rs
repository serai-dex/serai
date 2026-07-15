use core::fmt;

use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet, Signature, AggregateSignature,
  SignatureScheme, Signer, Block, Commit, Blockchain,
};

/// A valid round.
///
/// This is not just the specification of the valid round but also the evidence needed to convince
/// other validators this round was valid. This allows each validator to only store their view of
/// the valid round, with a bounded amount of memory, yet to recognize the proposer's argument for
/// the valid round without issue.
///
/// This does increase the amount communicated by the proposer, but maintains the same `O(n^2)`
/// communication complexity for each round as here we have the single proposer sending a message
/// of size `n` to `n` other participants, while the following rounds have `n` participants sending
/// messages of size `1` to `n` other participants. This assumes the aggregate signature is of size
/// linear to the individual signatures, such as by a naïve concatenation into a list, though with
/// threshold signatures or similar, this could be of equal complexity to the traditional concept
/// of a proposal message.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) struct ValidRound<A: AggregateSignature> {
  pub(crate) round_number: RoundNumber,
  pub(crate) aggregate_signature: A,
}

impl<A: AggregateSignature> PartialEq for ValidRound<A> {
  /// This equality is semantic and does not consider if any present signatures are equal. This
  /// ensures even for signature schemes with malleable signatures, multiple signatures over the
  /// same messages are not semantically treated as distinct signatures. However, this also means a
  /// value with an invalid signature will be considered equal to a message with a valid signature.
  fn eq(&self, other: &Self) -> bool {
    let Self { round_number, aggregate_signature: _ } = self;
    (*round_number) == other.round_number
  }
}
impl<A: AggregateSignature> Eq for ValidRound<A> {}

impl<A: AggregateSignature> fmt::Debug for ValidRound<A> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Self { round_number, aggregate_signature: _ } = self;
    formatter.debug_struct("ValidRound").field("round_number", round_number).finish()
  }
}

/// The data within a message.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum Data<S: Signature, A: AggregateSignature, B: Block> {
  Proposal { valid_round: Option<ValidRound<A>>, proposal: B },
  Prevote { block: Option<B::Hash> },
  Precommit { block_and_precommit_signature: Option<(B::Hash, S)> },
}

impl<S: Signature, A: AggregateSignature, B: Block> PartialEq for Data<S, A, B> {
  /// This equality is semantic and does not consider if any present signatures are equal. This
  /// ensures even for signature schemes with malleable signatures, multiple signatures over the
  /// same messages are not semantically treated as distinct signatures. However, this also means a
  /// value with an invalid signature will be considered equal to a message with a valid signature.
  fn eq(&self, other: &Self) -> bool {
    match (self, other) {
      (
        Data::Proposal { valid_round, proposal },
        Data::Proposal { valid_round: other_valid_round, proposal: other_proposal },
      ) => (valid_round == other_valid_round) && (proposal.hash() == other_proposal.hash()),
      (Data::Prevote { block }, Data::Prevote { block: other_block }) => block == other_block,
      (
        Data::Precommit { block_and_precommit_signature: None },
        Data::Precommit { block_and_precommit_signature: None },
      ) => true,
      (
        Data::Precommit { block_and_precommit_signature: Some((block, _)) },
        Data::Precommit { block_and_precommit_signature: Some((other_block, _)) },
      ) => block == other_block,
      _ => false,
    }
  }
}
impl<S: Signature, A: AggregateSignature, B: Block> Eq for Data<S, A, B> {}

impl<S: Signature, A: AggregateSignature, B: Block> Data<S, A, B> {
  /// The serialization used for signing.
  ///
  /// This exists primarily as we do not want to sign the block in a proposal but solely its hash.
  /// This allows proving an equivocation occurred without rebroadcasting the blocks as a whole but
  /// solely their hashes.
  ///
  /// The result can be mapped to an `Iterator<Item = &[u8]>` as needed to be chained with a larger
  /// context of such schema. While this is rather annoying to do here, the borrow-checker somewhat
  /// requires this pattern.
  #[must_use]
  fn signature_message(
    &self,
  ) -> impl IntoIterator<IntoIter: Send, Item = Option<impl AsRef<[u8]>>> {
    let (kind, round_number, aggregate_signature, block, precommit_signature) = match self {
      Data::Proposal { valid_round, proposal } => {
        let (round_number, aggregate_signature) = valid_round
          .as_ref()
          .map(|ValidRound { round_number, aggregate_signature }| {
            (u64::from(*round_number).to_le_bytes(), aggregate_signature.clone())
          })
          .unzip();
        (
          0u8,
          // As `RoundNumber` is non-zero, we represent `None` with the encoding `0` would have
          Some(round_number.unwrap_or([0; _])),
          // This is `None` if the round number was encoded as `[0; 8]` and `Some` otherwise
          aggregate_signature,
          // We only sign the hash so the signed message is of a consistent length
          Some(proposal.hash()),
          None,
        )
      }
      /*
        This omits the encoding of the block hash to signify `None`, which is fine as this is
        without collisions and this doesn't have to be able to be deserialized from.
      */
      Data::Prevote { block } => (1u8, None, None, *block, None),
      Data::Precommit { block_and_precommit_signature } => {
        let (block, precommit_signature) = block_and_precommit_signature.clone().unzip();
        (
          2u8,
          None,
          None,
          /*
            The block hash has a fixed length and the precommit signature should be self-delimited
            (by virtue of being a `borsh` representation). These are both `Some` or both `None`.
          */
          block,
          precommit_signature,
        )
      }
    };

    enum Segment<S: Signature, A: AggregateSignature, B: Block> {
      Kind([u8; 1]),
      RoundNumber([u8; 8]),
      AggregateSignature(Option<A>),
      Block(B::Hash),
      PrecommitSignature(S),
    }
    impl<S: Signature, A: AggregateSignature, B: Block> AsRef<[u8]> for Segment<S, A, B> {
      fn as_ref(&self) -> &[u8] {
        match self {
          Self::Kind(kind) => kind.as_slice(),
          Self::RoundNumber(round_number) => round_number.as_slice(),
          Self::AggregateSignature(aggregate_signature) => {
            aggregate_signature.as_ref().map(AsRef::as_ref).unwrap_or(&[])
          }
          Self::Block(block) => block.as_ref(),
          Self::PrecommitSignature(precommit_signature) => precommit_signature.as_ref(),
        }
      }
    }

    [
      Some(Segment::<S, A, B>::Kind([kind])),
      round_number.map(Segment::RoundNumber),
      Some(Segment::AggregateSignature(aggregate_signature)),
      block.map(Segment::Block),
      precommit_signature.map(Segment::PrecommitSignature),
    ]
  }
}

/// A message from the Tendermint consensus process.
///
/// This encapsulates a [`Data`] with the validator, block and round numbers, and signature.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Message<V: Validator, S: Signature, A: AggregateSignature, B: Block> {
  pub(crate) validator: V,
  pub(crate) block_number: BlockNumber,
  pub(crate) round_number: RoundNumber,
  pub(crate) data: Data<S, A, B>,
  pub(crate) signature: S,
}

impl<V: Validator, S: Signature, A: AggregateSignature, B: Block> PartialEq
  for Message<V, S, A, B>
{
  /// This equality is semantic and does not consider if any present signatures are equal. This
  /// ensures even for signature schemes with malleable signatures, multiple signatures over the
  /// same messages are not semantically treated as distinct signatures. However, this also means a
  /// value with an invalid signature will be considered equal to a message with a valid signature.
  fn eq(&self, other: &Self) -> bool {
    let Self { validator, block_number, round_number, data, signature: _ } = self;
    ((*validator) == other.validator) &&
      ((*block_number) == other.block_number) &&
      ((*round_number) == other.round_number) &&
      (data == &other.data)
  }
}
impl<V: Validator, S: Signature, A: AggregateSignature, B: Block> Eq for Message<V, S, A, B> {}

/// The message type for a blockchain.
pub type MessageFor<B> = Message<
  <B as Blockchain>::Validator,
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::Signature,
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::AggregateSignature,
  <B as Blockchain>::Block,
>;

pub(crate) enum MessageError {
  /// The message was stale within the current context.
  Stale,
  /// The message was for a future context.
  ///
  /// This MAY suggest the local view is historic.
  Future,
  /// The message was not from a validator.
  NotValidator,
  /// The message had an invalid signature.
  InvalidSignature,
  /// This message has already been handled.
  AlreadyHandled,
}

/// A pair of datas which equivocate with each other.
///
/// These represent two separate [`Data`]s which were published with the same block number and
/// round number, by the same signer, when an honest validator will always only publish one such
/// message.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum EquivocatingData<S: Signature, A: AggregateSignature, B: Block> {
  Proposal {
    first_valid_round: Option<ValidRound<A>>,
    first_proposal: B::Hash,
    second_valid_round: Option<ValidRound<A>>,
    second_proposal: B::Hash,
  },
  Prevote {
    first_block: Option<B::Hash>,
    second_block: Option<B::Hash>,
  },
  Precommit {
    first_block_and_precommit_signature: Option<(B::Hash, S)>,
    second_block_and_precommit_signature: Option<(B::Hash, S)>,
  },
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for EquivocatingData<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Proposal { first_valid_round, first_proposal, second_valid_round, second_proposal } => {
        formatter
          .debug_struct("EquivocatingData::Proposal")
          .field("first_valid_round", first_valid_round)
          .field("first_proposal", first_proposal)
          .field("second_valid_round", second_valid_round)
          .field("second_proposal", second_proposal)
          .finish_non_exhaustive()
      }
      Self::Prevote { first_block, second_block } => formatter
        .debug_struct("EquivocatingData::Prevote")
        .field("first_block", first_block)
        .field("second_block", second_block)
        .finish_non_exhaustive(),
      Self::Precommit {
        first_block_and_precommit_signature,
        second_block_and_precommit_signature,
      } => formatter
        .debug_struct("EquivocatingData::Precommit")
        .field(
          "first_block",
          &first_block_and_precommit_signature.as_ref().map(|(block, _precommit_signature)| block),
        )
        .field(
          "second_block",
          &second_block_and_precommit_signature.as_ref().map(|(block, _precommit_signature)| block),
        )
        .finish_non_exhaustive(),
    }
  }
}

impl<S: Signature, A: AggregateSignature, B: Block> EquivocatingData<S, A, B> {
  #[expect(clippy::type_complexity)]
  fn split(&self) -> (Data<S, A, StubBlock<B::Hash>>, Data<S, A, StubBlock<B::Hash>>) {
    match self {
      EquivocatingData::Proposal {
        first_valid_round,
        first_proposal,
        second_valid_round,
        second_proposal,
      } => (
        Data::Proposal {
          valid_round: first_valid_round.clone(),
          proposal: StubBlock(*first_proposal),
        },
        Data::Proposal {
          valid_round: second_valid_round.clone(),
          proposal: StubBlock(*second_proposal),
        },
      ),
      EquivocatingData::Prevote { first_block, second_block } => {
        (Data::Prevote { block: *first_block }, Data::Prevote { block: *second_block })
      }
      EquivocatingData::Precommit {
        first_block_and_precommit_signature,
        second_block_and_precommit_signature,
      } => (
        Data::Precommit {
          block_and_precommit_signature: first_block_and_precommit_signature.clone(),
        },
        Data::Precommit {
          block_and_precommit_signature: second_block_and_precommit_signature.clone(),
        },
      ),
    }
  }
}

/// Evidence for a slash.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum Evidence<S: Signature, A: AggregateSignature, B: Block> {
  /// The validator equivocated, sending two distinct messages when they should have only sent one.
  Equivocation { data: EquivocatingData<S, A, B>, first_signature: S, second_signature: S },
  /// The validator created an invalid proposal.
  InvalidProposal { valid_round: Option<ValidRound<A>>, proposal: B::Hash, signature: S },
  /// The validator created an invalid precommit.
  InvalidPrecommit { block: B::Hash, precommit_signature: S, signature: S },
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for Evidence<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Equivocation { data, first_signature: _, second_signature: _ } => {
        formatter.debug_struct("Evidence::Equivocation").field("data", data).finish_non_exhaustive()
      }
      Self::InvalidProposal { valid_round, proposal, signature: _ } => formatter
        .debug_struct("Evidence::InvalidProposal")
        .field("valid_round", valid_round)
        .field("proposal", proposal)
        .finish_non_exhaustive(),
      Self::InvalidPrecommit { block, precommit_signature: _, signature: _ } => formatter
        .debug_struct("Evidence::InvalidPrecommit")
        .field("block", block)
        .finish_non_exhaustive(),
    }
  }
}

/// A reason to slash a validator.
///
/// This contains the necessary evidence to convince other validators of this slash.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct SlashReason<S: Signature, A: AggregateSignature, B: Block> {
  pub(crate) block_number: BlockNumber,
  pub(crate) round_number: RoundNumber,
  pub(crate) evidence: Evidence<S, A, B>,
}

impl<S: Signature, A: AggregateSignature, B: Block<Hash: fmt::Debug>> fmt::Debug
  for SlashReason<S, A, B>
{
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Self { block_number, round_number, evidence } = self;
    formatter
      .debug_struct("SlashReason")
      .field("block_number", block_number)
      .field("round_number", round_number)
      .field("evidence", evidence)
      .finish()
  }
}

impl<V: Validator, S: Signature, A: AggregateSignature, B: Block> Message<V, S, A, B> {
  #[must_use]
  pub(crate) fn signature_message(
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    data: &Data<S, A, B>,
  ) -> impl IntoIterator<IntoIter: Send, Item: AsRef<[u8]>> {
    enum Segment<G: AsRef<[u8]>> {
      Dst([u8; 1]),
      Genesis(G),
      U64([u8; 8]),
    }
    impl<G: AsRef<[u8]>> AsRef<[u8]> for Segment<G> {
      fn as_ref(&self) -> &[u8] {
        match self {
          Self::Dst(dst) => dst.as_slice(),
          Self::Genesis(genesis) => genesis.as_ref(),
          Self::U64(number) => number.as_slice(),
        }
      }
    }

    enum Either<L: AsRef<[u8]>, R: AsRef<[u8]>> {
      L(L),
      R(Option<R>),
    }
    impl<L: AsRef<[u8]>, R: AsRef<[u8]>> AsRef<[u8]> for Either<L, R> {
      fn as_ref(&self) -> &[u8] {
        match self {
          Either::L(l) => l.as_ref(),
          Either::R(Some(r)) => r.as_ref(),
          Either::R(None) => &[],
        }
      }
    }

    [
      Segment::Dst([1]),
      Segment::Dst([u8::try_from(genesis.as_ref().len()).unwrap()]),
      Segment::Genesis(genesis),
      Segment::U64(u64::from(block_number.0).to_le_bytes()),
      Segment::U64(u64::from(round_number.0).to_le_bytes()),
    ]
    .into_iter()
    .map(Either::L)
    .chain(data.signature_message().into_iter().map(Either::R))
  }

  #[must_use]
  pub(crate) async fn sign(
    signer: &impl Signer<Validator = V, Signature = S>,
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    data: Data<S, A, B>,
  ) -> Self {
    let signature =
      signer.sign(Self::signature_message(genesis, block_number, round_number, &data)).await;
    Self { validator: signer.validator().await, block_number, round_number, data, signature }
  }

  /// Verify all signatures within this message.
  ///
  /// This verifies not just the message's signature, but if this is a precommit with a contained
  /// signature, the precommit's signature as well. If the latter is invalid, the corresponding
  /// slash will be issued.
  pub(crate) fn verify_signatures(
    &self,
    blockchain: &impl Blockchain<
      Validator = V,
      SignatureScheme: SignatureScheme<Signature = S, AggregateSignature = A>,
      Block = B,
    >,
  ) -> Result<(), MessageError> {
    let validator_set = blockchain.validator_set();
    if validator_set.weight(&self.validator).is_none() {
      Err(MessageError::NotValidator)?;
    }

    let genesis = blockchain.genesis();
    let signature_scheme = blockchain.signature_scheme();

    if !signature_scheme.verify(
      &self.validator,
      Self::signature_message(&genesis, self.block_number, self.round_number, &self.data),
      &self.signature,
    ) {
      Err(MessageError::InvalidSignature)?;
    }

    if let Data::Proposal {
      valid_round: Some(ValidRound { round_number, aggregate_signature }),
      proposal,
    } = &self.data
    {
      if !signature_scheme
        .verify_aggregate(
          Self::signature_message(
            &genesis,
            self.block_number,
            *round_number,
            &Data::Prevote { block: Some(proposal.hash()) },
          ),
          aggregate_signature,
        )
        .is_ok_and(|validators| crate::validators_satisfy_threshold(validators, validator_set))
      {
        blockchain.slash(
          self.validator,
          SlashReason {
            block_number: self.block_number,
            round_number: self.round_number,
            evidence: Evidence::InvalidProposal {
              valid_round: Some(ValidRound {
                round_number: *round_number,
                aggregate_signature: aggregate_signature.clone(),
              }),
              proposal: proposal.hash(),
              signature: self.signature.clone(),
            },
          },
        );
        Err(MessageError::InvalidSignature)?;
      }
    }

    if let Data::Precommit { block_and_precommit_signature: Some((block, precommit_signature)) } =
      &self.data
    {
      if !Commit::verify_precommit(
        signature_scheme,
        &self.validator,
        genesis,
        self.block_number,
        self.round_number,
        block,
        precommit_signature,
      ) {
        blockchain.slash(
          self.validator,
          SlashReason {
            block_number: self.block_number,
            round_number: self.round_number,
            evidence: Evidence::InvalidPrecommit {
              block: *block,
              precommit_signature: precommit_signature.clone(),
              signature: self.signature.clone(),
            },
          },
        );
        Err(MessageError::InvalidSignature)?;
      }
    }

    Ok(())
  }
}

/// An invalid reason for a slash was provided.
#[derive(Clone, Debug)]
pub struct InvalidReason;

/// A stub block which satisfies the `Block` trait from only a hash.
///
/// We use this to build a `Data` (expecting `B: Block`) from solely a hash, as for the purposes of
/// verifying its signature.
#[derive(Clone)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
struct StubBlock<Hash>(Hash);
impl<Hash: Send + Sync + Clone + Copy + PartialEq + Eq + AsRef<[u8]> + crate::Borshy> Block
  for StubBlock<Hash>
{
  type Hash = Hash;
  fn hash(&self) -> Self::Hash {
    self.0
  }
}

impl<S: Signature, A: AggregateSignature, B: Block> SlashReason<S, A, B> {
  /// Verify the reasoning for this slash.
  pub fn verify<V: Validator>(
    &self,
    genesis: impl Send + Sync + AsRef<[u8]>,
    validator_set: &impl ValidatorSet<Validator = V>,
    signature_scheme: &impl SignatureScheme<Validator = V, Signature = S, AggregateSignature = A>,
    validator: V,
  ) -> Result<(), InvalidReason> {
    let verify_message = |data, signature| {
      if !signature_scheme.verify(
        &validator,
        Message::<V, S, A, _>::signature_message(
          &genesis,
          self.block_number,
          self.round_number,
          &data,
        ),
        signature,
      ) {
        // If this message's signature was invalid, this wasn't actually a message from the accused
        // validator, and this is an invalid reason to slash the accused validator
        Err(InvalidReason)?;
      }

      Ok(())
    };

    match &self.evidence {
      Evidence::Equivocation { data, first_signature, second_signature } => {
        let (data1, data2) = data.split();

        // If these aren't distinct, this isn't an equivocation
        if data1 == data2 {
          Err(InvalidReason)?;
        }

        // Check these were both signed by this validator
        for (data, signature) in [(data1, first_signature), (data2, second_signature)] {
          verify_message(data, signature)?;
        }
      }
      Evidence::InvalidProposal { valid_round, proposal, signature } => {
        // Check this was a proposal message signed by this validator
        verify_message(
          Data::Proposal { valid_round: valid_round.clone(), proposal: StubBlock(*proposal) },
          signature,
        )?;

        // If the structure of this proposal was valid, this is an invalid reason to slash this
        // validator
        if (validator == validator_set.proposer(self.block_number, self.round_number)) &&
          match valid_round {
            Some(ValidRound { round_number, aggregate_signature }) => {
              ((*round_number) < self.round_number) &&
                signature_scheme
                  .verify_aggregate(
                    Message::<V, S, A, B>::signature_message(
                      &genesis,
                      self.block_number,
                      *round_number,
                      &Data::Prevote { block: Some(*proposal) },
                    ),
                    aggregate_signature,
                  )
                  .is_ok_and(|validators| {
                    crate::validators_satisfy_threshold(validators, validator_set)
                  })
            }
            None => true,
          }
        {
          Err(InvalidReason)?;
        }
      }
      Evidence::InvalidPrecommit { block, precommit_signature, signature } => {
        // Check this was a precommit message signed by this validator
        verify_message(
          Data::Precommit {
            block_and_precommit_signature: Some((*block, precommit_signature.clone())),
          },
          signature,
        )?;

        // If the inner signature is valid, this a valid precommit and an invalid reason to slash
        // the accused validator
        if Commit::verify_precommit(
          signature_scheme,
          &validator,
          genesis,
          self.block_number,
          self.round_number,
          block,
          precommit_signature,
        ) {
          Err(InvalidReason)?;
        }
      }
    }

    Ok(())
  }
}
