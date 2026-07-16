use core::fmt;

use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet as _, Signature, AggregateSignature,
  SignatureScheme, Signer, Block, Commit, Blockchain, Evidence, SlashReason,
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
///
/// In order for this to be valid, the signature MUST be valid and aggregated from signatures by
/// validators whose weight is sufficient for the threshold. Deserialization or instantiation alone
/// DOES NOT signify validity.
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
  Proposal {
    #[borsh(bound(
      serialize = "A: borsh::BorshSerialize",
      deserialize = "A: borsh::BorshDeserialize"
    ))]
    valid_round: Option<ValidRound<A>>,
    #[borsh(bound(
      serialize = "B: borsh::BorshSerialize",
      deserialize = "B: borsh::BorshDeserialize"
    ))]
    proposal: B,
  },
  Prevote {
    #[borsh(bound(
      serialize = "B::Hash: borsh::BorshSerialize",
      deserialize = "B::Hash: borsh::BorshDeserialize"
    ))]
    block: Option<B::Hash>,
  },
  Precommit {
    #[borsh(bound(
      serialize = "S: borsh::BorshSerialize, B::Hash: borsh::BorshSerialize",
      deserialize = "S: borsh::BorshDeserialize, B::Hash: borsh::BorshDeserialize"
    ))]
    block_and_precommit_signature: Option<(B::Hash, S)>,
  },
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
      (
        Data::Precommit { block_and_precommit_signature: Some(_) },
        Data::Precommit { block_and_precommit_signature: None },
      ) |
      (
        Data::Precommit { block_and_precommit_signature: None },
        Data::Precommit { block_and_precommit_signature: Some(_) },
      ) |
      (Data::Proposal { .. }, Data::Prevote { .. } | Data::Precommit { .. }) |
      (Data::Prevote { .. }, Data::Proposal { .. } | Data::Precommit { .. }) |
      (Data::Precommit { .. }, Data::Proposal { .. } | Data::Prevote { .. }) => false,
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
  #[borsh(bound(
    serialize = "
      S: borsh::BorshSerialize,
      A: borsh::BorshSerialize,
      B: borsh::BorshSerialize,
      B::Hash: borsh::BorshSerialize
    ",
    deserialize = "
      S: borsh::BorshDeserialize,
      A: borsh::BorshDeserialize,
      B: borsh::BorshDeserialize,
      B::Hash: borsh::BorshDeserialize
    "
  ))]
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

impl<V: Validator, S: Signature, A: AggregateSignature, B: Block> Message<V, S, A, B> {
  #[must_use]
  pub(crate) fn signature_message(
    genesis: impl Send + AsRef<[u8]>,
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
      R(R),
    }
    impl<L: AsRef<[u8]>, R: AsRef<[u8]>> AsRef<[u8]> for Either<L, R> {
      fn as_ref(&self) -> &[u8] {
        match self {
          Either::L(l) => l.as_ref(),
          Either::R(r) => r.as_ref(),
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
    .chain(data.signature_message().into_iter().filter_map(|value| value.map(Either::R)))
  }

  #[must_use]
  pub(crate) async fn sign(
    signer: &impl Signer<Validator = V, Signature = S>,
    genesis: impl Send + AsRef<[u8]>,
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
    let genesis = genesis.as_ref();
    let signature_scheme = blockchain.signature_scheme();

    if !signature_scheme.verify(
      &self.validator,
      Self::signature_message(genesis, self.block_number, self.round_number, &self.data),
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
            genesis,
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
