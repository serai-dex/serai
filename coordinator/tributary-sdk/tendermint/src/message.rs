use core::{iter::Flatten, fmt};

use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet, Signature, AggregateSignature,
  SignatureScheme, Signer, BlockHash, Block, Commit, Blockchain, Evidence, SlashReason,
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

#[doc(hidden)]
pub(crate) enum MessageSegment<'genesis, S: Signature, A: AggregateSignature, B: Block> {
  Dst([u8; 1]),
  Genesis(&'genesis [u8]),
  U64([u8; 8]),
  AggregateSignature(A),
  Block(B::Hash),
  PrecommitSignature(S),
}
impl<S: Signature, A: AggregateSignature, B: Block> AsRef<[u8]> for MessageSegment<'_, S, A, B> {
  fn as_ref(&self) -> &[u8] {
    match self {
      Self::Dst(dst) => dst.as_slice(),
      Self::Genesis(genesis) => genesis,
      Self::U64(round_number) => round_number.as_slice(),
      Self::AggregateSignature(aggregate_signature) => aggregate_signature.as_ref(),
      Self::Block(block) => block.as_ref(),
      Self::PrecommitSignature(precommit_signature) => precommit_signature.as_ref(),
    }
  }
}

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
  fn signature_message(&self) -> [Option<MessageSegment<'static, S, A, B>>; 5] {
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
          /*
            `round_number` and `aggregate_signature` are both `Some` or both `None`, and
            `round_number` is fixed-length, preventing collisions between the two of them.
          */
          round_number,
          aggregate_signature,
          /*
            We only sign the hash to avoid having to serialize/store the entire block.

            This is bound to be of fixed-length so it does not need length-prefixing, nor do the
            prior two fields (which behave as a single field, the sole field of variable length in
            this message).
          */
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
            The block hash has a fixed length and these are both `Some` or both `None`, meaning
            that regardless of the precommit signature's encoding, this is without conflict.
          */
          block,
          precommit_signature,
        )
      }
    };

    [
      Some(MessageSegment::<S, A, B>::Dst([kind])),
      round_number.map(MessageSegment::U64),
      aggregate_signature.map(MessageSegment::AggregateSignature),
      block.map(MessageSegment::Block),
      precommit_signature.map(MessageSegment::PrecommitSignature),
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

#[cfg_attr(test, derive(Debug))]
pub(crate) enum MessageError<S: Signature, A: AggregateSignature, H: BlockHash> {
  /// The message was stale within the current context.
  Stale,
  /// The message was for a future context.
  ///
  /// This MAY suggest the local view is historic.
  Future,
  /// The message was not from a validator.
  NotValidator,
  /// The message had an invalid signature and could not be authenticated as from the validator.
  InvalidOuterSignature,
  /// The message has an invalid intenal structure.
  Invalid(SlashReason<S, A, H>),
  /// This message has already been handled.
  AlreadyHandled,
}

type MessageSignatureMessage<'genesis, S, A, B> =
  Flatten<<[Option<MessageSegment<'genesis, S, A, B>>; 10] as IntoIterator>::IntoIter>;
impl<V: Validator, S: Signature, A: AggregateSignature, B: Block> Message<V, S, A, B> {
  #[expect(clippy::many_single_char_names)]
  pub(crate) fn signature_message<'genesis>(
    genesis: &'genesis [u8],
    block_number: BlockNumber,
    round_number: RoundNumber,
    data: &Data<S, A, B>,
  ) -> MessageSignatureMessage<'genesis, S, A, B> {
    let [a, b, c, d, e] = [
      MessageSegment::Dst([1]),
      MessageSegment::Dst([u8::try_from(genesis.len()).unwrap()]),
      MessageSegment::Genesis(genesis),
      MessageSegment::U64(u64::from(block_number).to_le_bytes()),
      MessageSegment::U64(u64::from(round_number).to_le_bytes()),
    ]
    .map(Some);
    let [f, g, h, i, j] = data.signature_message();

    [a, b, c, d, e, f, g, h, i, j].into_iter().flatten()
  }

  #[must_use]
  pub(crate) async fn sign(
    signer: &(impl ?Sized + Signer<Validator = V, Signature = S>),
    genesis: &[u8],
    block_number: BlockNumber,
    round_number: RoundNumber,
    data: Data<S, A, B>,
  ) -> Self {
    let signature =
      signer.sign(Self::signature_message(genesis, block_number, round_number, &data)).await;
    Self { validator: signer.validator(), block_number, round_number, data, signature }
  }

  /// Perform static verification for this message.
  ///
  /// This only verifies the values within this message which can be verified against solely the
  /// `blockchain` itself, without any state from the Tendermint consensus process. This includes:
  ///
  /// - The message is from a validator
  /// - The message's signature
  /// - The signatures inside the message ([`ValidRound`], the precommit signature)
  /// - The proposer is actually the proposer for this round
  /// - The valid round's round number is less than this message's round number
  pub(crate) fn static_verificiation(
    &self,
    genesis: impl AsRef<[u8]>,
    validator_set: &(impl ?Sized + ValidatorSet<Validator = V>),
    signature_scheme: &(impl ?Sized
        + SignatureScheme<Validator = V, Signature = S, AggregateSignature = A>),
  ) -> Result<(), MessageError<S, A, B::Hash>> {
    let genesis = genesis.as_ref();

    if validator_set.weight(&self.validator).is_none() {
      Err(MessageError::NotValidator)?;
    }

    if !signature_scheme.verify(
      &self.validator,
      Self::signature_message(genesis, self.block_number, self.round_number, &self.data),
      &self.signature,
    ) {
      Err(MessageError::InvalidOuterSignature)?;
    }

    match &self.data {
      Data::Proposal { valid_round, proposal } => {
        if !(valid_round.as_ref().is_none_or(|ValidRound { round_number, aggregate_signature }| {
          ((*round_number) < self.round_number) &&
            signature_scheme
              .verify_aggregate(
                Self::signature_message(
                  genesis,
                  self.block_number,
                  *round_number,
                  &Data::Prevote { block: Some(proposal.hash()) },
                ),
                aggregate_signature,
              )
              .is_ok_and(|validators| {
                crate::validators_satisfy_threshold(validators, validator_set)
              })
        }) && (self.validator == validator_set.proposer(self.block_number, self.round_number)))
        {
          Err(MessageError::Invalid(SlashReason {
            block_number: self.block_number,
            round_number: self.round_number,
            evidence: Evidence::InvalidProposal {
              valid_round: valid_round.clone(),
              proposal: proposal.hash(),
              signature: self.signature.clone(),
            },
          }))?;
        }
      }
      Data::Precommit { block_and_precommit_signature: Some((block, precommit_signature)) } => {
        if !Commit::verify_precommit(
          signature_scheme,
          &self.validator,
          genesis,
          self.block_number,
          self.round_number,
          block.as_ref(),
          precommit_signature,
        ) {
          Err(MessageError::Invalid(SlashReason {
            block_number: self.block_number,
            round_number: self.round_number,
            evidence: Evidence::InvalidPrecommit {
              block: *block,
              precommit_signature: precommit_signature.clone(),
              signature: self.signature.clone(),
            },
          }))?;
        }
      }
      Data::Prevote { .. } | Data::Precommit { block_and_precommit_signature: None } => {}
    }

    Ok(())
  }
}

#[cfg(test)]
pub(crate) fn random_valid_round(
) -> Option<ValidRound<<crate::TestSignatureScheme as SignatureScheme>::AggregateSignature>> {
  use core::num::NonZero;
  use rand_core::{TryRngCore as _, OsRng};

  ((OsRng.try_next_u64().unwrap() & 1) == 1).then(|| {
    let round_number =
      RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let mut aggregate_signature = [0; 8 + 32];
    OsRng.try_fill_bytes(&mut aggregate_signature).unwrap();
    ValidRound { round_number, aggregate_signature }
  })
}

#[test]
fn test_random_valid_round() {
  let mut some = false;
  let mut none = false;
  for _ in 0 .. 128 {
    some |= random_valid_round().is_some();
    none |= random_valid_round().is_none();
  }
  assert!(some);
  assert!(none);
}

#[cfg(feature = "alloc")]
#[test]
fn signature_message() {
  use core::num::NonZero;
  use alloc::{vec::Vec, vec};

  use rand_core::{TryRngCore as _, OsRng};

  use crate::{StubBlock, TestSignatureScheme};

  for _ in 0 .. 128 {
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    let genesis_len = OsRng.try_next_u64().unwrap() as u8;
    let mut genesis = vec![0xff; usize::from(genesis_len)];
    OsRng.try_fill_bytes(&mut genesis).unwrap();
    let genesis = genesis.as_ref();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number =
      RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

    let mut block = [0xff; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(&block);

    type TestData<'hash> = Data<
      <TestSignatureScheme as SignatureScheme>::Signature,
      <TestSignatureScheme as SignatureScheme>::AggregateSignature,
      StubBlock<'hash>,
    >;

    let mut signature = [0; 1 + 8];
    OsRng.try_fill_bytes(&mut signature).unwrap();

    let valid_round = loop {
      let valid_round = random_valid_round();
      if let Some(valid_round) = valid_round {
        break valid_round;
      }
    };

    let prefix = [
      [1].as_slice(),
      [genesis_len].as_slice(),
      genesis,
      u64::from(block_number).to_le_bytes().as_slice(),
      u64::from(round_number).to_le_bytes().as_slice(),
    ]
    .concat();

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Proposal { valid_round: Some(valid_round.clone()), proposal: block.clone() }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [
        prefix.as_slice(),
        [0].as_slice(),
        u64::from(valid_round.round_number).to_le_bytes().as_slice(),
        valid_round.aggregate_signature.as_ref(),
        block.hash().as_ref(),
      ]
      .concat(),
    );

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Proposal { valid_round: None, proposal: block.clone() }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [prefix.as_slice(), [0].as_slice(), block.hash().as_ref()].concat(),
    );

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Prevote { block: Some(block.hash()) }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [prefix.as_slice(), [1].as_slice(), block.hash().as_ref()].concat(),
    );

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Prevote { block: None }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [prefix.as_slice(), [1].as_slice()].concat(),
    );

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Precommit { block_and_precommit_signature: Some((block.hash(), signature)) }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [prefix.as_slice(), [2].as_slice(), block.hash().as_ref(), signature.as_ref()].concat(),
    );

    assert_eq!(
      Message::<<TestSignatureScheme as SignatureScheme>::Validator, _, _, _>::signature_message(
        genesis,
        block_number,
        round_number,
        &TestData::Precommit { block_and_precommit_signature: None }
      )
      .fold(Vec::<u8>::new(), |mut accum, item| {
        accum.extend(item.as_ref());
        accum
      }),
      [prefix.as_slice(), [2].as_slice()].concat(),
    );
  }
}

#[cfg(feature = "alloc")]
#[test]
fn sign() {
  use core::num::NonZero;
  use core::{
    pin::pin,
    task::{Poll, Waker, Context},
    future::Future as _,
  };

  use rand_core::{TryRngCore as _, OsRng};

  use crate::{StubBlock, TestSignatureScheme};

  for _ in 0 .. 128 {
    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = ((OsRng.try_next_u64().unwrap() & 1) == 1).then_some(block);

    let data =
      Data::Prevote { block: block.as_ref().map(|block| StubBlock::from(block.as_slice()).hash()) };

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number =
      RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

    let signature_scheme = TestSignatureScheme::new();
    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(message) =
      pin!(Message::<
        _,
        _,
        <TestSignatureScheme as SignatureScheme>::AggregateSignature,
        StubBlock<'_>,
      >::sign(&signer, &genesis, block_number, round_number, data))
      .poll(&mut context)
    else {
      panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
    };

    let one_weight = NonZero::new(1).unwrap();
    let validator_set = alloc::collections::BTreeMap::from([(0, one_weight), (1, one_weight)]);
    message.static_verificiation(genesis, &validator_set, &signature_scheme).unwrap();

    {
      let mut message = message.clone();
      message.signature[0] ^= 1;
      assert!(matches!(
        message.static_verificiation(genesis, &validator_set, &signature_scheme),
        Err(MessageError::InvalidOuterSignature)
      ));
    }

    {
      let mut message = message.clone();
      message.validator = 1;
      assert!(matches!(
        message.static_verificiation(genesis, &validator_set, &signature_scheme),
        Err(MessageError::InvalidOuterSignature)
      ));
    }

    {
      let mut message = message.clone();
      message.validator = 2;
      assert!(matches!(
        message.static_verificiation(genesis, &validator_set, &signature_scheme),
        Err(MessageError::NotValidator)
      ));
    }
  }
}
