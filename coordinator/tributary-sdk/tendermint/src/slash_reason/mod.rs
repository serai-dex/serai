use core::fmt;

use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet, Signature, AggregateSignature,
  SignatureScheme, BlockHash, Block, Blockchain, ValidRound, Data, Message, MessageError,
};

#[cfg(test)]
mod tests;

/// A pair of datas which equivocate with each other.
///
/// These represent two separate [`Data`]s which were published with the same block number and
/// round number, by the same signer, when an honest validator will always only publish one such
/// message.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum EquivocatingData<S: Signature, A: AggregateSignature, H: BlockHash> {
  Proposal {
    first_valid_round: Option<ValidRound<A>>,
    first_proposal: H,
    second_valid_round: Option<ValidRound<A>>,
    second_proposal: H,
  },
  Prevote {
    first_block: Option<H>,
    second_block: Option<H>,
  },
  Precommit {
    first_block_and_precommit_signature: Option<(H, S)>,
    second_block_and_precommit_signature: Option<(H, S)>,
  },
}

impl<S: Signature, A: AggregateSignature, H: fmt::Debug + BlockHash> fmt::Debug
  for EquivocatingData<S, A, H>
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

/// A block hash, yet wrapped as to be opaque.
///
/// We use this to ensure that this type only implements the traits we explicitly want implemented.
/// The main thing we want to avoid is an inadvertent implementation of [`BorshSerialize`] or
/// [`BorshDeserialize`], as this isn't guaranteed to have an equivalent [`borsh`] representation
/// to the original type this fills in for.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct OpaqueBlockHash<'hash>(&'hash [u8]);
impl AsRef<[u8]> for OpaqueBlockHash<'_> {
  fn as_ref(&self) -> &[u8] {
    self.0
  }
}

/// A stub block which satisfies the `Block` trait from only a hash.
///
/// We use this to build a `Data` (expecting `B: Block`) from solely a hash, as for the purposes of
/// verifying its signature.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[repr(transparent)]
pub(crate) struct StubBlock<'hash>(&'hash [u8]);

#[cfg(test)]
impl<'hash> StubBlock<'hash> {
  pub(crate) fn from(hash: &'hash [u8]) -> Self {
    Self(hash)
  }
}
impl<'hash> Block for StubBlock<'hash> {
  type Hash = OpaqueBlockHash<'hash>;
  fn hash(&self) -> Self::Hash {
    OpaqueBlockHash(self.0)
  }
}

impl<S: Signature, A: AggregateSignature, H: BlockHash> EquivocatingData<S, A, H> {
  fn split(&self) -> (Data<S, A, StubBlock<'_>>, Data<S, A, StubBlock<'_>>) {
    match self {
      EquivocatingData::Proposal {
        first_valid_round,
        first_proposal,
        second_valid_round,
        second_proposal,
      } => (
        Data::Proposal {
          valid_round: first_valid_round.clone(),
          proposal: StubBlock(first_proposal.as_ref()),
        },
        Data::Proposal {
          valid_round: second_valid_round.clone(),
          proposal: StubBlock(second_proposal.as_ref()),
        },
      ),
      EquivocatingData::Prevote { first_block, second_block } => (
        Data::Prevote { block: first_block.as_ref().map(|hash| OpaqueBlockHash(hash.as_ref())) },
        Data::Prevote { block: second_block.as_ref().map(|hash| OpaqueBlockHash(hash.as_ref())) },
      ),
      EquivocatingData::Precommit {
        first_block_and_precommit_signature,
        second_block_and_precommit_signature,
      } => (
        Data::Precommit {
          block_and_precommit_signature: first_block_and_precommit_signature
            .as_ref()
            .map(|(block, signature)| (OpaqueBlockHash(block.as_ref()), signature.clone())),
        },
        Data::Precommit {
          block_and_precommit_signature: second_block_and_precommit_signature
            .as_ref()
            .map(|(block, signature)| (OpaqueBlockHash(block.as_ref()), signature.clone())),
        },
      ),
    }
  }
}

/// Evidence for a slash.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub(crate) enum Evidence<S: Signature, A: AggregateSignature, H: BlockHash> {
  /// The validator equivocated, sending two distinct messages when they should have only sent one.
  Equivocation { data: EquivocatingData<S, A, H>, first_signature: S, second_signature: S },
  /// The validator created an invalid proposal.
  InvalidProposal { valid_round: Option<ValidRound<A>>, proposal: H, signature: S },
  /// The validator created an invalid precommit.
  InvalidPrecommit { block: H, precommit_signature: S, signature: S },
}

impl<S: Signature, A: AggregateSignature, H: fmt::Debug + BlockHash> fmt::Debug
  for Evidence<S, A, H>
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
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct SlashReason<S: Signature, A: AggregateSignature, H: BlockHash> {
  pub(crate) block_number: BlockNumber,
  pub(crate) round_number: RoundNumber,
  pub(crate) evidence: Evidence<S, A, H>,
}

/// The [`SlashReason`] type for a [`Blockchain`].
pub type SlashReasonFor<B> = SlashReason<
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::Signature,
  <<B as Blockchain>::SignatureScheme as SignatureScheme>::AggregateSignature,
  <<B as Blockchain>::Block as Block>::Hash,
>;

impl<S: Signature, A: AggregateSignature, H: fmt::Debug + BlockHash> fmt::Debug
  for SlashReason<S, A, H>
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

/// An invalid reason for a slash was provided.
#[derive(Clone, Debug)]
pub struct InvalidReason;

impl<S: Signature, A: AggregateSignature, H: BlockHash> SlashReason<S, A, H> {
  /// Form a `SlashReason` from a pair of equivocating messages.
  ///
  /// This does not guarantee the messages actually form an equivocation. This will return `None`
  /// if the messages are not of the same type and therefore fundamentally cannot form an
  /// equivocation.
  pub(crate) fn equivocation<V: Validator, B: Block<Hash = H>>(
    first_message: Message<V, S, A, B>,
    second_message: Message<V, S, A, B>,
  ) -> Option<Self> {
    Some(Self {
      block_number: first_message.block_number,
      round_number: first_message.round_number,
      evidence: Evidence::Equivocation {
        data: match (first_message.data, second_message.data) {
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
            Data::Precommit { block_and_precommit_signature: first_block_and_precommit_signature },
            Data::Precommit { block_and_precommit_signature: second_block_and_precommit_signature },
          ) => EquivocatingData::Precommit {
            first_block_and_precommit_signature,
            second_block_and_precommit_signature,
          },
          _ => None?,
        },
        first_signature: first_message.signature,
        second_signature: second_message.signature,
      },
    })
  }

  /// Verify the reasoning for this slash.
  pub fn verify<V: Validator>(
    &self,
    genesis: impl AsRef<[u8]>,
    validator_set: &(impl ?Sized + ValidatorSet<Validator = V>),
    signature_scheme: &(
       impl ?Sized + SignatureScheme<Validator = V, Signature = S, AggregateSignature = A>
     ),
    validator: V,
  ) -> Result<(), InvalidReason> {
    match &self.evidence {
      Evidence::Equivocation { data, first_signature, second_signature } => {
        let (data1, data2) = data.split();

        // If these aren't distinct, this isn't an equivocation
        if data1 == data2 {
          Err(InvalidReason)?;
        }

        // Check these were both signed by this validator
        for (data, signature) in [(data1, first_signature), (data2, second_signature)] {
          let verify_message = |data, signature| {
            if !signature_scheme.verify(
              &validator,
              Message::<V, S, A, _>::signature_message(
                genesis.as_ref(),
                self.block_number,
                self.round_number,
                &data,
              ),
              signature,
            ) {
              /*
                If this message's signature was invalid, this wasn't actually a message from the
                accused validator, and this is an invalid reason to slash the accused validator.
              */
              Err(InvalidReason)?;
            }

            Ok(())
          };

          verify_message(data, signature)?;
        }
      }
      Evidence::InvalidProposal { valid_round, proposal, signature } => {
        if !matches!(
          (Message {
            validator,
            block_number: self.block_number,
            round_number: self.round_number,
            data: Data::Proposal {
              valid_round: valid_round.clone(),
              proposal: StubBlock(proposal.as_ref()),
            },
            signature: signature.clone(),
          })
          .static_verificiation(genesis, validator_set, signature_scheme),
          Err(MessageError::Invalid(SlashReason { .. }))
        ) {
          Err(InvalidReason)?;
        }
      }
      Evidence::InvalidPrecommit { block, precommit_signature, signature } => {
        if !matches!(
          (Message::<_, _, _, StubBlock<'_>> {
            validator,
            block_number: self.block_number,
            round_number: self.round_number,
            data: Data::Precommit {
              block_and_precommit_signature: Some((
                StubBlock(block.as_ref()).hash(),
                precommit_signature.clone()
              )),
            },
            signature: signature.clone(),
          })
          .static_verificiation(genesis, validator_set, signature_scheme),
          Err(MessageError::Invalid(SlashReason { .. }))
        ) {
          Err(InvalidReason)?;
        }
      }
    }

    Ok(())
  }
}
