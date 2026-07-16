use core::{future::Future, num::NonZero};

use crate::{Validator, SignatureScheme, ValidatorSet, Commit, SlashReason};

/// A block's number.
///
/// The genesis block is considered to have number `0` where following blocks' numbers increase
/// incrementally by one.
///
/// As this library never works with the genesis block, as it's constant and does not undergo the
/// consensus process, this library represents block numbers via [`NonZero`]. This is complete to
/// all block numbers this library has to consider.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[repr(transparent)]
pub struct BlockNumber(pub(crate) NonZero<u64>);
impl BlockNumber {
  pub(crate) const ONE: Self = Self(NonZero::new(1).unwrap());
}
impl From<BlockNumber> for u64 {
  fn from(block_number: BlockNumber) -> Self {
    u64::from(block_number.0)
  }
}
impl From<NonZero<u64>> for BlockNumber {
  fn from(block_number: NonZero<u64>) -> Self {
    Self(block_number)
  }
}
/// A round's number.
///
/// Tendermint describes this as starting from `0`, yet we start it from `1`. This has two
/// benefits:
/// 1) It allows representing `None` (our representation of what the paper describes as `-1`) as
///    `0`, saving a byte in memory and encoding
/// 2) It slightly simplifies calculating timeouts
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[repr(transparent)]
pub struct RoundNumber(pub(crate) NonZero<u64>);
impl RoundNumber {
  pub(crate) const ONE: Self = Self(NonZero::new(1).unwrap());
}
impl From<RoundNumber> for u64 {
  fn from(round_number: RoundNumber) -> Self {
    u64::from(round_number.0)
  }
}

/// The block was invalid.
#[derive(Clone, Copy, Debug)]
pub struct InvalidBlock;

/// A view over the application layer's block.
///
/// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
/// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing a
/// value which was successfully serialized, from a well-formed reader.
pub trait Block: Send + Sync + Clone {
  // The type representing a block's hash.
  ///
  /// The `AsRef<[u8]>` implementation MUST return a slice with a consistent length for _any_
  /// value, meaning it's _constant_.
  ///
  /// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
  /// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing
  /// a value which was successfully serialized, from a well-formed reader.
  type Hash: Send + Clone + Copy + PartialEq + Eq + AsRef<[u8]>;

  /// The block's hash.
  ///
  /// This MUST be cryptographically binding to the entirety of the block.
  ///
  /// For two blocks, `b1` and `b2`, `b1 == b2` MUST equal `b1.hash() == b2.hash()`, except with
  /// negligible probability (per the binding property).
  ///
  /// This MUST always return the same hash for a value upon each call.
  fn hash(&self) -> Self::Hash;
}

/// A view of the application layer's blockchain.
pub trait Blockchain {
  /// The type used to identify validators.
  ///
  /// It is RECOMMENDED to use [`u16`] to identify validators.
  type Validator: Validator;
  /// The type used to define the validator set.
  type ValidatorSet: ValidatorSet<Validator = Self::Validator>;
  /// The signature scheme used by validators.
  type SignatureScheme: SignatureScheme<Validator = Self::Validator>;
  /// The block type.
  type Block: Block;

  /// The future for a block proposal.
  ///
  /// This allows the proposal to not be _immediately_ ready, such as if the blockchain is still
  /// syncing, where this future will be occasionally polled (likely infrequently) for if the
  /// proposal is ready. It is RECOMMENDED to literally instantiate it with
  /// [`futures_channel::oneshot::Receiver`] or similar.
  type BlockProposal: Future<Output = Self::Block>;

  /// The genesis ID of this blockchain.
  ///
  /// This MUST be consistent for the lifetime of this blockchain and unique across blockchains.
  /// This DOES NOT need to satisfy any cryptographic binding properties and is solely used for
  /// domain-separation purposes. This MUST have a length less than or equal to [`u8::MAX`].
  fn genesis(&self) -> impl Send + AsRef<[u8]>;

  /// The validator set's definition.
  ///
  /// This MUST be consistent for the lifetime of this blockchain.
  fn validator_set(&self) -> &Self::ValidatorSet;

  /// The signature scheme for this blockchain.
  fn signature_scheme(&self) -> &Self::SignatureScheme;

  /// Validate a block.
  ///
  /// This SHOULD NOT cause any mutations to the blockchain. This solely validates a potential
  /// candidate with minimal context passed and no call pattern guaranteed. The proposer is
  /// specified in case the blockchain wishes to record a slash for this block, if it is
  /// fundamentally invalid.
  // TODO: Don't just provide the proposer, but enough to build evidence sufficient to convince
  // someone else (the signed proposal message)?
  // TODO: `&mut self`?
  fn validate(
    &self,
    proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>>;

  /// Add a block, returning a future for the proposal for the next block.
  ///
  /// It's possible a block, which was never validated or even failed validation, may be passed
  /// here if a supermajority of validators did consider it valid and created a verified commit for
  /// it. This deviates from the paper which will have a local node refuse to decide on a block it
  /// considers invalid. This library acknowledges the validators did decide on it, leaving
  /// handling of it to the application layer, and outside of this scope. If this block is invalid,
  /// it's a break in the assumptions required for Tendermint's soundness.
  ///
  /// The proposal for the next block is returned as a [`Future`]. This allows the proposal to not
  /// be ready _yet_, such as if the blockchain is still syncing, where this future will be
  /// occasionally polled (likely infrequently) for if the proposal is ready. It likely SHOULD be
  /// literally instantiated with [`futures_channel::oneshot::Receiver`] or similar.
  ///
  /// This MAY be called multiple times if the process reboots before the Tendermint process
  /// commits its advanced state. The underlying blockchain MUST be able to handle being asked to
  /// add a block which it already added.
  fn add_block(
    &mut self,
    block: Self::Block,
    commit: Commit<Self::SignatureScheme>,
  ) -> impl Send + Future<Output = Self::BlockProposal>;

  /// Record a missed proposal.
  ///
  /// This is a non-`async` function as this is expected to be implemented in a non-blocking
  /// fashion as to not hold up the consensus process.
  ///
  /// A missed proposal is LIKELY something which should cause the validator to be slashed.
  /// However, there is no evidence for a missed proposal as it may have never been sent, or may
  /// have simply not been received by the local view (which may be the one faulty). For this
  /// reason, it's explicitly distinguished from a slash.
  // TODO: `&mut self`?
  fn missed_proposal(&self, proposer: Self::Validator);

  /// Slash a validator.
  ///
  /// This is a non-`async` function as this is expected to be implemented in a non-blocking
  /// fashion as to not hold up the consensus process.
  ///
  /// The actual recording of this slash and its interpretation is left entirely to the application
  /// layer. All slashes have the necessary evidence and can be verified by this library.
  // TODO: `&mut self`?
  fn slash(
    &self,
    validator: Self::Validator,
    slash_reason: SlashReason<
      <Self::SignatureScheme as SignatureScheme>::Signature,
      <Self::SignatureScheme as SignatureScheme>::AggregateSignature,
      Self::Block,
    >,
  );
}
