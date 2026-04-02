use sp_core::Get;
use frame_support::{weights::Weight, dispatch::PerDispatchClass};
use frame_system::limits::{BlockLength, BlockWeights};

/// The limits for the Serai protocol.
pub struct Limits;
impl Get<BlockLength> for Limits {
  fn get() -> BlockLength {
    /*
      We do not differentiate based on whether a transaction is mandatory/operational, assuming
      transactions will be prioritized in the mempool. This does technically give block producers
      an incentive to misbehave by on-purposely favoring paying non-operational transactions over
      operational transactions, but ensures the entire block is available to the transactions
      actually present in the mempool.

      The header size limit is unlimited as Serai's header is of fixed size, and while the
      committed-to Substrate header is not by syntax, its digests are fixed and finite. This
      removes the need to bound it. Note `Some(_)` is used as `None` would not state there is no
      max header size but rather effect a default value of 20% of the block size limit. The
      subtraction of the size of a `u32` is an allowance for the encoding of the length of an empty
      `transactions` vector.

      Serai does not use `frame-system`'s provided transaction extension to enforce these limits.
      It implements its own solution to enforce the block size accordingly. That makes this setting
      pointless other than as a declared intent. Note this intent is somewhat fuzzy as it's a
      `Block`'s, not a `SubstrateBlock`'s, max size declared as the intent within the Substrate
      runtime.
    */
    let block_size_limit = u32::try_from(serai_abi::Block::MAX_SIZE).unwrap();
    BlockLength {
      max: PerDispatchClass::new(|_| block_size_limit),
      max_header_size: Some(block_size_limit - (u32::BITS / u8::BITS)),
    }
  }
}
impl Get<BlockWeights> for Limits {
  fn get() -> BlockWeights {
    /*
      While Serai does limit the size of a block, every transaction is expected to operate in
      complexity constant to the current state size, regardless of what the state is. Accordingly,
      the most efficient set of transactions (basic transfers?) is expected to be within an order
      of magnitude of the most expensive transactions (multi-pool swaps?).

      Instead of engaging with the complexity within the consensus protocol of metering both
      bandwidth and computation, we do not define limits for weights. We do, however, still use the
      weight system in order to determine fee rates and ensure prioritization to
      computationally-cheaper transactions. That solely serves as mempool policy however.

      Finally, the block size limit is incredibly conservative, allowing us to take this
      somewhat-ignorant position. Future discussion is to be tracked in
      https://github.com/serai-dex/serai/issues/715, and if necessary, a soft fork could be
      introduced to not accept blocks of a sufficient weight unless already finalized. This allows
      flexibility outside of the hard fork schedule.

      And then again, as above, Serai does not use `frame-system`'s provided transaction extension
      which enforces these limits, so this is also simply a declaration of intent and practice.
    */
    BlockWeights::simple_max(Weight::MAX)
  }
}

// This simply tests the above getters do not panic.
#[test]
fn limits() {
  <Limits as Get<BlockLength>>::get();
  <Limits as Get<BlockWeights>>::get();
}
