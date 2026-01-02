use sp_core::Get;
use frame_support::weights::Weight;
use frame_system::limits::{BlockLength, BlockWeights};

/// The limits for the Serai protocol.
pub struct Limits;
impl Get<BlockLength> for Limits {
  fn get() -> BlockLength {
    /*
      We do not reserve an allocation for mandatory/operational transactions, assuming they'll be
      prioritized in the mempool. This does technically give block producers an inventive to
      misbehave by on-purposely favoring paying non-operational transactions over operational
      transactions, but ensures the entire block is available to the transactions actually present
      in the mempool.

      Additionally, Serai does not use `frame-system`'s provided transaction extension to enforce
      these limits. It implements its own solution to enforce the block size accordingly. That
      makes this setting pointless other than as a declared intent.
    */
    BlockLength::max(u32::try_from(serai_abi::Block::SIZE_LIMIT).unwrap())
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
