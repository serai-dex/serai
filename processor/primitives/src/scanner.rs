use core::{future::Future, fmt::Debug};

use serai_primitives::{
  network_id::ExternalNetworkId, coin::ExternalCoin, balance::Amount,
};

use crate::Block;

/// A feed usable to scan a blockchain.
///
/// This defines the primitive types used, along with various getters necessary for indexing.
pub trait ScannerFeed: 'static + Send + Sync + Clone {
  /// The ID of the network being scanned for.
  const NETWORK: ExternalNetworkId;

  /// The amount of confirmations a block must have to be considered finalized.
  ///
  /// This value must be at least `1`.
  // This is distinct from `WINDOW_LENGTH` as it's only used for determining the lifetime of the
  // key. The key switches to various stages of its lifetime depending on when user transactions
  // will hit the Serai network (relative to the time they're made) and when outputs created by
  // Serai become available again. If we set a long WINDOW_LENGTH, say two hours, that doesn't mean
  // we expect user transactions made within a few minutes of a new key being declared to only
  // appear in finalized blocks two hours later.
  const CONFIRMATIONS: u64;

  /// The amount of blocks to process in parallel.
  ///
  /// This must be at least `1`. This value MUST be at least the worst-case latency to publish a
  /// Batch for a block divided by the expected block time. Setting this value too low will risk a
  /// backlog forming. Setting this value too high will only delay key rotation and forwarded
  /// outputs.
  // The latency to publish a Batch for a block is the latency of a provided transaction
  // (1 minute), the latency of a signing protocol (1 minute), the latency of Serai to finalize a
  // block (1 minute), and the latency to cosign such a block (5 minutes for the cosign distance
  // plus 1 minute). Accordingly, this should be at least ~30 minutes, ideally 60 minutes.
  const WINDOW_LENGTH: u64;

  /// The amount of blocks which will occur in 10 minutes (approximate).
  ///
  /// This value must be at least `1`.
  const TEN_MINUTES: u64;

  /// The representation of a block for this blockchain.
  ///
  /// A block is defined as a consensus event associated with a set of transactions. It is not
  /// necessary to literally define it as whatever the external network defines as a block. For
  /// external networks which finalize block(s), this block type should be a representation of all
  /// transactions within a finalization event.
  type Block: Block;

  /// An error encountered when fetching data from the blockchain.
  ///
  /// This MUST be an ephemeral error. Retrying fetching data from the blockchain MUST eventually
  /// resolve without manual intervention/changing the arguments.
  type EphemeralError: Debug;

  /// Fetch the number of the latest finalized block.
  ///
  /// The block number is its zero-indexed position within a linear view of the external network's
  /// consensus. The genesis block accordingly has block number 0.
  fn latest_finalized_block_number(
    &self,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>>;

  /// Fetch the timestamp of a block (represented in seconds since the epoch).
  ///
  /// This must be monotonically incrementing. Two blocks may share a timestamp.
  fn time_of_block(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>>;

  /// Fetch a block header by its number.
  ///
  /// This does not check the returned BlockHeader is the header for the block we indexed.
  fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<<Self::Block as Block>::Header, Self::EphemeralError>>;

  /// Fetch a block by its number.
  ///
  /// This does not check the returned Block is the block we indexed.
  fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> impl Send + Future<Output = Result<Self::Block, Self::EphemeralError>>;

  /// Fetch a block by its number.
  ///
  /// Panics if the block requested wasn't indexed.
  fn block_by_number(
    &self,
    number: u64,
    indexed_block_id: &[u8; 32],
  ) -> impl Send + Future<Output = Result<Self::Block, String>> {
    async move {
      let block = match self.unchecked_block_by_number(number).await {
        Ok(block) => block,
        Err(e) => Err(format!("couldn't fetch block {number}: {e:?}"))?,
      };

      // Check the ID of this block is the expected ID
      {
        assert_eq!(
          &block.id(),
          indexed_block_id,
          "finalized chain reorganized from {} to {} at {}",
          hex::encode(indexed_block_id),
          hex::encode(block.id()),
          number,
        );
      }

      Ok(block)
    }
  }

  /// The dust threshold for the specified coin.
  ///
  /// This MUST be constant. Serai MUST NOT create internal outputs worth less than this. This
  /// SHOULD be a value worth handling at a human level.
  fn dust(coin: ExternalCoin) -> Amount;

  /// The cost to aggregate an input as of the specified block.
  ///
  /// This is defined as the transaction fee for a 2-input, 1-output transaction.
  fn cost_to_aggregate(
    &self,
    coin: ExternalCoin,
    reference_block: &Self::Block,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>>;
}
