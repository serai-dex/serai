use bitcoin_serai::rpc::{RpcError, Rpc as BRpc};

use serai_client::primitives::{NetworkId, Coin, Amount};

use serai_db::Db;
use scanner::ScannerFeed;
use signers::TransactionPublisher;

use crate::{
  db,
  transaction::Transaction,
  block::{BlockHeader, Block},
};

#[derive(Clone)]
pub(crate) struct Rpc<D: Db> {
  pub(crate) db: D,
  pub(crate) rpc: BRpc,
}

#[async_trait::async_trait]
impl<D: Db> ScannerFeed for Rpc<D> {
  const NETWORK: NetworkId = NetworkId::Bitcoin;
  const CONFIRMATIONS: u64 = 6;
  const WINDOW_LENGTH: u64 = 6;

  const TEN_MINUTES: u64 = 1;

  type Block = Block<D>;

  type EphemeralError = RpcError;

  async fn latest_finalized_block_number(&self) -> Result<u64, Self::EphemeralError> {
    db::LatestBlockToYieldAsFinalized::get(&self.db).ok_or(RpcError::ConnectionError)
  }

  async fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError> {
    Ok(BlockHeader(
      self.rpc.get_block(&self.rpc.get_block_hash(number.try_into().unwrap()).await?).await?.header,
    ))
  }

  async fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> Result<Self::Block, Self::EphemeralError> {
    Ok(Block(
      self.db.clone(),
      self.rpc.get_block(&self.rpc.get_block_hash(number.try_into().unwrap()).await?).await?,
    ))
  }

  fn dust(coin: Coin) -> Amount {
    assert_eq!(coin, Coin::Bitcoin);

    /*
      A Taproot input is:
      - 36 bytes for the OutPoint
      - 0 bytes for the script (+1 byte for the length)
      - 4 bytes for the sequence
      Per https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format

      There's also:
      - 1 byte for the witness length
      - 1 byte for the signature length
      - 64 bytes for the signature
      which have the SegWit discount.

      (4 * (36 + 1 + 4)) + (1 + 1 + 64) = 164 + 66 = 230 weight units
      230 ceil div 4 = 57 vbytes

      Bitcoin defines multiple minimum feerate constants *per kilo-vbyte*. Currently, these are:
      - 1000 sat/kilo-vbyte for a transaction to be relayed
      - Each output's value must exceed the fee of the TX spending it at 3000 sat/kilo-vbyte
      The DUST constant needs to be determined by the latter.
      Since these are solely relay rules, and may be raised, we require all outputs be spendable
      under a 5000 sat/kilo-vbyte fee rate.

      5000 sat/kilo-vbyte = 5 sat/vbyte
      5 * 57 = 285 sats/spent-output

      Even if an output took 100 bytes (it should be just ~29-43), taking 400 weight units, adding
      100 vbytes, tripling the transaction size, then the sats/tx would be < 1000.

      Increase by an order of magnitude, in order to ensure this is actually worth our time, and we
      get 10,000 satoshis. This is $5 if 1 BTC = 50,000 USD.
    */
    Amount(10_000)
  }

  async fn cost_to_aggregate(
    &self,
    coin: Coin,
    _reference_block: &Self::Block,
  ) -> Result<Amount, Self::EphemeralError> {
    assert_eq!(coin, Coin::Bitcoin);
    // TODO
    Ok(Amount(0))
  }
}

#[async_trait::async_trait]
impl<D: Db> TransactionPublisher<Transaction> for Rpc<D> {
  type EphemeralError = RpcError;

  async fn publish(&self, tx: Transaction) -> Result<(), Self::EphemeralError> {
    self.rpc.send_raw_transaction(&tx.0).await.map(|_| ())
  }
}
