use core::future::Future;

use bitcoin_serai::bitcoin::ScriptBuf;

use serai_db::{Get, DbTxn, Db};

use primitives::task::ContinuallyRan;
use scanner::ScannerFeed;

use crate::{db, rpc::Rpc, hash_bytes};

pub(crate) fn script_pubkey_for_on_chain_output(
  getter: &impl Get,
  txid: [u8; 32],
  vout: u32,
) -> ScriptBuf {
  // We index every single output on the blockchain, so this shouldn't be possible
  ScriptBuf::from_bytes(
    db::ScriptPubKey::get(getter, txid, vout)
      .expect("requested script public key for unknown output"),
  )
}

/*
  We want to be able to return received outputs. We do that by iterating over the inputs to find an
  address format we recognize, then setting that address as the address to return to.

  Since inputs only contain the script signatures, yet addresses are for script public keys, we
  need to pull up the output spent by an input and read the script public key from that. While we
  could use `txindex=1`, and an asynchronous call to the Bitcoin node, we:

  1) Can maintain a much smaller index ourselves
  2) Don't want the asynchronous call (which would require the flow be async, allowed to
     potentially error, and more latent)
  3) Don't want to risk Bitcoin's `txindex` corruptions (frequently observed on testnet)

  This task builds that index.
*/
pub(crate) struct TxIndexTask<D: Db>(pub(crate) Rpc<D>);

impl<D: Db> ContinuallyRan for TxIndexTask<D> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let latest_block_number = self
        .0
        .rpc
        .get_latest_block_number()
        .await
        .map_err(|e| format!("couldn't fetch latest block number: {e:?}"))?;
      let latest_block_number = u64::try_from(latest_block_number).unwrap();
      // `CONFIRMATIONS - 1` as any on-chain block inherently has one confirmation (itself)
      let finalized_block_number =
        latest_block_number.checked_sub(Rpc::<D>::CONFIRMATIONS - 1).ok_or(format!(
          "blockchain only just started and doesn't have {} blocks yet",
          Rpc::<D>::CONFIRMATIONS
        ))?;

      /*
        `finalized_block_number` is the latest block number minus confirmations. The blockchain may
        undetectably re-organize though, as while the scanner will maintain an index of finalized
        blocks and panics on reorganization, this runs prior to the scanner and that index.

        A reorganization of `CONFIRMATIONS` blocks is still an invariant. Even if that occurs, this
        saves the script public keys *by the transaction hash an output index*. Accordingly, it
        isn't invalidated on reorganization. The only risk would be if the new chain reorganized to
        include a transaction to Serai which we didn't index the parents of. If that happens, we'll
        panic when we scan the transaction, causing the invariant to be detected.
      */

      let finalized_block_number_in_db = db::LatestBlockToYieldAsFinalized::get(&self.0.db);
      let next_block = finalized_block_number_in_db.map_or(0, |block| block + 1);

      let mut iterated = false;
      for b in next_block ..= finalized_block_number {
        iterated = true;

        // Fetch the block
        let block_hash = self
          .0
          .rpc
          .get_block_hash(b.try_into().unwrap())
          .await
          .map_err(|e| format!("couldn't fetch block hash for block {b}: {e:?}"))?;
        let block = self
          .0
          .rpc
          .get_block(&block_hash)
          .await
          .map_err(|e| format!("couldn't fetch block {b}: {e:?}"))?;

        let mut txn = self.0.db.txn();

        for tx in &block.txdata {
          let txid = hash_bytes(tx.compute_txid().to_raw_hash());
          for (o, output) in tx.output.iter().enumerate() {
            let o = u32::try_from(o).unwrap();
            // Set the script public key for this transaction
            db::ScriptPubKey::set(&mut txn, txid, o, &output.script_pubkey.clone().into_bytes());
          }
        }

        db::LatestBlockToYieldAsFinalized::set(&mut txn, &b);
        txn.commit();
      }
      Ok(iterated)
    }
  }
}
