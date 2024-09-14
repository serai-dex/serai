use core::{
  future::Future,
  ops::{Bound, RangeBounds},
};

use curve25519_dalek::{
  scalar::Scalar,
  edwards::{CompressedEdwardsY, EdwardsPoint},
};
use monero_wallet::{
  DEFAULT_LOCK_WINDOW,
  primitives::Commitment,
  transaction::{Timelock, Input, Pruned, Transaction},
  rpc::{OutputInformation, RpcError, Rpc as MRpcTrait, DecoyRpc},
};

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, Db, create_db};

use primitives::task::ContinuallyRan;
use scanner::ScannerFeed;

use crate::Rpc;

#[derive(BorshSerialize, BorshDeserialize)]
struct EncodableOutputInformation {
  height: u64,
  timelocked: bool,
  key: [u8; 32],
  commitment: [u8; 32],
}

create_db! {
  MoneroProcessorDecoys {
    NextToIndexBlock: () -> u64,
    PriorIndexedBlock: () -> [u8; 32],
    DistributionStartBlock: () -> u64,
    Distribution: () -> Vec<u64>,
    Out: (index: u64) -> EncodableOutputInformation,
  }
}

/*
  We want to be able to select decoys when planning transactions, but planning transactions is a
  synchronous process. We store the decoys to a local database and have our database implement
  `DecoyRpc` to achieve synchronous decoy selection.

  This is only needed as the transactions we sign must have decoys decided and agreed upon. With
  FCMP++s, we'll be able to sign transactions without the membership proof, letting any signer
  prove for membership after the fact (with their local views). Until then, this task remains.
*/
pub(crate) struct DecoysTask<D: Db> {
  pub(crate) rpc: Rpc<D>,
  pub(crate) current_distribution: Vec<u64>,
}

impl<D: Db> ContinuallyRan for DecoysTask<D> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let finalized_block_number = self
        .rpc
        .rpc
        .get_height()
        .await
        .map_err(|e| format!("couldn't fetch latest block number: {e:?}"))?
        .checked_sub(Rpc::<D>::CONFIRMATIONS.try_into().unwrap())
        .ok_or(format!(
          "blockchain only just started and doesn't have {} blocks yet",
          Rpc::<D>::CONFIRMATIONS
        ))?;

      if NextToIndexBlock::get(&self.rpc.db).is_none() {
        let distribution = self
          .rpc
          .rpc
          .get_output_distribution(..= finalized_block_number)
          .await
          .map_err(|e| format!("failed to get output distribution: {e:?}"))?;
        if distribution.is_empty() {
          Err("distribution was empty".to_string())?;
        }

        let distribution_start_block = finalized_block_number - (distribution.len() - 1);
        // There may have been a reorg between the time of getting the distribution and the time of
        // getting this block. This is an invariant and assumed not to have happened in the split
        // second it's possible.
        let block = self
          .rpc
          .rpc
          .get_block_by_number(distribution_start_block)
          .await
          .map_err(|e| format!("failed to get the start block for the distribution: {e:?}"))?;

        let mut txn = self.rpc.db.txn();
        NextToIndexBlock::set(&mut txn, &distribution_start_block.try_into().unwrap());
        PriorIndexedBlock::set(&mut txn, &block.header.previous);
        DistributionStartBlock::set(&mut txn, &u64::try_from(distribution_start_block).unwrap());
        txn.commit();
      }

      let next_to_index_block =
        usize::try_from(NextToIndexBlock::get(&self.rpc.db).unwrap()).unwrap();
      if next_to_index_block >= finalized_block_number {
        return Ok(false);
      }

      for b in next_to_index_block ..= finalized_block_number {
        // Fetch the block
        let block = self
          .rpc
          .rpc
          .get_block_by_number(b)
          .await
          .map_err(|e| format!("decoys task failed to fetch block: {e:?}"))?;
        let prior = PriorIndexedBlock::get(&self.rpc.db).unwrap();
        if block.header.previous != prior {
          panic!(
            "decoys task detected reorg: expected {}, found {}",
            hex::encode(prior),
            hex::encode(block.header.previous)
          );
        }

        // Fetch the transactions in the block
        let transactions = self
          .rpc
          .rpc
          .get_pruned_transactions(&block.transactions)
          .await
          .map_err(|e| format!("failed to get the pruned transactions within a block: {e:?}"))?;

        fn outputs(
          list: &mut Vec<EncodableOutputInformation>,
          block_number: u64,
          tx: Transaction<Pruned>,
        ) {
          match tx {
            Transaction::V1 { .. } => {}
            Transaction::V2 { prefix, proofs } => {
              for (i, output) in prefix.outputs.into_iter().enumerate() {
                list.push(EncodableOutputInformation {
                  // This is correct per the documentation on OutputInformation, which this maps to
                  height: block_number,
                  timelocked: prefix.additional_timelock != Timelock::None,
                  key: output.key.to_bytes(),
                  commitment: if matches!(
                    prefix.inputs.first().expect("Monero transaction had no inputs"),
                    Input::Gen(_)
                  ) {
                    Commitment::new(
                      Scalar::ONE,
                      output.amount.expect("miner transaction outputs didn't have amounts set"),
                    )
                    .calculate()
                    .compress()
                    .to_bytes()
                  } else {
                    proofs
                      .as_ref()
                      .expect("non-miner V2 transaction didn't have proofs")
                      .base
                      .commitments
                      .get(i)
                      .expect("amount of commitments didn't match amount of outputs")
                      .compress()
                      .to_bytes()
                  },
                });
              }
            }
          }
        }

        let block_hash = block.hash();

        let b = u64::try_from(b).unwrap();
        let mut encodable = Vec::with_capacity(2 * (1 + block.transactions.len()));
        outputs(&mut encodable, b, block.miner_transaction.into());
        for transaction in transactions {
          outputs(&mut encodable, b, transaction);
        }

        let existing_outputs = self.current_distribution.last().copied().unwrap_or(0);
        let now_outputs = existing_outputs + u64::try_from(encodable.len()).unwrap();
        self.current_distribution.push(now_outputs);

        let mut txn = self.rpc.db.txn();
        NextToIndexBlock::set(&mut txn, &(b + 1));
        PriorIndexedBlock::set(&mut txn, &block_hash);
        // TODO: Don't write the entire 10 MB distribution to the DB every two minutes
        Distribution::set(&mut txn, &self.current_distribution);
        for (b, out) in (existing_outputs .. now_outputs).zip(encodable) {
          Out::set(&mut txn, b, &out);
        }
        txn.commit();
      }
      Ok(true)
    }
  }
}

// TODO: Cache the distribution in a static
pub(crate) struct Decoys<'a, G: Get>(&'a G);
impl<'a, G: Sync + Get> DecoyRpc for Decoys<'a, G> {
  #[rustfmt::skip]
  fn get_output_distribution_end_height(
    &self,
  ) -> impl Send + Future<Output = Result<usize, RpcError>> {
    async move {
      Ok(NextToIndexBlock::get(self.0).map_or(0, |b| usize::try_from(b).unwrap() + 1))
    }
  }
  fn get_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
    async move {
      let from = match range.start_bound() {
        Bound::Included(from) => *from,
        Bound::Excluded(from) => from.checked_add(1).ok_or_else(|| {
          RpcError::InternalError("range's from wasn't representable".to_string())
        })?,
        Bound::Unbounded => 0,
      };
      let to = match range.end_bound() {
        Bound::Included(to) => *to,
        Bound::Excluded(to) => to
          .checked_sub(1)
          .ok_or_else(|| RpcError::InternalError("range's to wasn't representable".to_string()))?,
        Bound::Unbounded => {
          panic!("requested distribution till latest block, which is non-deterministic")
        }
      };
      if from > to {
        Err(RpcError::InternalError(format!(
          "malformed range: inclusive start {from}, inclusive end {to}"
        )))?;
      }

      let distribution_start_block = usize::try_from(
        DistributionStartBlock::get(self.0).expect("never populated the distribution start block"),
      )
      .unwrap();
      let len_of_distribution_until_to =
        to.checked_sub(distribution_start_block).ok_or_else(|| {
          RpcError::InternalError(
            "requested distribution until a block when the distribution had yet to start"
              .to_string(),
          )
        })? +
          1;
      let distribution = Distribution::get(self.0).expect("never populated the distribution");
      assert!(
        distribution.len() >= len_of_distribution_until_to,
        "requested distribution until block we have yet to index"
      );
      Ok(
        distribution[from.saturating_sub(distribution_start_block) .. len_of_distribution_until_to]
          .to_vec(),
      )
    }
  }
  fn get_outs(
    &self,
    _indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<OutputInformation>, RpcError>> {
    async move { unimplemented!("get_outs is unused") }
  }
  fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
    fingerprintable_deterministic: bool,
  ) -> impl Send + Future<Output = Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError>> {
    assert!(fingerprintable_deterministic, "processor wasn't using deterministic output selection");
    async move {
      let mut res = vec![];
      for index in indexes {
        let out = Out::get(self.0, *index).expect("requested output we didn't index");
        let unlocked = (!out.timelocked) &&
          ((usize::try_from(out.height).unwrap() + DEFAULT_LOCK_WINDOW) <= height);
        res.push(unlocked.then(|| CompressedEdwardsY(out.key).decompress()).flatten().map(|key| {
          [
            key,
            CompressedEdwardsY(out.commitment)
              .decompress()
              .expect("output with invalid commitment"),
          ]
        }));
      }
      Ok(res)
    }
  }
}
