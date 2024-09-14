#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

use monero_simple_request_rpc::SimpleRequestRpc;

mod primitives;
pub(crate) use crate::primitives::*;

mod key_gen;
use crate::key_gen::KeyGenParams;
mod rpc;
use rpc::Rpc;
mod scheduler;
use scheduler::{Planner, Scheduler};

#[tokio::main]
async fn main() {
  let db = bin::init();
  let feed = Rpc {
    rpc: loop {
      match SimpleRequestRpc::new(bin::url()).await {
        Ok(rpc) => break rpc,
        Err(e) => {
          log::error!("couldn't connect to the Monero node: {e:?}");
          tokio::time::sleep(core::time::Duration::from_secs(5)).await;
        }
      }
    },
  };

  bin::main_loop::<_, KeyGenParams, _>(
    db,
    feed.clone(),
    Scheduler::new(Planner(feed.clone())),
    feed,
  )
  .await;
}

/*
#[async_trait]
impl TransactionTrait<Monero> for Transaction {
  #[cfg(test)]
  async fn fee(&self, _: &Monero) -> u64 {
    match self {
      Transaction::V1 { .. } => panic!("v1 TX in test-only function"),
      Transaction::V2 { ref proofs, .. } => proofs.as_ref().unwrap().base.fee,
    }
  }
}

impl Monero {
  async fn median_fee(&self, block: &Block) -> Result<FeeRate, NetworkError> {
    let mut fees = vec![];
    for tx_hash in &block.transactions {
      let tx =
        self.rpc.get_transaction(*tx_hash).await.map_err(|_| NetworkError::ConnectionError)?;
      // Only consider fees from RCT transactions, else the fee property read wouldn't be accurate
      let fee = match &tx {
        Transaction::V2 { proofs: Some(proofs), .. } => proofs.base.fee,
        _ => continue,
      };
      fees.push(fee / u64::try_from(tx.weight()).unwrap());
    }
    fees.sort();
    let fee = fees.get(fees.len() / 2).copied().unwrap_or(0);

    // TODO: Set a sane minimum fee
    const MINIMUM_FEE: u64 = 1_500_000;
    Ok(FeeRate::new(fee.max(MINIMUM_FEE), 10000).unwrap())
  }

  #[cfg(test)]
  fn test_view_pair() -> ViewPair {
    ViewPair::new(*EdwardsPoint::generator(), Zeroizing::new(Scalar::ONE.0)).unwrap()
  }

  #[cfg(test)]
  fn test_scanner() -> Scanner {
    Scanner::new(Self::test_view_pair())
  }

  #[cfg(test)]
  fn test_address() -> Address {
    Address::new(Self::test_view_pair().legacy_address(MoneroNetwork::Mainnet)).unwrap()
  }
}

#[async_trait]
impl Network for Monero {
  #[cfg(test)]
  async fn get_block_number(&self, id: &[u8; 32]) -> usize {
    self.rpc.get_block(*id).await.unwrap().number().unwrap()
  }

  #[cfg(test)]
  async fn get_transaction_by_eventuality(
    &self,
    block: usize,
    eventuality: &Eventuality,
  ) -> Transaction {
    let block = self.rpc.get_block_by_number(block).await.unwrap();
    for tx in &block.transactions {
      let tx = self.rpc.get_transaction(*tx).await.unwrap();
      if eventuality.matches(&tx.clone().into()) {
        return tx;
      }
    }
    panic!("block didn't have a transaction for this eventuality")
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    // https://github.com/serai-dex/serai/issues/198
    sleep(std::time::Duration::from_millis(100)).await;
    self.rpc.generate_blocks(&Self::test_address().into(), 1).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Address) -> Block {
    use zeroize::Zeroizing;
    use rand_core::{RngCore, OsRng};
    use monero_wallet::rpc::FeePriority;

    let new_block = self.get_latest_block_number().await.unwrap() + 1;
    for _ in 0 .. 80 {
      self.mine_block().await;
    }

    let new_block = self.rpc.get_block_by_number(new_block).await.unwrap();
    let mut outputs = Self::test_scanner()
      .scan(self.rpc.get_scannable_block(new_block.clone()).await.unwrap())
      .unwrap()
      .ignore_additional_timelock();
    let output = outputs.swap_remove(0);

    let amount = output.commitment().amount;
    // The dust should always be sufficient for the fee
    let fee = Monero::DUST;

    let rct_type = match new_block.header.hardfork_version {
      14 => RctType::ClsagBulletproof,
      15 | 16 => RctType::ClsagBulletproofPlus,
      _ => panic!("Monero hard forked and the processor wasn't updated for it"),
    };

    let output = OutputWithDecoys::fingerprintable_deterministic_new(
      &mut OsRng,
      &self.rpc,
      match rct_type {
        RctType::ClsagBulletproof => 11,
        RctType::ClsagBulletproofPlus => 16,
        _ => panic!("selecting decoys for an unsupported RctType"),
      },
      self.rpc.get_height().await.unwrap(),
      output,
    )
    .await
    .unwrap();

    let mut outgoing_view_key = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(outgoing_view_key.as_mut());
    let tx = MSignableTransaction::new(
      rct_type,
      outgoing_view_key,
      vec![output],
      vec![(address.into(), amount - fee)],
      Change::fingerprintable(Some(Self::test_address().into())),
      vec![],
      self.rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
    )
    .unwrap()
    .sign(&mut OsRng, &Zeroizing::new(Scalar::ONE.0))
    .unwrap();

    let block = self.get_latest_block_number().await.unwrap() + 1;
    self.rpc.publish_transaction(&tx).await.unwrap();
    for _ in 0 .. 10 {
      self.mine_block().await;
    }
    self.get_block(block).await.unwrap()
  }
}
*/
