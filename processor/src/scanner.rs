use core::time::Duration;

use async_trait::async_trait;

use tokio::{sync::mpsc, time::timeout};

use frost::{curve::Ciphersuite, ThresholdKeys};

use crate::coin::{Block, Coin};

/// A block number from the Substrate chain, considered a canonical orderer by all instances.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CanonicalNumber(u64);

// TODO: Either move everything over or get rid of this
/// A block number of some arbitrary chain, later-affirmed by the Substrate chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainNumber(u64);

/// Orders for the scanner.
#[derive(Clone, Debug)]
pub enum ScannerOrder<C: Ciphersuite> {
  /// Update the keys being scanned for.
  /// If no keys have been prior set, these will become the keys with no further actions.
  /// If keys have been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old keys will eventually stop being scanned for, leaving just the
  /// updated-to keys.
  UpdateKeys { activation_number: ChainNumber, keys: ThresholdKeys<C> },
}

#[derive(Clone, Debug)]
pub enum ScannerEvent<C: Coin> {
  // Needs to be reported to Substrate
  Block(ChainNumber, <C::Block as Block>::Id),

  // Needs to be processed/sent up to Substrate
  ExternalOutput(C::Output),

  // Given a known output set, and a known series of outbound transactions, we should be able to
  // form a completely deterministic schedule S. The issue is when S has TXs which spend prior TXs
  // in S (which is needed for our logarithmic scheduling). In order to have the descendant TX, say
  // S[1], build off S[0], we need to observe when S[0] is included on-chain.
  //
  // We cannot.
  //
  // Monero (and other privacy coins) do not expose their UTXO graphs. Even if we know how to
  // create S[0], and the actual payment info behind it, we cannot observe it on the blockchain
  // unless we participated in creating it. Locking the entire schedule, when we cannot sign for
  // the entire schedule at once, to a single signing set isn't feasible.
  //
  // While any member of the active signing set can provide data enabling other signers to
  // participate, it's several KB of data which we then have to code communication for.
  // The other option is to simply not observe S[0]. Instead, observe a TX with an identical output
  // to the one in S[0] we intended to use for S[1]. It's either from S[0], or Eve, a malicious
  // actor, has sent us a forged TX which is... equally as usable? so who cares?
  //
  // The only issue is if we have multiple outputs on-chain with identical amounts and purposes.
  // Accordingly, when the scheduler makes a plan for when a specific output is available, it
  // shouldn't write that plan. It should *push* that plan to a queue of plans to perform when
  // instances of that output occur.
  BranchOutput(C::Output),

  // Should be added to the available UTXO pool with no further action
  ChangeOutput(C::Output),
}

pub type ScannerOrderChannel<C> = mpsc::UnboundedSender<ScannerOrder<C>>;
pub type ScannerEventChannel<C> = mpsc::UnboundedReceiver<ScannerEvent<C>>;

#[async_trait]
pub trait ScannerDb<C: Ciphersuite>: Send + Sync {
  async fn get_latest_scanned_block(&self, key: C::G) -> ChainNumber;
  async fn save_scanned_block(&mut self, key: C::G, block: ChainNumber);
}

#[derive(Debug)]
pub struct Scanner<C: Coin, D: ScannerDb<C::Curve>> {
  coin: C,
  db: D,
  keys: Vec<ThresholdKeys<C::Curve>>,

  orders: mpsc::UnboundedReceiver<ScannerOrder<C::Curve>>,
  events: mpsc::UnboundedSender<ScannerEvent<C>>,
}

#[derive(Debug)]
pub struct ScannerHandle<C: Coin> {
  orders: ScannerOrderChannel<C::Curve>,
  events: ScannerEventChannel<C>,
}

impl<C: Coin + 'static, D: ScannerDb<C::Curve> + 'static> Scanner<C, D> {
  #[allow(clippy::new_ret_no_self)]
  fn new(coin: C, db: D) -> ScannerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      Scanner { coin, db, keys: vec![], orders: orders_recv, events: events_send }.run(),
    );
    ScannerHandle { orders: orders_send, events: events_recv }
  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(mut self) {
    loop {
      // Scan new blocks
      {
        let latest = match self.coin.get_latest_block_number().await {
          Ok(latest) => latest,
          Err(_) => {
            log::warn!("Couldn't get {}'s latest block number", C::ID);
            break;
          }
        };

        for key in &self.keys {
          let latest_scanned =
            usize::try_from(self.db.get_latest_scanned_block(key.group_key()).await.0).unwrap();
          for i in (latest_scanned + 1) ..= latest {
            // TODO: Check for key deprecation

            let block = match self.coin.get_block(i).await {
              Ok(block) => block,
              Err(_) => {
                log::warn!("Couldn't get {} block {i}", C::ID);
                break;
              }
            };

            let outputs = match self.coin.get_outputs(&block, key.group_key()).await {
              Ok(outputs) => outputs,
              Err(_) => {
                log::warn!("Couldn't scan {} block {i}", C::ID);
                break;
              }
            };

            // TODO: Process outputs
            /*
            emit ScannerEvent::Block(i, block.id());
            for output in outputs.drain(..) {
              match output.kind() {
                OutputType::External => emit ScannerEvent::ExternalOutput,
                OutputType::Branch => emit ScannerEvent::BranchOutput,
                OutputType::Change => emit ScannerEvent::ChangeOutput,
              }
            }
            */

            self.db.save_scanned_block(key.group_key(), ChainNumber(i.try_into().unwrap())).await;
          }
        }
      }

      // Handle any new orders
      if let Ok(order) = timeout(Duration::from_secs(1), self.orders.recv()).await {
        todo!();
      }
    }
  }
}
