use std::sync::{Arc as StdArc, RwLock as StdRwLock};

use loom::{
  thread::{self, JoinHandle},
  sync::{Arc, RwLock, mpsc},
};

#[cfg(test)]
mod tests;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Batch {
  block: u64,
  keys: Vec<u64>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Event {
  IncludedBatch(Batch),
  // Allows if let else on this without clippy believing it's redundant
  __Ignore,
}

// The amount of blocks to scan after we publish a batch, before confirming the batch was
// included.
// Prevents race conditions on rotation regarding when the new keys activate.
const BATCH_FTL: u64 = 3;

#[derive(Debug)]
pub struct Serai {
  handle: JoinHandle<()>,
  remaining_ticks: Arc<RwLock<usize>>,
  // Activation block, ID
  pub active_keys: Arc<RwLock<Vec<(u64, u64)>>>,
  pub mempool_batches: Arc<RwLock<Vec<Batch>>>,
  pub events: mpsc::Receiver<Event>,
  all_events_unsafe: StdArc<StdRwLock<Vec<Event>>>,
}

impl Serai {
  #[allow(clippy::new_without_default)]
  pub fn new(ticks: usize, mut queued_key: bool) -> Serai {
    let remaining_ticks = Arc::new(RwLock::new(ticks));

    let active_keys = Arc::new(RwLock::new(vec![(0, 0)]));
    let mempool_batches = Arc::new(RwLock::new(vec![]));
    let (events_sender, events_receiver) = mpsc::channel();
    let all_events_unsafe = StdArc::new(StdRwLock::new(vec![]));

    let handle = thread::spawn({
      let remaining_ticks = remaining_ticks.clone();

      let active_keys = active_keys.clone();
      let mempool_batches = mempool_batches.clone();
      let all_events_unsafe = all_events_unsafe.clone();

      move || {
        while {
          let mut remaining_ticks = remaining_ticks.write().unwrap();
          let ticking = *remaining_ticks != 0;
          *remaining_ticks = remaining_ticks.saturating_sub(1);
          ticking
        } {
          let mut batches = mempool_batches.write().unwrap();
          if !batches.is_empty() {
            let batch: Batch = batches.remove(0);

            // Activate keys after the FTL
            if queued_key {
              let mut active_keys = active_keys.write().unwrap();
              let len = active_keys.len().try_into().unwrap();
              // TODO: active_keys is under Serai, yet the processor is the one actually with the
              // context on when it activates
              // This should be re-modeled as an event
              active_keys.push((batch.block + BATCH_FTL, len));
            }
            queued_key = false;

            let event = Event::IncludedBatch(batch);
            events_sender.send(event.clone()).unwrap();
            all_events_unsafe.write().unwrap().push(event);
          }
        }
      }
    });

    Serai {
      handle,
      remaining_ticks,
      mempool_batches,
      active_keys,
      events: events_receiver,
      all_events_unsafe,
    }
  }

  pub fn exhausted(&self) -> bool {
    *self.remaining_ticks.read().unwrap() == 0
  }

  pub fn join(self) -> Vec<Event> {
    self.handle.join().unwrap();

    self.all_events_unsafe.read().unwrap().clone()
  }
}

#[derive(Debug)]
pub struct Processor {
  handle: JoinHandle<Serai>,
}

impl Processor {
  pub fn new(serai: Serai, blocks: u64) -> Processor {
    let handle = thread::spawn(move || {
      let mut last_finalized_block = 0;
      for b in 0 .. blocks {
        // If this block is too far ahead of Serai's last block, wait for Serai to process
        // Note this wait only has to occur if we have a Batch which has yet to be included
        // mini just publishes a Batch for every Block at this point in time, meaning it always has
        // to wait
        while b >= (last_finalized_block + BATCH_FTL) {
          if serai.exhausted() {
            return serai;
          }
          let Ok(event) = serai.events.recv() else { return serai };
          if let Event::IncludedBatch(Batch { block, .. }) = event {
            last_finalized_block = block;
          }
        }
        serai.mempool_batches.write().unwrap().push(Batch {
          block: b,
          keys: serai
            .active_keys
            .read()
            .unwrap()
            .iter()
            .filter_map(|(activation_block, id)| Some(*id).filter(|_| b >= *activation_block))
            .collect(),
        });
      }
      serai
    });
    Processor { handle }
  }

  pub fn join(self) -> Serai {
    self.handle.join().unwrap()
  }
}
