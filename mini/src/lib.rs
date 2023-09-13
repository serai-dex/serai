use std::sync::{Arc as StdArc, RwLock as StdRwLock};

use loom::{
  thread::{self, JoinHandle},
  sync::{Arc, RwLock},
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
}

#[derive(Debug)]
pub struct Serai {
  handle: JoinHandle<()>,
  pub active_keys: Arc<RwLock<Vec<u64>>>,
  pub mempool_batches: Arc<RwLock<Vec<Batch>>>,
  pub events: StdArc<StdRwLock<Vec<Event>>>,
}

impl Serai {
  #[allow(clippy::new_without_default)]
  pub fn new(ticks: usize, mut queued_key: bool) -> Serai {
    let active_keys = Arc::new(RwLock::new(vec![0]));
    let mempool_batches = Arc::new(RwLock::new(vec![]));
    let events = StdArc::new(StdRwLock::new(vec![]));

    let handle = thread::spawn({
      let events = events.clone();
      let active_keys = active_keys.clone();
      let mempool_batches = mempool_batches.clone();
      move || {
        for _ in 0 .. ticks {
          let mut batches = mempool_batches.write().unwrap();
          if !batches.is_empty() {
            let batch = batches.remove(0);
            events.write().unwrap().push(Event::IncludedBatch(batch));
            // Activate keys after the next received block
            if queued_key {
              let mut active_keys = active_keys.write().unwrap();
              let len = active_keys.len().try_into().unwrap();
              active_keys.push(len);
            }
            queued_key = false;
          }
        }
      }
    });

    Serai { handle, mempool_batches, active_keys, events }
  }

  pub fn join(self) -> Vec<Event> {
    self.handle.join().unwrap();

    self.events.read().unwrap().clone()
  }
}

#[derive(Debug)]
pub struct Processor {
  handle: JoinHandle<Serai>,
}

impl Processor {
  pub fn new(serai: Serai, batches: u64) -> Processor {
    let handle = thread::spawn(move || {
      for b in 0 .. batches {
        serai
          .mempool_batches
          .write()
          .unwrap()
          .push(Batch { block: b, keys: serai.active_keys.read().unwrap().clone() });
      }
      serai
    });
    Processor { handle }
  }

  pub fn join(self) -> Serai {
    self.handle.join().unwrap()
  }
}
