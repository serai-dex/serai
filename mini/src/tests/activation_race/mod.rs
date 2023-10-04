use std::{
  collections::HashSet,
  sync::{Arc as StdArc, RwLock as StdRwLock},
};

use crate::*;

#[test]
fn activation_race() {
  #[derive(Debug)]
  struct EagerProcessor {
    handle: JoinHandle<Serai>,
  }

  impl EagerProcessor {
    fn new(serai: Serai, batches: u64) -> EagerProcessor {
      let handle = thread::spawn(move || {
        for b in 0 .. batches {
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
      EagerProcessor { handle }
    }

    fn join(self) -> Serai {
      self.handle.join().unwrap()
    }
  }

  let results = StdArc::new(StdRwLock::new(HashSet::new()));

  loom::model({
    let results = results.clone();
    move || {
      let serai = Serai::new(4, true);
      let processor = EagerProcessor::new(serai, 4);
      let serai = processor.join();
      let events = serai.join();

      results.write().unwrap().insert(events);
    }
  });

  let results: HashSet<_> = results.read().unwrap().clone();
  assert_eq!(results.len(), 6);
  for result in results {
    for (b, batch) in result.into_iter().enumerate() {
      if b < 3 {
        assert_eq!(
          batch,
          Event::IncludedBatch(Batch { block: b.try_into().unwrap(), keys: vec![0] })
        );
      } else {
        let Event::IncludedBatch(batch) = batch else { panic!("unexpected event") };
        assert_eq!(batch.block, b.try_into().unwrap());
        assert!((batch.keys == vec![0]) || (batch.keys == vec![0, 1]));
      }
    }
  }
}

#[test]
fn sequential_solves_activation_race() {
  #[derive(Debug)]
  struct DelayedProcessor {
    handle: JoinHandle<Serai>,
  }

  impl DelayedProcessor {
    fn new(serai: Serai, batches: u64) -> DelayedProcessor {
      let handle = thread::spawn(move || {
        for b in 0 .. batches {
          let batch = {
            let mut batches = serai.mempool_batches.write().unwrap();
            let batch = Batch {
              block: b,
              keys: serai
                .active_keys
                .read()
                .unwrap()
                .iter()
                .filter_map(|(activation_block, id)| Some(*id).filter(|_| b >= *activation_block))
                .collect(),
            };
            batches.push(batch.clone());
            batch
          };

          while (!serai.exhausted()) &&
            (serai.events.recv().unwrap() != Event::IncludedBatch(batch.clone()))
          {
            loom::thread::yield_now();
          }
        }
        serai
      });
      DelayedProcessor { handle }
    }

    fn join(self) -> Serai {
      self.handle.join().unwrap()
    }
  }

  let results = StdArc::new(StdRwLock::new(HashSet::new()));

  loom::model({
    let results = results.clone();
    move || {
      let serai = Serai::new(4, true);
      let processor = DelayedProcessor::new(serai, 4);
      let serai = processor.join();
      let events = serai.join();

      results.write().unwrap().insert(events);
    }
  });

  let results: HashSet<_> = results.read().unwrap().clone();
  assert_eq!(results.len(), 5);
  for result in results {
    for (b, batch) in result.into_iter().enumerate() {
      assert_eq!(
        batch,
        Event::IncludedBatch(Batch {
          block: b.try_into().unwrap(),
          keys: if b < 3 { vec![0] } else { vec![0, 1] }
        }),
      );
    }
  }
}

#[test]
fn ftl_solves_activation_race() {
  let results = StdArc::new(StdRwLock::new(HashSet::new()));

  loom::model({
    let results = results.clone();
    move || {
      let serai = Serai::new(4, true);
      // Uses Processor since this Processor has this algorithm implemented
      let processor = Processor::new(serai, 4);
      let serai = processor.join();
      let events = serai.join();

      results.write().unwrap().insert(events);
    }
  });

  let results: HashSet<_> = results.read().unwrap().clone();
  assert_eq!(results.len(), 5);
  for result in results {
    for (b, batch) in result.into_iter().enumerate() {
      assert_eq!(
        batch,
        Event::IncludedBatch(Batch {
          block: b.try_into().unwrap(),
          keys: if b < 3 { vec![0] } else { vec![0, 1] }
        }),
      );
    }
  }
}
