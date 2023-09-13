use std::{
  collections::HashSet,
  sync::{Arc as StdArc, RwLock as StdRwLock},
};

use crate::*;

#[test]
fn activation_race() {
  let results = StdArc::new(StdRwLock::new(HashSet::new()));

  loom::model({
    let results = results.clone();
    move || {
      let serai = Serai::new(2, true);
      let processor = Processor::new(serai, 2);
      let serai = processor.join();
      let events = serai.join();

      results.write().unwrap().insert(events);
    }
  });

  assert_eq!(
    *results.read().unwrap(),
    HashSet::from([
      vec![],
      vec![Event::IncludedBatch(Batch { block: 0, keys: vec![0] })],
      vec![
        Event::IncludedBatch(Batch { block: 0, keys: vec![0] }),
        Event::IncludedBatch(Batch { block: 1, keys: vec![0] })
      ],
      vec![
        Event::IncludedBatch(Batch { block: 0, keys: vec![0] }),
        Event::IncludedBatch(Batch { block: 1, keys: vec![0, 1] })
      ],
    ])
  );
}
