use substrate_median::*;

use frame_support::{
  Blake2_128Concat, Identity,
  storage::types::{self, ValueQuery, OptionQuery},
};

use rand_core::{RngCore, OsRng};

macro_rules! prefix {
  ($name: ident, $prefix: expr) => {
    struct $name;
    impl frame_support::traits::StorageInstance for $name {
      const STORAGE_PREFIX: &'static str = $prefix;
      fn pallet_prefix() -> &'static str {
        "median"
      }
    }
  };
}
prefix!(PrefixLength, "Length");
prefix!(PrefixStore, "Store");
prefix!(PrefixReverse, "Reverse");
prefix!(PrefixPosition, "Position");
prefix!(PrefixMedian, "Median");

type StorageMapStruct<Prefix, Value, Query> =
  types::StorageMap<Prefix, Blake2_128Concat, (), Value, Query>;
type StorageDoubleMapStruct<Prefix, Key, Value> =
  types::StorageDoubleMap<Prefix, Blake2_128Concat, (), Identity, Key, Value, ValueQuery>;

macro_rules! test {
  ($policy: expr) => {
    struct Test;
    impl MedianStore<(), u32> for Test {
      const POLICY: Policy = $policy;
      type Length = StorageMapStruct<PrefixLength, u64, ValueQuery>;
      type Store =
        StorageDoubleMapStruct<PrefixStore, <u32 as LexicographicEncoding>::Encoding, u64>;
      type ReverseStore = StorageDoubleMapStruct<PrefixReverse, LexicographicReverse<u32>, ()>;
      type Position = StorageMapStruct<PrefixPosition, u64, OptionQuery>;
      type Median = StorageMapStruct<PrefixMedian, u32, OptionQuery>;
    }
  };
}

// This test tests the specific logic when the popped value is the median.
#[test]
fn pop_median() {
  test!(Policy::Greater);

  // Test when we pop to an empty list
  sp_io::TestExternalities::default().execute_with(|| {
    Test::push((), 0);
    assert!(Test::pop((), 0));
    assert_eq!(Test::length(()), 0);
    assert_eq!(Test::median(()), None);

    // This introspects the database, which is fine as a test within this very crate
    assert_eq!(<Test as MedianStore<_, _>>::Length::get(()), 0);
    assert!(<Test as MedianStore<_, _>>::Store::iter().next().is_none());
    assert!(<Test as MedianStore<_, _>>::ReverseStore::iter().next().is_none());
    assert!(<Test as MedianStore<_, _>>::Position::get(()).is_none());
    assert!(<Test as MedianStore<_, _>>::Median::get(()).is_none());
  });

  // Test when we pop such that `Position` is invalidated
  sp_io::TestExternalities::default().execute_with(|| {
    Test::push((), 0);
    Test::push((), 1);
    assert_eq!(Test::length(()), 2);
    assert_eq!(Test::median(()), Some(1));

    assert!(Test::pop((), 1));
    assert_eq!(Test::length(()), 1);
    assert_eq!(Test::median(()), Some(0));
  });

  // Test when we pop a median with multiple presences
  sp_io::TestExternalities::default().execute_with(|| {
    Test::push((), 0);
    Test::push((), 1);
    Test::push((), 1);
    assert_eq!(Test::length(()), 3);
    assert_eq!(Test::median(()), Some(1));

    assert!(Test::pop((), 1));
    assert_eq!(Test::length(()), 2);
    assert_eq!(Test::median(()), Some(1));
  });

  // Test when we pop a median with a value after
  sp_io::TestExternalities::default().execute_with(|| {
    Test::push((), 0);
    Test::push((), 1);
    Test::push((), 2);
    assert_eq!(Test::length(()), 3);
    assert_eq!(Test::median(()), Some(1));

    assert!(Test::pop((), 1));
    assert_eq!(Test::length(()), 2);
    assert_eq!(Test::median(()), Some(2));
  });
}

macro_rules! fuzz_test {
  ($name: ident, $policy: expr) => {
    #[test]
    fn $name() {
      test!($policy);

      sp_io::TestExternalities::default().execute_with(|| {
        assert_eq!(Test::length(()), 0);
        assert_eq!(Test::median(()), None);

        let mut current_list = vec![];
        for i in 0 .. 1000 {
          'reselect: loop {
            // This chooses a modulus low enough this `match` will in fact match, yet high enough
            // more cases can be added without forgetting to update it being an issue
            match OsRng.next_u64() % 8 {
              // Push a freshly sampled value
              0 => {
                #[allow(clippy::cast_possible_truncation)]
                let push = OsRng.next_u64() as u32;
                current_list.push(push);
                current_list.sort();
                Test::push((), push);
              }
              // Push an existing value
              1 if !current_list.is_empty() => {
                let i =
                  usize::try_from(OsRng.next_u64() % u64::try_from(current_list.len()).unwrap())
                    .unwrap();
                let push = current_list[i];
                current_list.push(push);
                current_list.sort();
                Test::push((), push);
              }
              // Remove an existing value
              2 if !current_list.is_empty() => {
                let i =
                  usize::try_from(OsRng.next_u64() % u64::try_from(current_list.len()).unwrap())
                    .unwrap();
                let pop = current_list.remove(i);
                assert!(Test::pop((), pop));
              }
              // Remove a value which is not present
              3 => {
                #[allow(clippy::cast_possible_truncation)]
                let pop = OsRng.next_u64() as u32;
                if current_list.contains(&pop) {
                  continue 'reselect;
                }
                assert!(!Test::pop((), pop));
              }
              _ => continue 'reselect,
            }
            break 'reselect;
          }

          assert_eq!(
            Test::length(()),
            u64::try_from(current_list.len()).unwrap(),
            "length differs on iteration: {i}",
          );
          let mut target_median_pos = current_list.len() / 2;
          if matches!($policy, Policy::Lesser | Policy::Average) && ((current_list.len() % 2) == 0)
          {
            target_median_pos = target_median_pos.saturating_sub(1);
          }
          let expected = (!current_list.is_empty()).then(|| match $policy {
            Policy::Greater | Policy::Lesser => current_list[target_median_pos],
            Policy::Average => {
              if (current_list.len() % 2) == 0 {
                u32::average(current_list[target_median_pos], current_list[target_median_pos + 1])
              } else {
                current_list[target_median_pos]
              }
            }
          });
          assert_eq!(Test::median(()), expected, "median differs on iteration: {i}");
        }
      });
    }
  };
}
fuzz_test!(greater, Policy::Greater);
fuzz_test!(lesser, Policy::Lesser);
fuzz_test!(average, Policy::Average);
