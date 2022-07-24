#![cfg_attr(not(feature = "std"), no_std)]

use scale::{Encode, Decode};

use ink_env::{
  hash::{CryptoHash, Blake2x256},
  topics::PrefixedValue,
};

use ink_lang as ink;

fn hash_prefixed<T: Encode>(prefixed: PrefixedValue<T>) -> [u8; 32] {
  let encoded = prefixed.encode();
  let mut hash = [0; 32];
  if encoded.len() < 32 {
    hash[.. encoded.len()].copy_from_slice(&encoded);
  } else {
    Blake2x256::hash(&encoded, &mut hash);
  }
  hash
}

#[allow(clippy::let_unit_value)]
#[ink::contract]
mod callee_contract {
  use ink_storage::traits::{SpreadLayout, PackedLayout};
  use ink_prelude::vec::Vec;

  use super::*;

  /// Test contract which emits events of its calls.
  #[ink(storage)]
  pub struct Callee;

  /// Event emitted when a call passes an u64.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[ink(event)]
  pub struct U64Call {
    pub value: u64,
  }

  /// Event emitted when a call passes a Vec<u8>.
  #[derive(Debug, Clone, PartialEq, Eq)]
  #[ink(event)]
  pub struct VecCall {
    pub value: Vec<u8>,
  }

  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, SpreadLayout, PackedLayout)]
  pub struct CallStruct {
    pub a: u64,
    pub b: bool,
    pub c: Vec<u8>,
  }

  /// Event emitted when a call passes a struct.
  #[derive(Debug, PartialEq, Eq)]
  #[ink(event)]
  pub struct StructCall {
    pub value: CallStruct,
  }

  /// Event emitted when a call passes a series of arguments.
  #[derive(Debug, PartialEq, Eq)]
  #[ink(event)]
  pub struct MultiArgCall {
    pub a: u64,
    pub b: bool,
    pub c: Vec<u8>,
    pub value: CallStruct,
  }

  impl Callee {
    #[allow(clippy::new_without_default)]
    #[ink(constructor)]
    pub fn new() -> Self {
      Self {}
    }

    /// Function which takes a u64 and emits U64Call.
    #[ink(message)]
    pub fn u64_call(&self, value: u64) {
      self.env().emit_event(U64Call { value })
    }

    /// Function which takes a Vec<u8> and emits VecCall.
    #[ink(message)]
    pub fn vec_call(&self, value: Vec<u8>) {
      self.env().emit_event(VecCall { value })
    }

    /// Function which takes a CallStruct and emits StructCall.
    #[ink(message)]
    pub fn struct_call(&self, value: CallStruct) {
      self.env().emit_event(StructCall { value })
    }

    /// Function which takes a CallStruct and emits StructCall.
    #[ink(message)]
    pub fn multi_arg_call(&self, a: u64, b: bool, c: Vec<u8>, value: CallStruct) {
      self.env().emit_event(MultiArgCall { a, b, c, value })
    }
  }
}

pub mod callee {
  use ink_prelude::vec;

  use super::*;
  pub use callee_contract::*;

  type Event = <Callee as ::ink_lang::reflect::ContractEventBase>::Type;

  pub fn assert_event<T: Encode + Decode>(event: &ink_env::test::EmittedEvent, value: T) {
    let decoded_event = <Event as Decode>::decode(&mut &event.data[..]).unwrap();

    let data = value.encode();
    let string_event = match decoded_event {
      Event::U64Call(call) => {
        assert_eq!(call, U64Call::decode(&mut &data[..]).unwrap());
        b"U64Call" as &'static [u8]
      }
      Event::VecCall(call) => {
        assert_eq!(call, VecCall::decode(&mut &data[..]).unwrap());
        b"VecCall"
      }
      Event::StructCall(call) => {
        assert_eq!(call, StructCall::decode(&mut &data[..]).unwrap());
        b"StructCall"
      }
      Event::MultiArgCall(call) => {
        assert_eq!(call, MultiArgCall::decode(&mut &data[..]).unwrap());
        b"MultiArgCall"
      }
    };

    // This doesn't work because it's not detected as fixed length and length prefixes
    // hash_prefixed(PrefixedValue { prefix: b"", value: &[b"Callee::", string_event].concat() }),
    let event_topic = {
      let mut topic = [0; 32];
      let value = [[0].as_ref(), b"Callee::", string_event].concat();
      topic[.. value.len()].copy_from_slice(&value);
      topic
    };


    let mut expected_topics = vec![
      event_topic,
      hash_prefixed(PrefixedValue {
        prefix: &[b"Callee::", string_event, b"::value"].concat(),
        value: &value,
      }),
    ];

    if string_event == b"MultiArgCall" {
      expected_topics.pop();
      let data = MultiArgCall::decode(&mut &data[..]).unwrap();
      expected_topics.extend([
        hash_prefixed(PrefixedValue { prefix: b"Callee::MultiArgCall::a", value: &data.a }),
        hash_prefixed(PrefixedValue { prefix: b"Callee::MultiArgCall::b", value: &data.b }),
        hash_prefixed(PrefixedValue { prefix: b"Callee::MultiArgCall::c", value: &data.c }),
        hash_prefixed(PrefixedValue { prefix: b"Callee::MultiArgCall::value", value: &data.value }),
      ]);
    }

    for (n, (actual_topic, expected_topic)) in event.topics.iter().zip(expected_topics).enumerate()
    {
      assert_eq!(actual_topic, &expected_topic, "encountered invalid topic at {}", n);
    }
  }

  #[cfg(test)]
  mod callee_tests {
    use super::*;

    fn event() -> ink_env::test::EmittedEvent {
      ink_env::test::recorded_events().next().unwrap()
    }

    /// The default constructor does its job.
    #[ink::test]
    fn new() {
      Callee::new();
    }

    /// u64 calls work.
    #[ink::test]
    fn u64_call() {
      Callee::new().u64_call(5);
      assert_event(&event(), U64Call { value: 5 });
    }

    /// Vec<u8> calls work.
    #[ink::test]
    fn vec_call() {
      let value = vec![1, 2, 3];
      Callee::new().vec_call(value.clone());
      assert_event(&event(), VecCall { value });
    }

    /// Struct calls work.
    #[ink::test]
    fn struct_call() {
      let value = CallStruct { a: 3, b: true, c: vec![7, 6, 8] };
      Callee::new().struct_call(value.clone());
      assert_event(&event(), StructCall { value });
    }

    /// Multiple argument calls work.
    #[ink::test]
    fn multi_arg_call() {
      let a = 3;
      let b = true;
      let c = vec![1, 2, 3];
      let value = CallStruct { a: 5, b: false, c: vec![7, 6, 8] };
      Callee::new().multi_arg_call(a, b, c.clone(), value.clone());
      assert_event(&event(), MultiArgCall { a, b, c, value });
    }
  }
}
