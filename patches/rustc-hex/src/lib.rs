//! Patch `rustc-hex` to a minimal alternative.
//!
//! This was prompted by how `rustc-hex`'s `<FromHexError as Display>::fmt` MAY print non-hex
//! characters directly, without any sanitization. By contrast, `hex` always uses
//! `<char as Debug>::fmt`, which applies sanitization.

#![no_std]

// This is required by `trie-db` and accordingly non-trivial to remove from our tree
pub struct ToHexIter<'a, T: Iterator<Item = &'a u8>>(T, Option<u8>);
impl<'a, T: Iterator<Item = &'a u8>> ToHexIter<'a, T> {
  pub fn new(iter: T) -> Self {
    Self(iter, None)
  }
}
impl<'a, T: Iterator<Item = &'a u8>> Iterator for ToHexIter<'a, T> {
  type Item = char;
  fn next(&mut self) -> Option<Self::Item> {
    match self.1.take() {
      Some(char) => Some(char::from(char)),
      None => {
        const CHARS: &[u8] = b"0123456789abcdef";
        let byte = *self.0.next()?;
        let first = CHARS[usize::from(byte >> 4)];
        let second = CHARS[usize::from(byte & 0b1111)];
        self.1 = Some(second);
        Some(char::from(first))
      }
    }
  }
}

#[test]
fn to_hex() {
  use core::fmt::Write;
  extern crate alloc;
  use alloc::string::String;

  let mut bytes = alloc::vec![];
  let mut hex = String::new();
  for i in 0 ..= u8::MAX {
    bytes.push(i);
    core::write!(&mut hex, "{i:02x}").unwrap();
    assert_eq!(ToHexIter::new(bytes.iter()).collect::<String>(), hex);
  }
}
