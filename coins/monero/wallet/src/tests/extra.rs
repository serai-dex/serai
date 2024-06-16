use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use monero_serai::io::write_varint;
use crate::{ExtraField, Extra, extra::MAX_TX_EXTRA_PADDING_COUNT};

// Borrowed tests from
// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
//   tests/unit_tests/test_tx_utils.cpp

const PUB_KEY_BYTES: [u8; 33] = [
  1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63,
  198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
];

fn pub_key() -> EdwardsPoint {
  CompressedEdwardsY(PUB_KEY_BYTES[1 .. PUB_KEY_BYTES.len()].try_into().expect("invalid pub key"))
    .decompress()
    .unwrap()
}

fn test_write_buf(extra: &Extra, buf: &[u8]) {
  let mut w: Vec<u8> = vec![];
  Extra::write(extra, &mut w).unwrap();
  assert_eq!(buf, w);
}

#[test]
fn empty_extra() {
  let buf: Vec<u8> = vec![];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_size_1() {
  let buf: Vec<u8> = vec![0];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(1)]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_size_2() {
  let buf: Vec<u8> = vec![0, 0];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(2)]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_max_size() {
  let buf: Vec<u8> = vec![0; MAX_TX_EXTRA_PADDING_COUNT];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(MAX_TX_EXTRA_PADDING_COUNT)]);
  test_write_buf(&extra, &buf);
}

#[test]
fn padding_only_exceed_max_size() {
  let buf: Vec<u8> = vec![0; MAX_TX_EXTRA_PADDING_COUNT + 1];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn invalid_padding_only() {
  let buf: Vec<u8> = vec![0, 42];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_only() {
  let buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key())]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_nonce_only() {
  let buf: Vec<u8> = vec![2, 1, 42];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Nonce(vec![42])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_nonce_only_wrong_size() {
  let mut buf: Vec<u8> = vec![0; 20];
  buf[0] = 2;
  buf[1] = 255;
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_and_padding() {
  let mut buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  buf.extend([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key()), ExtraField::Padding(76)]);
  test_write_buf(&extra, &buf);
}

#[test]
fn pub_key_and_invalid_padding() {
  let mut buf: Vec<u8> = PUB_KEY_BYTES.to_vec();
  buf.extend([0, 1]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(pub_key())]);
}

#[test]
fn extra_mysterious_minergate_only() {
  let buf: Vec<u8> = vec![222, 1, 42];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MysteriousMinergate(vec![42])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_mysterious_minergate_only_large() {
  let mut buf: Vec<u8> = vec![222];
  write_varint(&512u64, &mut buf).unwrap();
  buf.extend_from_slice(&vec![0; 512]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::MysteriousMinergate(vec![0; 512])]);
  test_write_buf(&extra, &buf);
}

#[test]
fn extra_mysterious_minergate_only_wrong_size() {
  let mut buf: Vec<u8> = vec![0; 20];
  buf[0] = 222;
  buf[1] = 255;
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn extra_mysterious_minergate_and_pub_key() {
  let mut buf: Vec<u8> = vec![222, 1, 42];
  buf.extend(PUB_KEY_BYTES.to_vec());
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(
    extra.0,
    vec![ExtraField::MysteriousMinergate(vec![42]), ExtraField::PublicKey(pub_key())]
  );
  test_write_buf(&extra, &buf);
}
