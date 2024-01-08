use crate::{
  wallet::{ExtraField, Extra, extra::MAX_TX_EXTRA_PADDING_COUNT},
};

use curve25519_dalek::edwards::CompressedEdwardsY;

// Borrowed tests from
// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
//   tests/unit_tests/test_tx_utils.cpp

fn test_write_buf(extra: Extra, buf: Vec<u8>) {
  let mut w: Vec<u8> = vec![];
  let _ = Extra::write(&extra, &mut w);
  assert_eq!(buf, w);
}

#[test]
fn empty_extra() {
  let buf: Vec<u8> = vec![];
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
  test_write_buf(extra, buf);
}

#[test]
fn padding_only_size_1() {
  let buf: Vec<u8> = Vec::from([0]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(1)]);
  test_write_buf(extra, buf);
}

#[test]
fn padding_only_size_2() {
  let buf: Vec<u8> = Vec::from([0, 0]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(2)]);
  test_write_buf(extra, buf);
}

#[test]
fn padding_only_max_size() {
  let buf: Vec<u8> = Vec::from([0; MAX_TX_EXTRA_PADDING_COUNT]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Padding(MAX_TX_EXTRA_PADDING_COUNT)]);
  test_write_buf(extra, buf);
}

#[test]
fn padding_only_exceed_max_size() {
  let buf: Vec<u8> = Vec::from([0; MAX_TX_EXTRA_PADDING_COUNT + 1]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn invalid_padding_only() {
  let buf: Vec<u8> = Vec::from([0, 42]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_only() {
  let buf: Vec<u8> = Vec::from([
    1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63,
    198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
  ]);
  let expected_pub_key =
    CompressedEdwardsY(buf.clone()[1 .. buf.len()].try_into().expect("invalid pub key"))
      .decompress()
      .unwrap();
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(expected_pub_key)]);
  test_write_buf(extra, buf);
}

#[test]
fn extra_nonce_only() {
  let buf: Vec<u8> = Vec::from([2, 1, 42]);
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::Nonce(vec![42])]);
  test_write_buf(extra, buf);
}

#[test]
fn extra_nonce_only_wrong_size() {
  let mut buf: Vec<u8> = Vec::from([0; 20]);
  buf[0] = 2;
  buf[1] = 255;
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert!(extra.0.is_empty());
}

#[test]
fn pub_key_and_padding() {
  let buf: Vec<u8> = Vec::from([
    1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228, 80, 63,
    198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]);
  let expected_pub_key =
    CompressedEdwardsY(buf.clone()[1 .. 33].try_into().expect("invalid pub key"))
      .decompress()
      .unwrap();
  let extra = Extra::read::<&[u8]>(&mut buf.as_ref()).unwrap();
  assert_eq!(extra.0, vec![ExtraField::PublicKey(expected_pub_key), ExtraField::Padding(76)]);
  test_write_buf(extra, buf);
}
