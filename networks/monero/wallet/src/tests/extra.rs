use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use crate::{
  io::write_varint,
  extra::{MAX_TX_EXTRA_PADDING_COUNT, ExtraField, Extra},
};

// Tests derived from
// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
//   tests/unit_tests/test_tx_utils.cpp
// which is licensed as follows:
#[rustfmt::skip]
/*
Copyright (c) 2014-2022, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Parts of the project are originally copyright (c) 2012-2013 The Cryptonote
developers

Parts of the project are originally copyright (c) 2014 The Boolberry
developers, distributed under the MIT licence:

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
