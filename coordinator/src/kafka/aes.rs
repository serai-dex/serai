use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hex_literal::hex;
use std::str;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn main() {
  let key = [0x42; 16];
  let iv = [0x24; 16];
  let plaintext = *b"hello world! this is my plaintext.";
  let ciphertext = hex!(
      "c7fe247ef97b21f07cbdd26cb5d346bf"
      "d27867cb00d9486723e159978fb9a5f9"
      "14cfb228a710de4171e396e7b6cf859e"
  );

  println!("{:?}", str::from_utf8(&plaintext).unwrap());

  // encrypt/decrypt in-place
  // buffer must be big enough for padded plaintext
  let mut buf = [0u8; 48];
  let pt_len = plaintext.len();
  buf[..pt_len].copy_from_slice(&plaintext);
  let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
    .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
    .unwrap();
  assert_eq!(ct, &ciphertext[..]);

  println!("{:?}", ct);

  let pt =
    Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf).unwrap();
  assert_eq!(pt, &plaintext);

  println!("{:?}", str::from_utf8(pt).unwrap());

  // encrypt/decrypt from buffer to buffer
  let mut buf = [0u8; 48];
  let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
    .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
    .unwrap();
  assert_eq!(ct, &ciphertext[..]);

  let mut buf = [0u8; 48];
  let pt = Aes128CbcDec::new(&key.into(), &iv.into())
    .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
    .unwrap();
  assert_eq!(pt, &plaintext);
}
