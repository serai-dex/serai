use std::collections::HashMap;

use crate::{SecureMessage, MessageBox, key_gen};

const A: &'static str = "A";
const B: &'static str = "B";

#[test]
pub fn re_export() {
  use crate::key::*;

  let (private, public) = key_gen();
  assert_eq!(private, PrivateKey::from_repr(private.to_repr()).unwrap());
  assert_eq!(public, PublicKey::from_bytes(&public.to_bytes()).unwrap());
}

#[test]
pub fn message_box() {
  let (a_priv, a_pub) = key_gen();
  let (b_priv, b_pub) = key_gen();

  let mut a_others = HashMap::new();
  a_others.insert(B, b_pub);

  let mut b_others = HashMap::new();
  b_others.insert(A, a_pub);

  let a_box = MessageBox::new(A, a_priv, a_others);
  let b_box = MessageBox::new(B, b_priv, b_others);

  let msg = b"Hello, world!".to_vec();
  let enc = a_box.encrypt_bytes(B, msg.clone());
  assert_eq!(enc, SecureMessage::new(enc.serialize()).unwrap());
  assert_eq!(enc, serde_json::from_str(&serde_json::to_string(&enc).unwrap()).unwrap());
  assert_eq!(msg, b_box.decrypt_to_bytes(A, enc));

  assert_eq!(msg, b_box.decrypt_from_bytes(A, a_box.encrypt_to_bytes(B, msg.clone())).unwrap());

  {
    #[allow(deprecated)]
    let enc = a_box.encrypt_to_string(B, msg.clone());
    #[allow(deprecated)]
    let dec = b_box.decrypt_from_str(A, &enc).unwrap();
    assert_eq!(msg, dec);
  }
}
