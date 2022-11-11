use std::collections::HashMap;

use crate::{Serialize, Deserialize, PrivateKey, PublicKey, SecureMessage, MessageBox, key_gen};

const A: &'static str = "A";
const B: &'static str = "B";

#[allow(deprecated)]
#[test]
pub fn key_serialization() {
  let (private, public) = key_gen();
  assert_eq!(private, PrivateKey::from_string(private.to_string()));
  assert_eq!(public, PublicKey::from_bytes(&public.to_bytes()).unwrap());
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct TestMessage {
  msg: String,
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

  // SecureMessage API
  {
    let msg = b"Hello, world!".to_vec();
    let enc = a_box.encrypt_bytes(&B, msg.clone());
    assert_eq!(msg, b_box.decrypt_to_bytes(&A, enc.clone()));

    // Additionally test its serialize and serde support
    assert_eq!(enc, SecureMessage::new(enc.serialize()).unwrap());
    assert_eq!(enc, serde_json::from_str(&serde_json::to_string(&enc).unwrap()).unwrap());
  }

  // Generic API
  let msg = TestMessage { msg: "Hello, world!".into() };
  let enc = a_box.encrypt(&B, &msg);
  assert_eq!(msg, b_box.decrypt(&A, enc));

  // Serialized API
  assert_eq!(msg, b_box.decrypt_from_slice(&A, &a_box.encrypt_to_bytes(&B, &msg)).unwrap());

  // String API
  {
    #[allow(deprecated)]
    let enc = a_box.encrypt_to_string(&B, &msg);
    #[allow(deprecated)]
    let dec = b_box.decrypt_from_str(&A, &enc).unwrap();
    assert_eq!(msg, dec);
  }
}
