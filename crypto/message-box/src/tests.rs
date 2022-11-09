use std::collections::HashMap;

use crate::{key_gen, MessageBox};

const A: &'static str = "A";
const B: &'static str = "B";

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
  let enc = a_box.encrypt(B, msg.clone());
  assert_eq!(msg, b_box.decrypt(A, enc))
}
