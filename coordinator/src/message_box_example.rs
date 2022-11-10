use message_box::MessageBox;
use std::{collections::HashMap};

// static names for each service
const A: &'static str = "A";
const B: &'static str = "B";

pub fn run_example() {
  // Create 2 priv / pub key pairs
  let (a_priv, a_pub) = message_box::key_gen();
  let (b_priv, b_pub) = message_box::key_gen();

  // Create a HashMap of each pair using service name and public key
  let mut a_others = HashMap::new();
  a_others.insert(B, b_pub);

  let mut b_others = HashMap::new();
  b_others.insert(A, a_pub);

  // Initialize a MessageBox for each service
  let a_box = MessageBox::new(A, a_priv, a_others);
  let b_box = MessageBox::new(B, b_priv, b_others);

  // Create message to send from A to B
  let msg = "Message to be encrypted".as_bytes().to_vec();

  // Encrypt message using A's MessageBox
  let enc = a_box.encrypt(B, msg.clone());

  // Decrypt message using B's MessageBox
  let dec = b_box.decrypt(A, enc);

  // Assert that the decrypted message is the same as the original message
  assert_eq!(msg, dec);

  // Print the decrypted message
  dbg!(String::from_utf8(dec).unwrap());
}
