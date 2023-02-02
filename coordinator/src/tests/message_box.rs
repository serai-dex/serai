use std::collections::HashMap;

use message_box::{PrivateKey, PublicKey, MessageBox};

// This illustrates the use of External Message box
// External Message box uses a pub key for its ID
#[test]
pub fn message_box_test() {
  println!("Starting External Message Box Test");
  // ID used for Message Box A:
  let a_string = "7028863a50b36889ac0861d782bfbde469ab989936aff4b8282a2af9cc1cfc23";
  let a_id = PublicKey::from_trusted_str(a_string);

  // Used for Message Box A
  let a_privkey_string = "8e06885acf9c5d39d38615368ffe957df611428b6f8060d2c44372d6b3df5d0c";
  let a_privkey = PrivateKey::from_string(a_privkey_string.to_string());

  let a_pubkey_string = "6a9eaf51b278baa6acc52fd0e4741013b5c81bc6d4d7123f0c23a68d2e6c2e68";
  let a_pubkey = PublicKey::from_trusted_str(a_pubkey_string);

  // ID used for Message Box B:
  let b_string = "a05669c02c1f3688fc21369703e4825cc05014bbb2d89d4405d98ddfde7b6676";
  let b_id = PublicKey::from_trusted_str(b_string);

  // Used for Message Box B
  let b_privkey_string = "699c67a3cb3f5a05dc125ac1f3cc830f6a557df3c852f0365178dc8ca803f60c";
  let b_privkey = PrivateKey::from_string(b_privkey_string.to_string());
  let b_pubkey_string = "08692c403818d49edf516d981a8395268075aa8bbb86e59f572b7d39618ed805";
  let b_pubkey = PublicKey::from_trusted_str(b_pubkey_string);

  let mut a_others = HashMap::new();
  a_others.insert(b_id, b_pubkey);

  let mut b_others = HashMap::new();
  b_others.insert(a_id, a_pubkey);

  let a_box = MessageBox::new(a_id, a_privkey, a_others);
  let b_box = MessageBox::new(b_id, b_privkey, b_others);

  let msg = "Message Box Test";

  let enc = a_box.encrypt_to_string(&b_id, &msg);
  let dec: String = b_box.decrypt_from_str(&a_id, &enc).unwrap();
  assert_eq!("Message Box Test", dec);
}
