use std::alloc::System;
use zeroize::Zeroize;
use zalloc::ZeroizingAlloc;
use group::ff::PrimeField;
use message_box;
use std::collections::HashMap;

// This illustrates the use of External Message box
// External Message box uses a pub key for its ID
#[test]
pub fn message_box_test() {
  println!("Starting External Message Box Test");
  // ID used for Message Box A:
  // Priv: 7fa1d7740f43a3e897f2cb07b6124fcf05ac54b3bf8af7b78f2ce2806bae630b
  let A_ID_STR = "7028863a50b36889ac0861d782bfbde469ab989936aff4b8282a2af9cc1cfc23";
  let A_ID = message_box::PublicKey::from_trusted_str(A_ID_STR);

  // Used for Message Box A
  let A_PRIV_STR = "8e06885acf9c5d39d38615368ffe957df611428b6f8060d2c44372d6b3df5d0c";
  let A_PRIV = message_box::PrivateKey::from_string(A_PRIV_STR.to_string());

  let A_PUB_STR = "6a9eaf51b278baa6acc52fd0e4741013b5c81bc6d4d7123f0c23a68d2e6c2e68";
  let A_PUB = message_box::PublicKey::from_trusted_str(A_PUB_STR);

  // ID used for Message Box B:
  // Priv: 7eafe7e9251208ed7360bad590b5af8be6d7fee5f6985e9066e90f2dd1fcb00c
  let B_ID_STR = "a05669c02c1f3688fc21369703e4825cc05014bbb2d89d4405d98ddfde7b6676";
  let B_ID = message_box::PublicKey::from_trusted_str(B_ID_STR);

  // Used for Message Box B
  let B_PRIV_STR = "699c67a3cb3f5a05dc125ac1f3cc830f6a557df3c852f0365178dc8ca803f60c";
  let B_PRIV = message_box::PrivateKey::from_string(B_PRIV_STR.to_string());
  let B_PUB_STR = "08692c403818d49edf516d981a8395268075aa8bbb86e59f572b7d39618ed805";
  let B_PUB = message_box::PublicKey::from_trusted_str(B_PUB_STR);
  
  let mut a_others = HashMap::new();
  a_others.insert(B_ID, B_PUB);

  let mut b_others = HashMap::new();
  b_others.insert(A_ID, A_PUB);

  let a_box = message_box::MessageBox::new(A_ID, A_PRIV, a_others);
  //let b_box = message_box::MessageBox::new(B_ID, B_PRIV, b_others);
  dbg!(a_box);
}
