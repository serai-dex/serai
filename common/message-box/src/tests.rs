use std::collections::HashMap;

use crate::{
  Serialize, Deserialize, PrivateKey, PublicKey, InternalMessageBox, ExternalMessageBox, key_gen,
};

const A: &str = "A";
const B: &str = "B";

#[allow(deprecated)]
#[test]
pub fn key_serialization() {
  let (private, public) = key_gen();
  assert_eq!(private, PrivateKey::from_string(private.to_string()));
  assert_eq!(public, PublicKey::from_str(&public.to_string()).unwrap());
  assert_eq!(public, bincode::deserialize(&bincode::serialize(&public).unwrap()).unwrap());
  assert_eq!(public, serde_json::from_str(&serde_json::to_string(&public).unwrap()).unwrap());
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct TestMessage {
  msg: String,
}

macro_rules! message_box_test {
  ($new: expr, $sign: expr, $encode: ident, $A_id: expr, $B_id: expr,) => {
    let (a_priv, a_pub) = key_gen();
    let (b_priv, b_pub) = key_gen();

    let mut a_others = HashMap::new();
    a_others.insert($B_id(b_pub), b_pub);

    let mut b_others = HashMap::new();
    b_others.insert($A_id(a_pub), a_pub);

    let a_box = $new($A_id(a_pub), a_priv, a_others);
    let b_box = $new($B_id(b_pub), b_priv, b_others);

    let msg = TestMessage { msg: "Hello, world!".into() };

    // Message API
    {
      let res = $sign(&a_box, msg.clone());
      assert_eq!(msg, b_box.verify(&$A_id(a_pub), res.clone()).unwrap());

      // Additionally test its serialize and serde support
      assert_eq!(res, bincode::deserialize(&bincode::serialize(&res).unwrap()).unwrap());
      assert_eq!(res, serde_json::from_str(&serde_json::to_string(&res).unwrap()).unwrap());
    }

    // Encoded API
    {
      let res = $sign(&a_box, msg.clone()).$encode();
      let dec = b_box.deserialize(&$A_id(a_pub), &res).unwrap();
      assert_eq!(msg, dec);
    }
  };
}

#[test]
pub fn message_box() {
  message_box_test!(
    InternalMessageBox::new,
    |a_box: &InternalMessageBox, msg| a_box.sign(B, msg),
    to_string,
    |_| A,
    |_| B,
  );

  message_box_test!(
    |_, key, others: HashMap<PublicKey, PublicKey>| {
      let mut a_box = ExternalMessageBox::new(key);
      for other in others.values() {
        a_box.add(*other);
      }
      a_box
    },
    |a_box: &ExternalMessageBox, msg| a_box.sign(msg),
    to_bytes,
    |key| key,
    |key| key,
  );
}
