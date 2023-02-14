use crate::wallet::seed::{Seed, LanguageName};

#[test]
fn test_classic() {
  // keys
  let spend = "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403";
  let _view = "513ba91c538a5a9069e0094de90e927c0cd147fa10428ce3ac1afd49f63e3b01";

  // seed string
  let mut seed = String::from("washing thirsty occur lectures tuesday fainted toxic adapt ");
  seed.push_str("abnormal memoir nylon mostly building shrugged online ember northern ");
  seed.push_str("ruby woes dauntless boil family illness inroads northern");

  // string -> key
  let s1 = Seed::from_string(seed).unwrap();
  let spend_bytes: [u8; 32] = hex::decode(spend).unwrap().try_into().unwrap();
  assert_eq!(s1.spend(), spend_bytes);

  // key -> string
  let s2 = Seed::from_key(&spend_bytes, LanguageName::English).unwrap();
  assert_eq!(s1, s2);
}
