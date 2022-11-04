use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::env;

pub fn start() {
  let mc = new_magic_crypt!("magickey", 256);

  let json_string = "json string possibly";

  println!("Initial String:");
  println!("{}", json_string);

  let base64 = mc.encrypt_str_to_base64(json_string);

  println!("Encrypted String:");
  println!("{}", base64);

  let decrypted_string = mc.decrypt_base64_to_string(&base64).unwrap();
  println!("Decrypted String:");
  println!("{}", decrypted_string);

  //assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);
  //assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
}

pub fn setKey(encrypt_key: &str) {
  let key = "ENCRYPT_KEY";
  env::set_var(key, encrypt_key);
}

pub fn encrypt(msg: &str) -> std::string::String {
  let key = env::var("ENCRYPT_KEY").unwrap();
  let mc = new_magic_crypt!(key, 256);

  //println!("Initial String:");
  //println!("{}", msg);

  let encrypted_string = mc.encrypt_str_to_base64(msg);

  //println!("Encrypted String:");
  //println!("{}", encrypted_string);

  return encrypted_string;
}

pub fn decrypt(encrypted_string: &str) -> std::string::String {
  let key = env::var("ENCRYPT_KEY").unwrap();
  let mc = new_magic_crypt!(key, 256);

  let decrypted_string = mc.decrypt_base64_to_string(&encrypted_string).unwrap();
  //println!("Decrypted String:");
  //println!("{}", decrypted_string);

  return decrypted_string;
}
