use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::env;

pub trait SeraiCrypt {
  fn setKey(encrypt_key: &str) {
    let key = "ENCRYPT_KEY";
    env::set_var(key, encrypt_key);
  }

  fn encrypt(msg: &str) -> std::string::String {
    let key = env::var("ENCRYPT_KEY").unwrap();
    let mc = new_magic_crypt!(key, 256);

    //println!("Initial String:");
    //println!("{}", msg);

    let encrypted_string = mc.encrypt_str_to_base64(msg);

    //println!("Encrypted String:");
    //println!("{}", encrypted_string);

    return encrypted_string;
  }

  fn decrypt(encrypted_string: &str) -> std::string::String {
    let key = env::var("ENCRYPT_KEY").unwrap();
    let mc = new_magic_crypt!(key, 256);

    let decrypted_string = mc.decrypt_base64_to_string(&encrypted_string).unwrap();
    //println!("Decrypted String:");
    //println!("{}", decrypted_string);

    return decrypted_string;
  }
}
