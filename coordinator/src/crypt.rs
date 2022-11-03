use magic_crypt::{new_magic_crypt, MagicCryptTrait};

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
