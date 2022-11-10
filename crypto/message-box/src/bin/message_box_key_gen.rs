use zeroize::Zeroize;
use rand_core::OsRng;

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};

use message_box::{PrivateKey, PublicKey};

fn main() {
  let mut private = PrivateKey::random(&mut OsRng);
  let mut private_bytes = private.to_repr();
  let public = {
    let borrowed = &private;
    PublicKey::generator() * borrowed
  };
  private.zeroize();

  println!("Private: {}", hex::encode(private_bytes.as_ref()));
  private_bytes.zeroize();
  println!("Public: {}", hex::encode(public.to_bytes()));
}
