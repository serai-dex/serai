use zeroize::Zeroize;

use group::ff::PrimeField;

use message_box::key_gen;

fn main() {
  let (private, public) = key_gen();
  let mut private_bytes = unsafe { private.inner().to_repr() };
  println!("Private: {}", hex::encode(private_bytes.as_ref()));
  private_bytes.zeroize();
  println!("Public: {}", hex::encode(public.to_bytes()));
}
