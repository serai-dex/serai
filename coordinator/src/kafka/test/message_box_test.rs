use std::alloc::System;
use zeroize::Zeroize;
use zalloc::ZeroizingAlloc;
use group::ff::PrimeField;
use message_box;

pub fn start() {
  println!("Starting Message Box Test");
  let (private, public) = message_box::key_gen();
  // let mut private_bytes = unsafe { private.inner().to_repr() };
  // println!("Private: {}", hex::encode(private_bytes.as_ref()));
  // private_bytes.zeroize();
  // println!("Public: {}", hex::encode(public.to_bytes()));
  dbg!(private);
}
