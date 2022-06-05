use sha2::{Digest, Sha256};

pub mod kp256;

// TODO: Actually make proper or replace with something from another crate
pub(crate) fn expand_message_xmd_sha256(dst: &[u8], msg: &[u8], len: u16) -> Option<Vec<u8>> {
  const OUTPUT_SIZE: u16 = 32;
  const BLOCK_SIZE: u16 = 64;

  let blocks = ((len + OUTPUT_SIZE) - 1) / OUTPUT_SIZE;
  if blocks > 255 {
    return None;
  }
  let blocks = blocks as u8;

  let mut dst = dst;
  let oversize = Sha256::digest([b"H2C-OVERSIZE-DST-", dst].concat());
  if dst.len() > 255 {
    dst = &oversize;
  }
  let dst_prime = &[dst, &[dst.len() as u8]].concat();

  let mut msg_prime = vec![0; BLOCK_SIZE.into()];
  msg_prime.extend(msg);
  msg_prime.extend(len.to_be_bytes());
  msg_prime.push(0);
  msg_prime.extend(dst_prime);

  let mut b = vec![Sha256::digest(&msg_prime).to_vec()];

  {
    let mut b1 = b[0].clone();
    b1.push(1);
    b1.extend(dst_prime);
    b.push(Sha256::digest(&b1).to_vec());
  }

  for i in 2 ..= blocks {
    let mut msg = b[0]
      .iter().zip(b[usize::from(i) - 1].iter())
      .map(|(a, b)| *a ^ b).collect::<Vec<_>>();
    msg.push(i);
    msg.extend(dst_prime);
    b.push(Sha256::digest(msg).to_vec());
  }

  Some(b[1 ..].concat()[.. usize::from(len)].to_vec())
}
