use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use monero::{consensus::{Encodable, deserialize}, util::ringct::Bulletproof};

use crate::{Commitment, transaction::TransactionError, free, c_generate_bp, c_verify_bp};

pub fn generate(outputs: &[Commitment]) -> Result<Bulletproof, TransactionError> {
  if outputs.len() > 16 {
    return Err(TransactionError::TooManyOutputs)?;
  }

  let masks: Vec<[u8; 32]> = outputs.iter().map(|commitment| commitment.mask.to_bytes()).collect();
  let amounts: Vec<u64> = outputs.iter().map(|commitment| commitment.amount).collect();
  let res;
  unsafe {
    let ptr = c_generate_bp(outputs.len() as u8, amounts.as_ptr(), masks.as_ptr());
    let len = ((ptr.read() as usize) << 8) + (ptr.add(1).read() as usize);
    res = deserialize(
      std::slice::from_raw_parts(ptr.add(2), len)
    ).expect("Couldn't deserialize Bulletproof from Monero");
    free(ptr);
  }

  Ok(res)
}

pub fn verify(bp: &Bulletproof, commitments: &[EdwardsPoint]) -> bool {
  if commitments.len() > 16 {
    return false;
  }

  let mut serialized = vec![];
  bp.consensus_encode(&mut serialized).unwrap();
  let commitments: Vec<[u8; 32]> = commitments.iter().map(
    |commitment| (commitment * Scalar::from(8 as u8).invert()).compress().to_bytes()
  ).collect();
  unsafe {
    c_verify_bp(serialized.len(), serialized.as_ptr(), commitments.len() as u8, commitments.as_ptr())
  }
}
