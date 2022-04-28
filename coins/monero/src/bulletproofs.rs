use monero::{consensus::deserialize, util::ringct::Bulletproof};

use crate::{Commitment, transaction::TransactionError, free, c_gen_bp};

pub fn generate(outputs: Vec<Commitment>) -> Result<Bulletproof, TransactionError> {
  if outputs.len() > 16 {
    return Err(TransactionError::TooManyOutputs)?;
  }

  let masks: Vec<[u8; 32]> = outputs.iter().map(|commitment| commitment.mask.to_bytes()).collect();
  let amounts: Vec<u64> = outputs.iter().map(|commitment| commitment.amount).collect();
  let res;
  unsafe {
    let ptr = c_gen_bp(outputs.len() as u8, amounts.as_ptr(), masks.as_ptr());
    let len = ((ptr.read() as usize) << 8) + (ptr.add(1).read() as usize);
    res = deserialize(
      std::slice::from_raw_parts(ptr.add(2), len)
    ).expect("Couldn't deserialize Bulletproof from Monero");
    free(ptr);
  }

  Ok(res)
}
