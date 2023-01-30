use bitcoin::{hashes::hex::FromHex, consensus::encode, Txid, OutPoint};

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub output: OutPoint,
  pub amount: u64,
}

impl SpendableOutput {
  pub fn read<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
    let mut txid_buf = [0; 32];
    r.read_exact(&mut txid_buf)?;
    txid_buf.reverse();
    let tx_obj = Txid::from_hex(hex::encode(txid_buf).as_str()).unwrap();
    let mut vout_buff = [0; 4];
    r.read_exact(&mut vout_buff)?;
    let vout = u32::from_le_bytes(vout_buff);
    let mut amount_buff = [0; 8];
    r.read_exact(&mut amount_buff)?;
    let amount = u64::from_le_bytes(amount_buff);
    Ok(SpendableOutput { output: OutPoint { txid: tx_obj, vout }, amount })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = encode::serialize(&self.output);
    res.extend(encode::serialize(&self.amount));
    res
  }
}
