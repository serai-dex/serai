use bitcoin::{Txid, OutPoint, consensus::encode};
use bitcoin_hashes::hex::FromHex;

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub output: OutPoint,
  pub amount: u64,
}

impl SpendableOutput {
  pub fn read<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
    let mut txid_buff = [0; 32];
    r.read(&mut txid_buff)?;
    txid_buff.reverse();
    let tx_obj = Txid::from_hex(hex::encode(&txid_buff).as_str()).unwrap();
    let mut vout_buff = [0; 4];
    r.read(&mut vout_buff)?;
    let vout = u32::from_le_bytes(vout_buff);
    let mut amount_buff = [0; 8];
    r.read(&mut amount_buff)?;
    let amount = u64::from_le_bytes(amount_buff);
    Ok(SpendableOutput { output: OutPoint { txid: tx_obj, vout: vout }, amount: amount })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = encode::serialize(&self.output);
    res.extend(encode::serialize(&self.amount));
    res
  }
}
