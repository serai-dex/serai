use bitcoin::{Txid};
use bitcoin_hashes::hex::FromHex;

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub txid: Txid,//[u8;32],
  pub vout: u32,
  pub amount:u64,
}

impl SpendableOutput {
  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
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
    Ok(SpendableOutput { txid: tx_obj, vout: vout, amount: amount })
  }
  
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = self.txid.to_vec();
    res.extend(self.vout.to_le_bytes().to_vec());
    res.extend(self.amount.to_le_bytes().to_vec());
    res
  }
}