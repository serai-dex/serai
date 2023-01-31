use std::io;

use bitcoin::{
  consensus::encode::{Encodable, Decodable, serialize},
  TxOut, OutPoint,
};

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub output: TxOut,
  pub outpoint: OutPoint,
}

impl SpendableOutput {
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<SpendableOutput> {
    Ok(SpendableOutput {
      output: TxOut::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid TxOut"))?,
      outpoint: OutPoint::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid OutPoint"))?,
    })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = serialize(&self.output);
    self.outpoint.consensus_encode(&mut res).unwrap();
    res
  }
}
