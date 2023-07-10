use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use k256::{
  elliptic_curve::sec1::{Tag, ToEncodedPoint},
  Scalar, ProjectivePoint,
};
use frost::{
  curve::{Ciphersuite, Secp256k1},
  ThresholdKeys,
};

use bitcoin::{
  consensus::encode::{Decodable, serialize},
  key::TweakedPublicKey,
  OutPoint, ScriptBuf, TxOut, Transaction, Block, Network, Address,
};

use crate::crypto::{x_only, make_even};

mod send;
pub use send::*;

/// Tweak keys to ensure they're usable with Bitcoin.
pub fn tweak_keys(keys: &ThresholdKeys<Secp256k1>) -> ThresholdKeys<Secp256k1> {
  let (_, offset) = make_even(keys.group_key());
  keys.offset(Scalar::from(offset))
}

/// Return the Taproot address for a public key.
pub fn address(network: Network, key: ProjectivePoint) -> Option<Address> {
  if key.to_encoded_point(true).tag() != Tag::CompressedEvenY {
    return None;
  }

  Some(Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(x_only(&key)), network))
}

/// A spendable output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceivedOutput {
  // The scalar offset to obtain the key usable to spend this output.
  offset: Scalar,
  // The output to spend.
  output: TxOut,
  // The TX ID and vout of the output to spend.
  outpoint: OutPoint,
}

impl ReceivedOutput {
  /// The offset for this output.
  pub fn offset(&self) -> Scalar {
    self.offset
  }

  /// The outpoint for this output.
  pub fn outpoint(&self) -> &OutPoint {
    &self.outpoint
  }

  /// The value of this output.
  pub fn value(&self) -> u64 {
    self.output.value
  }

  /// Read a ReceivedOutput from a generic satisfying Read.
  pub fn read<R: Read>(r: &mut R) -> io::Result<ReceivedOutput> {
    Ok(ReceivedOutput {
      offset: Secp256k1::read_F(r)?,
      output: TxOut::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid TxOut"))?,
      outpoint: OutPoint::consensus_decode(r)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid OutPoint"))?,
    })
  }

  /// Write a ReceivedOutput to a generic satisfying Write.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.offset.to_bytes())?;
    w.write_all(&serialize(&self.output))?;
    w.write_all(&serialize(&self.outpoint))
  }

  /// Serialize a ReceivedOutput to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }
}

/// A transaction scanner capable of being used with HDKD schemes.
#[derive(Clone, Debug)]
pub struct Scanner {
  key: ProjectivePoint,
  scripts: HashMap<ScriptBuf, Scalar>,
}

impl Scanner {
  /// Construct a Scanner for a key.
  ///
  /// Returns None if this key can't be scanned for.
  pub fn new(key: ProjectivePoint) -> Option<Scanner> {
    let mut scripts = HashMap::new();
    // Uses Network::Bitcoin since network is irrelevant here
    scripts.insert(address(Network::Bitcoin, key)?.script_pubkey(), Scalar::ZERO);
    Some(Scanner { key, scripts })
  }

  /// Register an offset to scan for.
  ///
  /// Due to Bitcoin's requirement that points are even, not every offset may be used.
  /// If an offset isn't usable, it will be incremented until it is. If this offset is already
  /// present, None is returned. Else, Some(offset) will be, with the used offset.
  pub fn register_offset(&mut self, mut offset: Scalar) -> Option<Scalar> {
    // This loop will terminate as soon as an even point is found, with any point having a ~50%
    // chance of being even
    // That means this should terminate within a very small amount of iterations
    loop {
      match address(Network::Bitcoin, self.key + (ProjectivePoint::GENERATOR * offset)) {
        Some(address) => {
          let script = address.script_pubkey();
          if self.scripts.contains_key(&script) {
            None?;
          }
          self.scripts.insert(script, offset);
          return Some(offset);
        }
        None => offset += Scalar::ONE,
      }
    }
  }

  /// Scan a transaction.
  pub fn scan_transaction(&self, tx: &Transaction) -> Vec<ReceivedOutput> {
    let mut res = vec![];
    for (vout, output) in tx.output.iter().enumerate() {
      // If the vout index exceeds 2**32, stop scanning outputs
      let Ok(vout) = u32::try_from(vout) else {
        break
      };

      if let Some(offset) = self.scripts.get(&output.script_pubkey) {
        res.push(ReceivedOutput {
          offset: *offset,
          output: output.clone(),
          outpoint: OutPoint::new(tx.txid(), vout),
        });
      }
    }
    res
  }

  /// Scan a block.
  ///
  /// This will also scan the coinbase transaction which is bound by maturity. If received outputs
  /// must be immediately spendable, a post-processing pass is needed to remove those outputs.
  /// Alternatively, scan_transaction can be called on `block.txdata[1 ..]`.
  pub fn scan_block(&self, block: &Block) -> Vec<ReceivedOutput> {
    let mut res = vec![];
    for tx in &block.txdata {
      res.extend(self.scan_transaction(tx));
    }
    res
  }
}
