use std_shims::{
  prelude::*,
  collections::HashMap,
  io::{self, Read, Write},
};

use k256::{
  elliptic_curve::{group::prime::PrimeCurveAffine as _, point::AffineCoordinates as _},
  Scalar, ProjectivePoint,
};

use frost::{
  curve::{WrappedGroup, GroupIo as _, Secp256k1},
  ThresholdKeys,
};

use bitcoin::{
  hashes::Hash as _,
  key::{XOnlyPublicKey, TweakedPublicKey},
  TapTweakHash,
  consensus::encode::{Decodable as _, serialize},
  OutPoint, ScriptBuf, TxOut, Transaction, Block,
};

mod send;
pub use send::*;

/// Tweak keys to ensure they're safe to use with Taproot.
///
/// This adds an unspendable script path to the key, preventing any outputs received to this key
/// from being spent via a script.
///
/// This has a neligible probability of returning keys whose group key is the point at infinity and
/// will be unusable accordingly.
pub fn tweak_keys(keys: ThresholdKeys<Secp256k1>) -> ThresholdKeys<Secp256k1> {
  use k256::elliptic_curve::{
    bigint::{Encoding as _, U256},
    ops::Reduce as _,
    group::GroupEncoding as _,
  };

  // Adds an unspendable script path per
  // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23
  let tweak_hash = TapTweakHash::hash(&keys.group_key().to_bytes().as_slice()[1 ..]);
  /*
    https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#cite_ref-13-0 states how the
    bias is negligible. This reduction shouldn't ever occur, yet if it did, the script path would
    be unusable due to a check the script path hash is less than the order. That doesn't impact us
    as we don't want the script path to be usable.
  */
  keys.offset(<Secp256k1 as WrappedGroup>::F::reduce(U256::from_be_bytes(
    *tweak_hash.to_raw_hash().as_ref(),
  )))
}

/// Return the Taproot address payload for a public key.
///
/// This will only consider the point's `x` coordinate, as BIP-340 does. That means this point
/// (and its discrete logarithm) may have to be negated before actually being further used.
///
/// If the point is the identity, this will return `None`.
pub fn p2tr_script_buf(key: ProjectivePoint) -> Option<ScriptBuf> {
  let key = key.to_affine();
  if bool::from(key.is_identity()) {
    None?;
  }
  Some(ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
    XOnlyPublicKey::from_slice(key.x().as_ref())
      .expect("`x` coordinate was not 32 bytes and on-curve"),
  )))
}

/// A spendable output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceivedOutput {
  /// The scalar offset to obtain the key usable to spend this output.
  offset: Scalar,
  /// The output to spend.
  output: TxOut,
  /// The TX ID and vout of the output to spend.
  outpoint: OutPoint,
}

impl ReceivedOutput {
  /// The offset for this output.
  pub fn offset(&self) -> Scalar {
    self.offset
  }

  /// The underlying output for this received output.
  pub fn output(&self) -> &TxOut {
    &self.output
  }

  /// The outpoint for this output.
  pub fn outpoint(&self) -> &OutPoint {
    &self.outpoint
  }

  /// The value of this output.
  pub fn value(&self) -> u64 {
    self.output.value.to_sat()
  }

  /// Read a [`ReceivedOutput`] from a generic satisfying [`Read`].
  pub fn read<R: Read>(r: &mut R) -> io::Result<ReceivedOutput> {
    let offset = Secp256k1::read_F(r)?;

    struct BitcoinRead<R: Read>(R);
    impl<R: Read> bitcoin::io::Read for BitcoinRead<R> {
      fn read(&mut self, buf: &mut [u8]) -> bitcoin::io::Result<usize> {
        self
          .0
          .read(buf)
          .map_err(|e| bitcoin::io::Error::new(bitcoin::io::ErrorKind::Other, e.to_string()))
      }
    }
    let mut r = BitcoinRead(r);

    let output = TxOut::consensus_decode(&mut r).map_err(|_| io::Error::other("invalid TxOut"))?;
    let outpoint =
      OutPoint::consensus_decode(&mut r).map_err(|_| io::Error::other("invalid OutPoint"))?;
    Ok(ReceivedOutput { offset, output, outpoint })
  }

  /// Write a [`ReceivedOutput`] to a generic satisfying [`Write`].
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.offset.to_bytes())?;
    w.write_all(&serialize(&self.output))?;
    w.write_all(&serialize(&self.outpoint))
  }

  /// Serialize a [`ReceivedOutput`] to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::new();
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
  /// This will return `None` if this key can't be scanned for.
  pub fn new(key: ProjectivePoint) -> Option<Scanner> {
    let mut scripts = HashMap::new();
    scripts.insert(p2tr_script_buf(key)?, Scalar::ZERO);
    Some(Scanner { key, scripts })
  }

  /// Register an offset to scan for.
  ///
  /// This will return `None` if the key corresponding to the registered offset cannot be scanned
  /// for or if it was already registered within the scanner.
  ///
  /// The offsets registered must be securely generated. Arbitrary offsets may introduce a script
  /// path into the output, allowing the output to be spent by satisfaction of an arbitrary script
  /// (not by the signature of the key).
  // TODO: `RegisterError`
  pub fn register_offset(&mut self, offset: Scalar) -> Option<()> {
    let script = p2tr_script_buf(self.key + (ProjectivePoint::GENERATOR * offset))?;
    if self.scripts.contains_key(&script) {
      None?;
    }
    self.scripts.insert(script, offset);
    Some(())
  }

  /// Scan a transaction.
  pub fn scan_transaction(&self, tx: &Transaction) -> Vec<ReceivedOutput> {
    let mut res = Vec::new();
    for (vout, output) in tx.output.iter().enumerate() {
      // If the vout index exceeds 2**32, stop scanning outputs
      let Ok(vout) = u32::try_from(vout) else { break };

      if let Some(offset) = self.scripts.get(&output.script_pubkey) {
        res.push(ReceivedOutput {
          offset: *offset,
          output: output.clone(),
          outpoint: OutPoint::new(tx.compute_txid(), vout),
        });
      }
    }
    res
  }

  /// Scan a block.
  ///
  /// This will also scan the coinbase transaction which is bound by maturity. If received outputs
  /// must be immediately spendable, a post-processing pass is needed to remove those outputs.
  /// Alternatively, [`scan_transaction`] can be called on `block.txdata[1 ..]`.
  pub fn scan_block(&self, block: &Block) -> Vec<ReceivedOutput> {
    let mut res = Vec::new();
    for tx in &block.txdata {
      res.extend(self.scan_transaction(tx));
    }
    res
  }
}
