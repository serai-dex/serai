use std_shims::{
  prelude::*,
  collections::HashMap,
  io::{self, Read, Write},
};

use k256::{
  elliptic_curve::{
    group::{ff::PrimeField as _, prime::PrimeCurveAffine as _},
    point::AffineCoordinates as _,
  },
  Scalar, ProjectivePoint,
};

use frost::{
  curve::{GroupIo as _, Secp256k1},
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

fn unspendable_script_path(x: [u8; 32]) -> Scalar {
  let tweak = TapTweakHash::hash(&x).to_scalar();
  Scalar::from_repr(tweak.to_be_bytes().into())
    .expect("`tweak` wasn't mutual between `secp256k1` and `k256`")
}

/// Add an unspendable script path to the keys.
///
/// This follows
/// [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation).
///
/// This has a neligible probability of returning keys whose group key is the point at infinity and
/// will be unusable accordingly.
pub(crate) fn tweak_with_unspendable_script_path(
  keys: ThresholdKeys<Secp256k1>,
) -> ThresholdKeys<Secp256k1> {
  let key = keys.group_key().to_affine();
  // This `keys` corresponds to the `internal_key` for a `derived_key` (the input `keys`)
  let keys = if bool::from(key.y_is_odd()) {
    keys.scale(-Scalar::ONE).expect("scaling keys by 1 or -1 yet interpreted as 0?")
  } else {
    keys
  };
  let key = key.x();

  keys.offset(unspendable_script_path(key.into()))
}

/// Return the Taproot address payload for a public key.
///
/// This will only consider the point's `x` coordinate, as BIP-340 does. That means this point
/// (and its discrete logarithm) may have to be negated before actually being further used.
///
/// This will add tweak the key with an unspendable script path, following the method described in
/// [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation).
///
/// If the resulting public key would be the identity point, this will return `None`.
pub fn address(key: ProjectivePoint) -> Option<ScriptBuf> {
  let (original_x, even_original_key) = {
    let affine = key.to_affine();
    if bool::from(affine.is_identity()) {
      None?;
    }
    (affine.x(), if bool::from(affine.y_is_odd()) { -key } else { key })
  };

  // The key, with an unspendable script path
  let key =
    even_original_key + (ProjectivePoint::GENERATOR * unspendable_script_path(original_x.into()));

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
  /// The scalar offset this output is associated with.
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
///
/// The scalar offsets are used to derive child keys from the root key. All derived keys are used
/// with [`bitcoin_serai::wallet::address`] to create addresses with unspendable script paths. The
/// process of adding an unspendable script path will "tweak" the keys, which in practice means
/// applying a second scalar offset. This is handled internally and opaquely so the user does not
/// have to be aware of this detail.
#[derive(Clone, Debug)]
pub struct Scanner {
  key: ProjectivePoint,
  scripts: HashMap<ScriptBuf, Scalar>,
}

impl Scanner {
  /// Construct a Scanner for a key.
  ///
  /// This will return `None` if this key cannot be scanned for.
  pub fn new(key: ProjectivePoint) -> Option<Scanner> {
    let mut scripts = HashMap::new();
    scripts.insert(address(key)?, Scalar::ZERO);
    Some(Scanner { key, scripts })
  }

  /// Register an offset to scan for.
  ///
  /// This will return `None` if the address corresponding to the registered offset cannot be
  /// scanned for (due to being invalid) or if it was already registered within the scanner.
  // TODO: `RegisterError`
  pub fn register_offset(&mut self, offset: Scalar) -> Option<()> {
    let script = address(self.key + (ProjectivePoint::GENERATOR * offset))?;
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
