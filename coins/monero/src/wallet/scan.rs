use std::io::Cursor;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar, edwards::EdwardsPoint};

use crate::{
  Commitment,
  serialize::{read_byte, read_u32, read_u64, read_bytes, read_scalar, read_point},
  transaction::{Timelock, Transaction},
  wallet::{PaymentId, Extra, Scanner, uniqueness, shared_key, amount_decryption, commitment_mask},
};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendableOutput {
  pub tx: [u8; 32],
  pub o: u8,

  pub key: EdwardsPoint,
  // Absolute difference between the spend key and the key in this output, inclusive of any
  // subaddress offset
  pub key_offset: Scalar,
  pub commitment: Commitment,

  // Metadata to know how to process this output

  // Does not have to be an Option since the 0 subaddress is the main address
  pub subaddress: (u32, u32),
  // Can be an Option, as extra doesn't necessarily have a payment ID, yet all Monero TXs should
  // have this
  // This will be gibberish if the payment ID wasn't intended for the recipient
  // This will be [0xff; 8] if the transaction didn't have a payment ID
  // 0xff was chosen as it'd be distinct from [0; 8], enabling atomically incrementing IDs (though
  // they should be randomly generated)
  pub payment_id: [u8; 8],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(Timelock, Vec<SpendableOutput>);
impl Timelocked {
  pub fn timelock(&self) -> Timelock {
    self.0
  }

  pub fn not_locked(&self) -> Vec<SpendableOutput> {
    if self.0 == Timelock::None {
      return self.1.clone();
    }
    vec![]
  }

  /// Returns None if the Timelocks aren't comparable. Returns Some(vec![]) if none are unlocked
  pub fn unlocked(&self, timelock: Timelock) -> Option<Vec<SpendableOutput>> {
    // If the Timelocks are comparable, return the outputs if they're now unlocked
    self.0.partial_cmp(&timelock).filter(|_| self.0 <= timelock).map(|_| self.1.clone())
  }

  pub fn ignore_timelock(&self) -> Vec<SpendableOutput> {
    self.1.clone()
  }
}

impl SpendableOutput {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(32 + 1 + 32 + 32 + 40);

    res.extend(&self.tx);
    res.push(self.o);

    res.extend(self.key.compress().to_bytes());
    res.extend(self.key_offset.to_bytes());
    res.extend(self.commitment.mask.to_bytes());
    res.extend(self.commitment.amount.to_le_bytes());

    res.extend(self.subaddress.0.to_le_bytes());
    res.extend(self.subaddress.1.to_le_bytes());
    res.extend(self.payment_id);

    res
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
    Ok(SpendableOutput {
      tx: read_bytes(r)?,
      o: read_byte(r)?,

      key: read_point(r)?,
      key_offset: read_scalar(r)?,
      commitment: Commitment::new(read_scalar(r)?, read_u64(r)?),

      subaddress: (read_u32(r)?, read_u32(r)?),
      payment_id: read_bytes(r)?,
    })
  }
}

impl Scanner {
  pub fn scan(&self, tx: &Transaction) -> Timelocked {
    let extra = Extra::deserialize(&mut Cursor::new(&tx.prefix.extra));
    let keys;
    let extra = if let Ok(extra) = extra {
      keys = extra.keys();
      extra
    } else {
      return Timelocked(tx.prefix.timelock, vec![]);
    };
    let payment_id = extra.payment_id();

    let mut res = vec![];
    for (o, output) in tx.prefix.outputs.iter().enumerate() {
      for key in &keys {
        let (view_tag, key_offset, payment_id_xor) = shared_key(
          if self.guaranteed { Some(uniqueness(&tx.prefix.inputs)) } else { None },
          &self.pair.view,
          key,
          o,
        );

        let payment_id =
          if let Some(PaymentId::Encrypted(id)) = payment_id.map(|id| id ^ payment_id_xor) {
            id
          } else {
            [0xff; 8]
          };

        if let Some(actual_view_tag) = output.view_tag {
          if actual_view_tag != view_tag {
            continue;
          }
        }

        // P - shared == spend
        let subaddress = self
          .subaddresses
          .get(&(output.key - (&key_offset * &ED25519_BASEPOINT_TABLE)).compress());
        if subaddress.is_none() {
          continue;
        }

        // Since we've found an output to us, get its amount
        let mut commitment = Commitment::zero();

        // Miner transaction
        if output.amount != 0 {
          commitment.amount = output.amount;
        // Regular transaction
        } else {
          let amount = match tx.rct_signatures.base.ecdh_info.get(o) {
            Some(amount) => amount_decryption(*amount, key_offset),
            // This should never happen, yet it may be possible with miner transactions?
            // Using get just decreases the possibility of a panic and lets us move on in that case
            None => break,
          };

          // Rebuild the commitment to verify it
          commitment = Commitment::new(commitment_mask(key_offset), amount);
          // If this is a malicious commitment, move to the next output
          // Any other R value will calculate to a different spend key and are therefore ignorable
          if Some(&commitment.calculate()) != tx.rct_signatures.base.commitments.get(o) {
            break;
          }
        }

        if commitment.amount != 0 {
          res.push(SpendableOutput {
            tx: tx.hash(),
            o: o.try_into().unwrap(),

            key: output.key,
            key_offset: key_offset + self.pair.subaddress(*subaddress.unwrap()),
            commitment,

            subaddress: (0, 0),
            payment_id,
          });
        }
        // Break to prevent public keys from being included multiple times, triggering multiple
        // inclusions of the same output
        break;
      }
    }

    Timelocked(tx.prefix.timelock, res)
  }
}
