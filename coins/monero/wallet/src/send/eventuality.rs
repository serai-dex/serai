use zeroize::Zeroize;

use crate::{
  ringct::RctProofs,
  transaction::{Input, Timelock, Transaction},
  send::SignableTransaction,
};

/// The eventual output of a SignableTransaction.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Eventuality(SignableTransaction);

impl From<SignableTransaction> for Eventuality {
  fn from(tx: SignableTransaction) -> Eventuality {
    Eventuality(tx)
  }
}

impl Eventuality {
  /// Return the extra any TX following this intent would use.
  ///
  /// This enables building a HashMap of Extra -> Eventuality for efficiently checking if an
  /// on-chain transaction may match one of several eventuality.
  ///
  /// This extra is cryptographically bound to the set of outputs intended to be spent as inputs.
  /// This means two SignableTransactions for the same set of payments will have distinct extras.
  /// This does not guarantee the matched transaction actually spent the intended outputs.
  pub fn extra(&self) -> Vec<u8> {
    self.0.extra()
  }

  /// Return if this TX matches the SignableTransaction this was created from.
  ///
  /// Matching the SignableTransaction means this transaction created the expected outputs, they're
  /// scannable, they're not locked, and this transaction claims to use the intended inputs (though
  /// this is not guaranteed). This 'claim' is evaluated by this transaction using the transaction
  /// keys derived from the intended inputs. This ensures two SignableTransactions with the same
  /// intended payments don't match for each other's `Eventuality`s (as they'll have distinct
  /// inputs intended).
  #[must_use]
  pub fn matches(&self, tx: &Transaction) -> bool {
    // Verify extra
    if self.0.extra() != tx.prefix().extra {
      return false;
    }

    // Also ensure no timelock was set
    if tx.prefix().timelock != Timelock::None {
      return false;
    }

    // Check the amount of inputs aligns
    if tx.prefix().inputs.len() != self.0.inputs.len() {
      return false;
    }
    // Collect the key images used by this transaction
    let Ok(key_images) = tx
      .prefix()
      .inputs
      .iter()
      .map(|input| match input {
        Input::Gen(_) => Err(()),
        Input::ToKey { key_image, .. } => Ok(*key_image),
      })
      .collect::<Result<Vec<_>, _>>()
    else {
      return false;
    };

    // Check the outputs
    if self.0.outputs(&key_images) != tx.prefix().outputs {
      return false;
    }

    // Check the encrypted amounts and commitments
    let commitments_and_encrypted_amounts = self.0.commitments_and_encrypted_amounts(&key_images);
    let Transaction::V2 { proofs: Some(RctProofs { ref base, .. }), .. } = tx else {
      return false;
    };
    if base.commitments !=
      commitments_and_encrypted_amounts
        .iter()
        .map(|(commitment, _)| commitment.calculate())
        .collect::<Vec<_>>()
    {
      return false;
    }
    if base.encrypted_amounts !=
      commitments_and_encrypted_amounts.into_iter().map(|(_, amount)| amount).collect::<Vec<_>>()
    {
      return false;
    }

    true
  }

  /*
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.protocol.write(w)?;
    write_raw_vec(write_byte, self.r_seed.as_ref(), w)?;
    write_vec(write_point, &self.inputs, w)?;

    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(payment, need_dummy_payment_id) => {
          w.write_all(&[0])?;
          write_vec(write_byte, payment.0.to_string().as_bytes(), w)?;
          w.write_all(&payment.1.to_le_bytes())?;
          if *need_dummy_payment_id {
            w.write_all(&[1])
          } else {
            w.write_all(&[0])
          }
        }
        InternalPayment::Change(change, change_view) => {
          w.write_all(&[1])?;
          write_vec(write_byte, change.0.to_string().as_bytes(), w)?;
          w.write_all(&change.1.to_le_bytes())?;
          if let Some(view) = change_view.as_ref() {
            w.write_all(&[1])?;
            write_scalar(view, w)
          } else {
            w.write_all(&[0])
          }
        }
      }
    }
    write_vec(write_payment, &self.payments, w)?;

    write_vec(write_byte, &self.extra, w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    self.write(&mut buf).unwrap();
    buf
  }

  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Eventuality> {
    fn read_address<R: io::Read>(r: &mut R) -> io::Result<MoneroAddress> {
      String::from_utf8(read_vec(read_byte, r)?)
        .ok()
        .and_then(|str| MoneroAddress::from_str_raw(&str).ok())
        .ok_or_else(|| io::Error::other("invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment(
          (read_address(r)?, read_u64(r)?),
          match read_byte(r)? {
            0 => false,
            1 => true,
            _ => Err(io::Error::other("invalid need additional"))?,
          },
        ),
        1 => InternalPayment::Change(
          (read_address(r)?, read_u64(r)?),
          match read_byte(r)? {
            0 => None,
            1 => Some(Zeroizing::new(read_scalar(r)?)),
            _ => Err(io::Error::other("invalid change view"))?,
          },
        ),
        _ => Err(io::Error::other("invalid payment"))?,
      })
    }

    Ok(Eventuality {
      protocol: RctType::read(r)?,
      r_seed: Zeroizing::new(read_bytes::<_, 32>(r)?),
      inputs: read_vec(read_point, r)?,
      payments: read_vec(read_payment, r)?,
      extra: read_vec(read_byte, r)?,
    })
  }
  */
}
