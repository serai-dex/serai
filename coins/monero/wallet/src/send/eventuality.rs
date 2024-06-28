use std_shims::io;

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

  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.0.write(w)
  }

  pub fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Eventuality> {
    Ok(Eventuality(SignableTransaction::read(r)?))
  }
}
