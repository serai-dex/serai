use std_shims::io;

use zeroize::Zeroize;

use crate::{
  ringct::RctProofs,
  transaction::{Input, Timelock, Transaction},
  send::SignableTransaction,
};

/// The eventual output of a SignableTransaction.
///
/// If a SignableTransaction is signed and published on-chain, it will create a Transaction
/// identifiable to whoever else has the same SignableTransaction (with the same outgoing view
/// key). This structure enables checking if a Transaction is in fact such an output, as it can.
///
/// Since Monero is a privacy coin without outgoing view keys, this only performs a fuzzy match.
/// The fuzzy match executes over the outputs and associated data necessary to work with the
/// outputs (the transaction randomness, ciphertexts). This transaction does not check if the
/// inputs intended to be spent where actually the inputs spent (as infeasible).
///
/// The transaction randomness does bind to the inputs intended to be spent, so an on-chain
/// transaction will not match for multiple `Eventuality`s unless the `SignableTransaction`s they
/// were built from were in conflict (and their intended transactions cannot simultaneously exist
/// on-chain).
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Eventuality(SignableTransaction);

impl From<SignableTransaction> for Eventuality {
  fn from(tx: SignableTransaction) -> Eventuality {
    Eventuality(tx)
  }
}

impl Eventuality {
  /// Return the `extra` field any transaction following this intent would use.
  ///
  /// This enables building a HashMap of Extra -> Eventuality for efficiently fetching the
  /// `Eventuality` an on-chain transaction may complete.
  ///
  /// This extra is cryptographically bound to the inputs intended to be spent. If the
  /// `SignableTransaction`s the `Eventuality`s are built from are not in conflict (their intended
  /// transactions can simultaneously exist on-chain), then each extra will only have a single
  /// Eventuality associated (barring a cryptographic problem considered hard failing).
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
    if tx.prefix().additional_timelock != Timelock::None {
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

  /// Write the Eventuality.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.0.write(w)
  }

  /// Serialize the Eventuality to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  /// Read a Eventuality.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Eventuality> {
    Ok(Eventuality(SignableTransaction::read(r)?))
  }
}
