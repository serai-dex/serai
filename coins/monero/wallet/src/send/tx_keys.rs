use core::ops::Deref;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};

use crate::{
  primitives::{keccak256, Commitment},
  ringct::EncryptedAmount,
  SharedKeyDerivations,
  send::{InternalPayment, SignableTransaction},
};

fn seeded_rng(
  dst: &'static [u8],
  outgoing_view_key: &Zeroizing<[u8; 32]>,
  output_keys: impl Iterator<Item = EdwardsPoint>,
) -> ChaCha20Rng {
  // Apply the DST
  let mut transcript = Zeroizing::new(vec![u8::try_from(dst.len()).unwrap()]);
  transcript.extend(dst);
  // Bind to the outgoing view key to prevent foreign entities from rebuilding the transcript
  transcript.extend(outgoing_view_key.as_slice());
  // Ensure uniqueness across transactions by binding to a use-once object
  // The output key is also binding to the output's key image, making this use-once
  for key in output_keys {
    transcript.extend(key.compress().to_bytes());
  }
  ChaCha20Rng::from_seed(keccak256(&transcript))
}

impl SignableTransaction {
  pub(crate) fn seeded_rng(&self, dst: &'static [u8]) -> ChaCha20Rng {
    seeded_rng(dst, &self.outgoing_view_key, self.inputs.iter().map(|(input, _)| input.key()))
  }

  fn has_payments_to_subaddresses(&self) -> bool {
    self.payments.iter().any(|payment| match payment {
      InternalPayment::Payment(addr, _) => addr.is_subaddress(),
      InternalPayment::Change(addr, view) => {
        if view.is_some() {
          // It should not be possible to construct a change specification to a subaddress with a
          // view key
          // TODO
          debug_assert!(!addr.is_subaddress());
        }
        addr.is_subaddress()
      }
    })
  }

  fn should_use_additional_keys(&self) -> bool {
    let has_payments_to_subaddresses = self.has_payments_to_subaddresses();
    if !has_payments_to_subaddresses {
      return false;
    }

    let has_change_view = self.payments.iter().any(|payment| match payment {
      InternalPayment::Payment(_, _) => false,
      InternalPayment::Change(_, view) => view.is_some(),
    });

    /*
      If sending to a subaddress, the shared key is not `rG` yet `rB`. Because of this, a
      per-subaddress shared key is necessary, causing the usage of additional keys.

      The one exception is if we're sending to a subaddress in a 2-output transaction. The second
      output, the change output, will attempt scanning the singular key `rB` with `v rB`. While we
      cannot calculate `r vB` with just `r` (as that'd require `vB` when we presumably only have
      `vG` when sending), since we do in fact have `v` (due to it being our own view key for our
      change output), we can still calculate the shared secret.
    */
    has_payments_to_subaddresses && !((self.payments.len() == 2) && has_change_view)
  }

  // Calculate the transaction keys used as randomness.
  fn transaction_keys(&self) -> (Zeroizing<Scalar>, Vec<Zeroizing<Scalar>>) {
    let mut rng = self.seeded_rng(b"transaction_keys");

    let tx_key = Zeroizing::new(Scalar::random(&mut rng));

    let mut additional_keys = vec![];
    if self.should_use_additional_keys() {
      for _ in 0 .. self.payments.len() {
        additional_keys.push(Zeroizing::new(Scalar::random(&mut rng)));
      }
    }
    (tx_key, additional_keys)
  }

  fn ecdhs(&self) -> Vec<Zeroizing<EdwardsPoint>> {
    let (tx_key, additional_keys) = self.transaction_keys();
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));
    let (tx_key_pub, additional_keys_pub) = self.transaction_keys_pub();
    debug_assert_eq!(additional_keys_pub.len(), additional_keys.len());

    let mut res = Vec::with_capacity(self.payments.len());
    for (i, payment) in self.payments.iter().enumerate() {
      let addr = payment.address();
      let key_to_use =
        if addr.is_subaddress() { additional_keys.get(i).unwrap_or(&tx_key) } else { &tx_key };

      let ecdh = match payment {
        // If we don't have the view key, use the key dedicated for this address (r A)
        InternalPayment::Payment(_, _) | InternalPayment::Change(_, None) => {
          Zeroizing::new(key_to_use.deref() * addr.view())
        }
        // If we do have the view key, use the commitment to the key (a R)
        InternalPayment::Change(_, Some(view)) => Zeroizing::new(view.deref() * tx_key_pub),
      };

      res.push(ecdh);
    }
    res
  }

  // Calculate the shared keys and the necessary derivations.
  pub(crate) fn shared_key_derivations(
    &self,
    key_images: &[EdwardsPoint],
  ) -> Vec<Zeroizing<SharedKeyDerivations>> {
    let ecdhs = self.ecdhs();

    let uniqueness = SharedKeyDerivations::uniqueness(&self.inputs(key_images));

    let mut res = Vec::with_capacity(self.payments.len());
    for (i, (payment, ecdh)) in self.payments.iter().zip(ecdhs).enumerate() {
      let addr = payment.address();
      res.push(SharedKeyDerivations::output_derivations(
        addr.is_guaranteed().then_some(uniqueness),
        ecdh,
        i,
      ));
    }
    res
  }

  // Calculate the payment ID XOR masks.
  pub(crate) fn payment_id_xors(&self) -> Vec<[u8; 8]> {
    let mut res = Vec::with_capacity(self.payments.len());
    for ecdh in self.ecdhs() {
      res.push(SharedKeyDerivations::payment_id_xor(ecdh));
    }
    res
  }

  // Calculate the transaction_keys' commitments.
  //
  // These depend on the payments. Commitments for payments to subaddresses use the spend key for
  // the generator.
  pub(crate) fn transaction_keys_pub(&self) -> (EdwardsPoint, Vec<EdwardsPoint>) {
    let (tx_key, additional_keys) = self.transaction_keys();
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));

    // The single transaction key uses the subaddress's spend key as its generator
    let has_payments_to_subaddresses = self.has_payments_to_subaddresses();
    let should_use_additional_keys = self.should_use_additional_keys();
    if has_payments_to_subaddresses && (!should_use_additional_keys) {
      debug_assert_eq!(additional_keys.len(), 0);

      let InternalPayment::Payment(addr, _) = self
        .payments
        .iter()
        .find(|payment| matches!(payment, InternalPayment::Payment(_, _)))
        .expect("payment to subaddress yet no payment")
      else {
        panic!("filtered payment wasn't a payment")
      };

      // TODO: Support subaddresses as change?
      debug_assert!(addr.is_subaddress());

      return (tx_key.deref() * addr.spend(), vec![]);
    }

    if should_use_additional_keys {
      let mut additional_keys_pub = vec![];
      for (additional_key, payment) in additional_keys.into_iter().zip(&self.payments) {
        let addr = payment.address();
        // TODO: Double check this against wallet2
        if addr.is_subaddress() {
          additional_keys_pub.push(additional_key.deref() * addr.spend());
        } else {
          additional_keys_pub.push(additional_key.deref() * ED25519_BASEPOINT_TABLE)
        }
      }
      return (tx_key.deref() * ED25519_BASEPOINT_TABLE, additional_keys_pub);
    }

    debug_assert!(!has_payments_to_subaddresses);
    debug_assert!(!should_use_additional_keys);
    (tx_key.deref() * ED25519_BASEPOINT_TABLE, vec![])
  }

  pub(crate) fn commitments_and_encrypted_amounts(
    &self,
    key_images: &[EdwardsPoint],
  ) -> Vec<(Commitment, EncryptedAmount)> {
    let shared_key_derivations = self.shared_key_derivations(key_images);

    let mut res = Vec::with_capacity(self.payments.len());
    for (payment, shared_key_derivations) in self.payments.iter().zip(shared_key_derivations) {
      let amount = match payment {
        InternalPayment::Payment(_, amount) => *amount,
        InternalPayment::Change(_, _) => {
          let inputs = self.inputs.iter().map(|input| input.0.commitment().amount).sum::<u64>();
          let payments = self
            .payments
            .iter()
            .filter_map(|payment| match payment {
              InternalPayment::Payment(_, amount) => Some(amount),
              InternalPayment::Change(_, _) => None,
            })
            .sum::<u64>();
          let fee = self.weight_and_fee().1;
          // Safe since the constructor checked this
          inputs - (payments + fee)
        }
      };
      let commitment = Commitment::new(shared_key_derivations.commitment_mask(), amount);
      let encrypted_amount = EncryptedAmount::Compact {
        amount: shared_key_derivations.compact_amount_encryption(amount),
      };
      res.push((commitment, encrypted_amount));
    }
    res
  }

  pub(crate) fn sum_output_masks(&self, key_images: &[EdwardsPoint]) -> Scalar {
    self
      .commitments_and_encrypted_amounts(key_images)
      .into_iter()
      .map(|(commitment, _)| commitment.mask)
      .sum()
  }
}
