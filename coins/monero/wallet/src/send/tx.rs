use std_shims::{vec, vec::Vec};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
  Scalar, EdwardsPoint,
};

use crate::{
  io::{varint_len, write_varint},
  primitives::Commitment,
  ringct::{
    clsag::Clsag, bulletproofs::Bulletproof, EncryptedAmount, RctType, RctBase, RctPrunable,
    RctProofs,
  },
  transaction::{Input, Output, Timelock, TransactionPrefix, Transaction},
  extra::{ARBITRARY_DATA_MARKER, PaymentId, ExtraField, Extra},
  send::{InternalPayment, SignableTransaction, SignableTransactionWithKeyImages},
};

impl SignableTransaction {
  // Output the inputs for this transaction.
  pub(crate) fn inputs(&self, key_images: &[EdwardsPoint]) -> Vec<Input> {
    debug_assert_eq!(self.inputs.len(), key_images.len());

    let mut res = Vec::with_capacity(self.inputs.len());
    for ((_, decoys), key_image) in self.inputs.iter().zip(key_images) {
      res.push(Input::ToKey {
        amount: None,
        key_offsets: decoys.offsets().to_vec(),
        key_image: *key_image,
      });
    }
    res
  }

  // Output the outputs for this transaction.
  pub(crate) fn outputs(&self, key_images: &[EdwardsPoint]) -> Vec<Output> {
    let shared_key_derivations = self.shared_key_derivations(key_images);
    debug_assert_eq!(self.payments.len(), shared_key_derivations.len());

    let mut res = Vec::with_capacity(self.payments.len());
    for (payment, shared_key_derivations) in self.payments.iter().zip(&shared_key_derivations) {
      let key =
        (&shared_key_derivations.shared_key * ED25519_BASEPOINT_TABLE) + payment.address().spend();
      res.push(Output {
        key: key.compress(),
        amount: None,
        view_tag: (match self.rct_type {
          RctType::ClsagBulletproof => false,
          RctType::ClsagBulletproofPlus => true,
          _ => panic!("unsupported RctType"),
        })
        .then_some(shared_key_derivations.view_tag),
      });
    }
    res
  }

  // Calculate the TX extra for this transaction.
  pub(crate) fn extra(&self) -> Vec<u8> {
    let (tx_key, additional_keys) = self.transaction_keys_pub();
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));
    let payment_id_xors = self.payment_id_xors();
    debug_assert_eq!(self.payments.len(), payment_id_xors.len());

    let amount_of_keys = 1 + additional_keys.len();
    let mut extra = Extra::new(tx_key, additional_keys);

    if let Some((id, id_xor)) =
      self.payments.iter().zip(&payment_id_xors).find_map(|(payment, payment_id_xor)| {
        payment.address().payment_id().map(|id| (id, payment_id_xor))
      })
    {
      let id = (u64::from_le_bytes(id) ^ u64::from_le_bytes(*id_xor)).to_le_bytes();
      let mut id_vec = Vec::with_capacity(1 + 8);
      PaymentId::Encrypted(id).write(&mut id_vec).unwrap();
      extra.push(ExtraField::Nonce(id_vec));
    } else {
      // If there's no payment ID, we push a dummy (as wallet2 does) if there's only one payment
      if (self.payments.len() == 2) &&
        self.payments.iter().any(|payment| matches!(payment, InternalPayment::Change(_, _)))
      {
        let (_, payment_id_xor) = self
          .payments
          .iter()
          .zip(&payment_id_xors)
          .find(|(payment, _)| matches!(payment, InternalPayment::Payment(_, _)))
          .expect("multiple change outputs?");
        let mut id_vec = Vec::with_capacity(1 + 8);
        // The dummy payment ID is [0; 8], which when xor'd with the mask, is just the mask
        PaymentId::Encrypted(*payment_id_xor).write(&mut id_vec).unwrap();
        extra.push(ExtraField::Nonce(id_vec));
      }
    }

    // Include data if present
    for part in &self.data {
      let mut arb = vec![ARBITRARY_DATA_MARKER];
      arb.extend(part);
      extra.push(ExtraField::Nonce(arb));
    }

    let mut serialized = Vec::with_capacity(32 * amount_of_keys);
    extra.write(&mut serialized).unwrap();
    serialized
  }

  pub(crate) fn weight_and_necessary_fee(&self) -> (usize, u64) {
    /*
      This transaction is variable length to:
        - The decoy offsets (fixed)
        - The TX extra (variable to key images, requiring an interactive protocol)

      Thankfully, the TX extra *length* is fixed. Accordingly, we can calculate the inevitable TX's
      weight at this time with a shimmed transaction.
    */
    let base_weight = {
      let mut key_images = Vec::with_capacity(self.inputs.len());
      let mut clsags = Vec::with_capacity(self.inputs.len());
      let mut pseudo_outs = Vec::with_capacity(self.inputs.len());
      for _ in &self.inputs {
        key_images.push(ED25519_BASEPOINT_POINT);
        clsags.push(Clsag {
          D: ED25519_BASEPOINT_POINT,
          s: vec![
            Scalar::ZERO;
            match self.rct_type {
              RctType::ClsagBulletproof => 11,
              RctType::ClsagBulletproofPlus => 16,
              _ => unreachable!("unsupported RCT type"),
            }
          ],
          c1: Scalar::ZERO,
        });
        pseudo_outs.push(ED25519_BASEPOINT_POINT);
      }
      let mut encrypted_amounts = Vec::with_capacity(self.payments.len());
      let mut bp_commitments = Vec::with_capacity(self.payments.len());
      let mut commitments = Vec::with_capacity(self.payments.len());
      for _ in &self.payments {
        encrypted_amounts.push(EncryptedAmount::Compact { amount: [0; 8] });
        bp_commitments.push(Commitment::zero());
        commitments.push(ED25519_BASEPOINT_POINT);
      }

      let padded_log2 = {
        let mut log2_find = 0;
        while (1 << log2_find) < self.payments.len() {
          log2_find += 1;
        }
        log2_find
      };
      // This is log2 the padded amount of IPA rows
      // We have 64 rows per commitment, so we need 64 * c IPA rows
      // We rewrite this as 2**6 * c
      // By finding the padded log2 of c, we get 2**6 * 2**p
      // This declares the log2 to be 6 + p
      let lr_len = 6 + padded_log2;

      let bulletproof = match self.rct_type {
        RctType::ClsagBulletproof => {
          let mut bp = Vec::with_capacity(((9 + (2 * lr_len)) * 32) + 2);
          let push_point = |bp: &mut Vec<u8>| {
            bp.push(1);
            bp.extend([0; 31]);
          };
          let push_scalar = |bp: &mut Vec<u8>| bp.extend([0; 32]);
          for _ in 0 .. 4 {
            push_point(&mut bp);
          }
          for _ in 0 .. 2 {
            push_scalar(&mut bp);
          }
          for _ in 0 .. 2 {
            write_varint(&lr_len, &mut bp).unwrap();
            for _ in 0 .. lr_len {
              push_point(&mut bp);
            }
          }
          for _ in 0 .. 3 {
            push_scalar(&mut bp);
          }
          Bulletproof::read(&mut bp.as_slice()).expect("made an invalid dummy BP")
        }
        RctType::ClsagBulletproofPlus => {
          let mut bp = Vec::with_capacity(((6 + (2 * lr_len)) * 32) + 2);
          let push_point = |bp: &mut Vec<u8>| {
            bp.push(1);
            bp.extend([0; 31]);
          };
          let push_scalar = |bp: &mut Vec<u8>| bp.extend([0; 32]);
          for _ in 0 .. 3 {
            push_point(&mut bp);
          }
          for _ in 0 .. 3 {
            push_scalar(&mut bp);
          }
          for _ in 0 .. 2 {
            write_varint(&lr_len, &mut bp).unwrap();
            for _ in 0 .. lr_len {
              push_point(&mut bp);
            }
          }
          Bulletproof::read_plus(&mut bp.as_slice()).expect("made an invalid dummy BP+")
        }
        _ => panic!("unsupported RctType"),
      };

      // `- 1` to remove the one byte for the 0 fee
      Transaction::V2 {
        prefix: TransactionPrefix {
          additional_timelock: Timelock::None,
          inputs: self.inputs(&key_images),
          outputs: self.outputs(&key_images),
          extra: self.extra(),
        },
        proofs: Some(RctProofs {
          base: RctBase { fee: 0, encrypted_amounts, pseudo_outs: vec![], commitments },
          prunable: RctPrunable::Clsag { bulletproof, clsags, pseudo_outs },
        }),
      }
      .weight() -
        1
    };

    // We now have the base weight, without the fee encoded
    // The fee itself will impact the weight as its encoding is [1, 9] bytes long
    let mut possible_weights = Vec::with_capacity(9);
    for i in 1 ..= 9 {
      possible_weights.push(base_weight + i);
    }
    debug_assert_eq!(possible_weights.len(), 9);

    // We now calculate the fee which would be used for each weight
    let mut possible_fees = Vec::with_capacity(9);
    for weight in possible_weights {
      possible_fees.push(self.fee_rate.calculate_fee_from_weight(weight));
    }

    // We now look for the fee whose length matches the length used to derive it
    let mut weight_and_fee = None;
    for (fee_len, possible_fee) in possible_fees.into_iter().enumerate() {
      let fee_len = 1 + fee_len;
      debug_assert!(1 <= fee_len);
      debug_assert!(fee_len <= 9);

      // We use the first fee whose encoded length is not larger than the length used within this
      // weight
      // This should be because the lengths are equal, yet means if somehow none are equal, this
      // will still terminate successfully
      if varint_len(possible_fee) <= fee_len {
        weight_and_fee = Some((base_weight + fee_len, possible_fee));
        break;
      }
    }
    weight_and_fee.unwrap()
  }
}

impl SignableTransactionWithKeyImages {
  pub(crate) fn transaction_without_signatures(&self) -> Transaction {
    let commitments_and_encrypted_amounts =
      self.intent.commitments_and_encrypted_amounts(&self.key_images);
    let mut commitments = Vec::with_capacity(self.intent.payments.len());
    let mut bp_commitments = Vec::with_capacity(self.intent.payments.len());
    let mut encrypted_amounts = Vec::with_capacity(self.intent.payments.len());
    for (commitment, encrypted_amount) in commitments_and_encrypted_amounts {
      commitments.push(commitment.calculate());
      bp_commitments.push(commitment);
      encrypted_amounts.push(encrypted_amount);
    }
    let bulletproof = {
      let mut bp_rng = self.intent.seeded_rng(b"bulletproof");
      (match self.intent.rct_type {
        RctType::ClsagBulletproof => Bulletproof::prove(&mut bp_rng, &bp_commitments),
        RctType::ClsagBulletproofPlus => Bulletproof::prove_plus(&mut bp_rng, bp_commitments),
        _ => panic!("unsupported RctType"),
      })
      .expect("couldn't prove BP(+)s for this many payments despite checking in constructor?")
    };

    Transaction::V2 {
      prefix: TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: self.intent.inputs(&self.key_images),
        outputs: self.intent.outputs(&self.key_images),
        extra: self.intent.extra(),
      },
      proofs: Some(RctProofs {
        base: RctBase {
          fee: if self
            .intent
            .payments
            .iter()
            .any(|payment| matches!(payment, InternalPayment::Change(_, _)))
          {
            // The necessary fee is the fee
            self.intent.weight_and_necessary_fee().1
          } else {
            // If we don't have a change output, the difference is the fee
            let inputs =
              self.intent.inputs.iter().map(|input| input.0.commitment().amount).sum::<u64>();
            let payments = self
              .intent
              .payments
              .iter()
              .filter_map(|payment| match payment {
                InternalPayment::Payment(_, amount) => Some(amount),
                InternalPayment::Change(_, _) => None,
              })
              .sum::<u64>();
            // Safe since the constructor checks inputs >= (payments + fee)
            inputs - payments
          },
          encrypted_amounts,
          pseudo_outs: vec![],
          commitments,
        },
        prunable: RctPrunable::Clsag { bulletproof, clsags: vec![], pseudo_outs: vec![] },
      }),
    }
  }
}
