use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng};

use crate::{
  Ciphersuite, ThresholdParams, ThresholdCore,
  frost::KeyGenMachine,
  encryption::{EncryptionKeyMessage, EncryptedMessage},
  tests::{THRESHOLD, PARTICIPANTS, clone_without},
};

/// Fully perform the FROST key generation algorithm.
pub fn frost_gen<R: RngCore + CryptoRng, C: Ciphersuite>(
  rng: &mut R,
) -> HashMap<u16, ThresholdCore<C>> {
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  for i in 1 ..= PARTICIPANTS {
    let machine = KeyGenMachine::<C>::new(
      ThresholdParams::new(THRESHOLD, PARTICIPANTS, i).unwrap(),
      "DKG Test Key Generation".to_string(),
    );
    let (machine, these_commitments) = machine.generate_coefficients(rng);
    machines.insert(i, machine);

    commitments.insert(
      i,
      EncryptionKeyMessage::read::<&[u8]>(
        &mut these_commitments.serialize().as_ref(),
        ThresholdParams { t: THRESHOLD, n: PARTICIPANTS, i: 1 },
      )
      .unwrap(),
    );
  }

  let mut secret_shares = HashMap::new();
  let mut machines = machines
    .drain()
    .map(|(l, machine)| {
      let (machine, mut shares) =
        machine.generate_secret_shares(rng, clone_without(&commitments, &l)).unwrap();
      let shares = shares
        .drain()
        .map(|(l, share)| {
          (
            l,
            EncryptedMessage::read::<&[u8]>(
              &mut share.serialize().as_ref(),
              ThresholdParams { t: THRESHOLD, n: PARTICIPANTS, i: 1 },
            )
            .unwrap(),
          )
        })
        .collect::<HashMap<_, _>>();
      secret_shares.insert(l, shares);
      (l, machine)
    })
    .collect::<HashMap<_, _>>();

  let mut verification_shares = None;
  let mut group_key = None;
  machines
    .drain()
    .map(|(i, machine)| {
      let mut our_secret_shares = HashMap::new();
      for (l, shares) in &secret_shares {
        if i == *l {
          continue;
        }
        our_secret_shares.insert(*l, shares[&i].clone());
      }
      let these_keys = machine.calculate_share(rng, our_secret_shares).unwrap().complete();

      // Verify the verification_shares are agreed upon
      if verification_shares.is_none() {
        verification_shares = Some(these_keys.verification_shares());
      }
      assert_eq!(verification_shares.as_ref().unwrap(), &these_keys.verification_shares());

      // Verify the group keys are agreed upon
      if group_key.is_none() {
        group_key = Some(these_keys.group_key());
      }
      assert_eq!(group_key.unwrap(), these_keys.group_key());

      (i, these_keys)
    })
    .collect::<HashMap<_, _>>()
}
