use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng};

use ciphersuite::Ciphersuite;

use crate::{
  Participant, ThresholdParams, ThresholdCore,
  frost::{Commitments, KeyGenMachine, SecretShare, KeyMachine},
  encryption::{EncryptionKeyMessage, EncryptedMessage},
  tests::{THRESHOLD, PARTICIPANTS, clone_without},
};

// Needed so rustfmt doesn't fail to format on line length issues
type FrostEncryptedMessage<C> = EncryptedMessage<C, SecretShare<<C as Ciphersuite>::F>>;
type FrostSecretShares<C> = HashMap<Participant, FrostEncryptedMessage<C>>;

const CONTEXT: &str = "DKG Test Key Generation";

// Commit, then return commitment messages, enc keys, and shares
#[allow(clippy::type_complexity)]
fn commit_enc_keys_and_shares<R: RngCore + CryptoRng, C: Ciphersuite>(
  rng: &mut R,
) -> (
  HashMap<Participant, KeyMachine<C>>,
  HashMap<Participant, EncryptionKeyMessage<C, Commitments<C>>>,
  HashMap<Participant, C::G>,
  HashMap<Participant, FrostSecretShares<C>>,
) {
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  let mut enc_keys = HashMap::new();
  for i in (1 ..= PARTICIPANTS).map(Participant) {
    let params = ThresholdParams::new(THRESHOLD, PARTICIPANTS, i).unwrap();
    let machine = KeyGenMachine::<C>::new(params, CONTEXT.to_string());
    let (machine, these_commitments) = machine.generate_coefficients(rng);
    machines.insert(i, machine);

    commitments.insert(
      i,
      EncryptionKeyMessage::read::<&[u8]>(&mut these_commitments.serialize().as_ref(), params)
        .unwrap(),
    );
    enc_keys.insert(i, commitments[&i].enc_key());
  }

  let mut secret_shares = HashMap::new();
  let machines = machines
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
              // Only t/n actually matters, so hardcode i to 1 here
              ThresholdParams { t: THRESHOLD, n: PARTICIPANTS, i: Participant(1) },
            )
            .unwrap(),
          )
        })
        .collect::<HashMap<_, _>>();
      secret_shares.insert(l, shares);
      (l, machine)
    })
    .collect::<HashMap<_, _>>();

  (machines, commitments, enc_keys, secret_shares)
}

fn generate_secret_shares<C: Ciphersuite>(
  shares: &HashMap<Participant, FrostSecretShares<C>>,
  recipient: Participant,
) -> FrostSecretShares<C> {
  let mut our_secret_shares = HashMap::new();
  for (i, shares) in shares {
    if recipient == *i {
      continue;
    }
    our_secret_shares.insert(*i, shares[&recipient].clone());
  }
  our_secret_shares
}

/// Fully perform the FROST key generation algorithm.
pub fn frost_gen<R: RngCore + CryptoRng, C: Ciphersuite>(
  rng: &mut R,
) -> HashMap<Participant, ThresholdCore<C>> {
  let (mut machines, _, _, secret_shares) = commit_enc_keys_and_shares::<_, C>(rng);

  let mut verification_shares = None;
  let mut group_key = None;
  machines
    .drain()
    .map(|(i, machine)| {
      let our_secret_shares = generate_secret_shares(&secret_shares, i);
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

#[cfg(test)]
mod literal {
  use rand_core::OsRng;

  use ciphersuite::Ristretto;

  use crate::{
    DkgError,
    encryption::EncryptionKeyProof,
    frost::{BlameMachine, AdditionalBlameMachine},
  };

  use super::*;

  const ONE: Participant = Participant(1);
  const TWO: Participant = Participant(2);

  fn test_blame(
    commitment_msgs: HashMap<Participant, EncryptionKeyMessage<Ristretto, Commitments<Ristretto>>>,
    machines: Vec<BlameMachine<Ristretto>>,
    msg: FrostEncryptedMessage<Ristretto>,
    blame: Option<EncryptionKeyProof<Ristretto>>,
  ) {
    for machine in machines {
      let (additional, blamed) = machine.blame(ONE, TWO, msg.clone(), blame.clone());
      assert_eq!(blamed, ONE);
      // Verify additional blame also works
      assert_eq!(additional.blame(ONE, TWO, msg.clone(), blame.clone()), ONE);

      // Verify machines constructed with AdditionalBlameMachine::new work
      assert_eq!(
        AdditionalBlameMachine::new(
          &mut OsRng,
          CONTEXT.to_string(),
          PARTICIPANTS,
          commitment_msgs.clone()
        )
        .unwrap()
        .blame(ONE, TWO, msg.clone(), blame.clone()),
        ONE,
      );
    }
  }

  // TODO: Write a macro which expands to the following
  #[test]
  fn invalid_encryption_pop_blame() {
    let (mut machines, commitment_msgs, _, mut secret_shares) =
      commit_enc_keys_and_shares::<_, Ristretto>(&mut OsRng);

    // Mutate the PoP of the encrypted message from 1 to 2
    secret_shares.get_mut(&ONE).unwrap().get_mut(&TWO).unwrap().invalidate_pop();

    let mut blame = None;
    let machines = machines
      .drain()
      .filter_map(|(i, machine)| {
        let our_secret_shares = generate_secret_shares(&secret_shares, i);
        let machine = machine.calculate_share(&mut OsRng, our_secret_shares);
        if i == TWO {
          assert_eq!(machine.err(), Some(DkgError::InvalidShare { participant: ONE, blame: None }));
          // Explicitly declare we have a blame object, which happens to be None since invalid PoP
          // is self-explainable
          blame = Some(None);
          None
        } else {
          Some(machine.unwrap())
        }
      })
      .collect::<Vec<_>>();

    test_blame(commitment_msgs, machines, secret_shares[&ONE][&TWO].clone(), blame.unwrap());
  }

  #[test]
  fn invalid_ecdh_blame() {
    let (mut machines, commitment_msgs, _, mut secret_shares) =
      commit_enc_keys_and_shares::<_, Ristretto>(&mut OsRng);

    // Mutate the share to trigger a blame event
    // Mutates from 2 to 1, as 1 is expected to end up malicious for test_blame to pass
    // While here, 2 is malicious, this is so 1 creates the blame proof
    // We then malleate 1's blame proof, so 1 ends up malicious
    // Doesn't simply invalidate the PoP as that won't have a blame statement
    // By mutating the encrypted data, we do ensure a blame statement is created
    secret_shares
      .get_mut(&TWO)
      .unwrap()
      .get_mut(&ONE)
      .unwrap()
      .invalidate_msg(&mut OsRng, CONTEXT, TWO);

    let mut blame = None;
    let machines = machines
      .drain()
      .filter_map(|(i, machine)| {
        let our_secret_shares = generate_secret_shares(&secret_shares, i);
        let machine = machine.calculate_share(&mut OsRng, our_secret_shares);
        if i == ONE {
          blame = Some(match machine.err() {
            Some(DkgError::InvalidShare { participant: TWO, blame: Some(blame) }) => Some(blame),
            _ => panic!(),
          });
          None
        } else {
          Some(machine.unwrap())
        }
      })
      .collect::<Vec<_>>();

    blame.as_mut().unwrap().as_mut().unwrap().invalidate_key();
    test_blame(commitment_msgs, machines, secret_shares[&TWO][&ONE].clone(), blame.unwrap());
  }

  // This should be largely equivalent to the prior test
  #[test]
  fn invalid_dleq_blame() {
    let (mut machines, commitment_msgs, _, mut secret_shares) =
      commit_enc_keys_and_shares::<_, Ristretto>(&mut OsRng);

    secret_shares
      .get_mut(&TWO)
      .unwrap()
      .get_mut(&ONE)
      .unwrap()
      .invalidate_msg(&mut OsRng, CONTEXT, TWO);

    let mut blame = None;
    let machines = machines
      .drain()
      .filter_map(|(i, machine)| {
        let our_secret_shares = generate_secret_shares(&secret_shares, i);
        let machine = machine.calculate_share(&mut OsRng, our_secret_shares);
        if i == ONE {
          blame = Some(match machine.err() {
            Some(DkgError::InvalidShare { participant: TWO, blame: Some(blame) }) => Some(blame),
            _ => panic!(),
          });
          None
        } else {
          Some(machine.unwrap())
        }
      })
      .collect::<Vec<_>>();

    blame.as_mut().unwrap().as_mut().unwrap().invalidate_dleq();
    test_blame(commitment_msgs, machines, secret_shares[&TWO][&ONE].clone(), blame.unwrap());
  }

  #[test]
  fn invalid_share_serialization_blame() {
    let (mut machines, commitment_msgs, enc_keys, mut secret_shares) =
      commit_enc_keys_and_shares::<_, Ristretto>(&mut OsRng);

    secret_shares.get_mut(&ONE).unwrap().get_mut(&TWO).unwrap().invalidate_share_serialization(
      &mut OsRng,
      CONTEXT,
      ONE,
      enc_keys[&TWO],
    );

    let mut blame = None;
    let machines = machines
      .drain()
      .filter_map(|(i, machine)| {
        let our_secret_shares = generate_secret_shares(&secret_shares, i);
        let machine = machine.calculate_share(&mut OsRng, our_secret_shares);
        if i == TWO {
          blame = Some(match machine.err() {
            Some(DkgError::InvalidShare { participant: ONE, blame: Some(blame) }) => Some(blame),
            _ => panic!(),
          });
          None
        } else {
          Some(machine.unwrap())
        }
      })
      .collect::<Vec<_>>();

    test_blame(commitment_msgs, machines, secret_shares[&ONE][&TWO].clone(), blame.unwrap());
  }

  #[test]
  fn invalid_share_value_blame() {
    let (mut machines, commitment_msgs, enc_keys, mut secret_shares) =
      commit_enc_keys_and_shares::<_, Ristretto>(&mut OsRng);

    secret_shares.get_mut(&ONE).unwrap().get_mut(&TWO).unwrap().invalidate_share_value(
      &mut OsRng,
      CONTEXT,
      ONE,
      enc_keys[&TWO],
    );

    let mut blame = None;
    let machines = machines
      .drain()
      .filter_map(|(i, machine)| {
        let our_secret_shares = generate_secret_shares(&secret_shares, i);
        let machine = machine.calculate_share(&mut OsRng, our_secret_shares);
        if i == TWO {
          blame = Some(match machine.err() {
            Some(DkgError::InvalidShare { participant: ONE, blame: Some(blame) }) => Some(blame),
            _ => panic!(),
          });
          None
        } else {
          Some(machine.unwrap())
        }
      })
      .collect::<Vec<_>>();

    test_blame(commitment_msgs, machines, secret_shares[&ONE][&TWO].clone(), blame.unwrap());
  }
}
