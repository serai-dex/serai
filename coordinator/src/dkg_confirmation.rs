use core::{ops::Deref, future::Future};
use std::{boxed::Box, collections::HashMap};

use zeroize::Zeroizing;
use rand_core::OsRng;
use ciphersuite::{group::GroupEncoding, Ciphersuite};
use dalek_ff_group::Ristretto;
use dkg::{Participant, musig};
use frost_schnorrkel::{
  frost::{FrostError, sign::*},
  Schnorrkel,
};

use serai_db::{DbTxn, Db as DbTrait};

use serai_client::{
  primitives::SeraiAddress,
  validator_sets::primitives::{ExternalValidatorSet, musig_context, set_keys_message},
};

use serai_task::{DoesNotError, ContinuallyRan};

use serai_coordinator_substrate::{NewSetInformation, Keys};
use serai_coordinator_tributary::{Transaction, DkgConfirmationMessages};

use crate::{KeysToConfirm, KeySet, TributaryTransactionsFromDkgConfirmation};

fn schnorrkel() -> Schnorrkel {
  Schnorrkel::new(b"substrate") // TODO: Pull the constant for this
}

fn our_i(
  set: &NewSetInformation,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  data: &HashMap<Participant, Vec<u8>>,
) -> Participant {
  let public = SeraiAddress((Ristretto::generator() * key.deref()).to_bytes());

  let mut our_i = None;
  for participant in data.keys() {
    let validator_index = usize::from(u16::from(*participant) - 1);
    let (validator, _weight) = set.validators[validator_index];
    if validator == public {
      our_i = Some(*participant);
    }
  }
  our_i.unwrap()
}

// Take a HashMap of participations with non-contiguous Participants and convert them to a
// contiguous sequence.
//
// The input data is expected to not include our own data, which also won't be in the output data.
//
// Returns the mapping from the contiguous Participants to the original Participants.
fn make_contiguous<T>(
  our_i: Participant,
  mut data: HashMap<Participant, Vec<u8>>,
  transform: impl Fn(Vec<u8>) -> std::io::Result<T>,
) -> Result<HashMap<Participant, T>, Participant> {
  assert!(!data.contains_key(&our_i));

  let mut ordered_participants = data.keys().copied().collect::<Vec<_>>();
  ordered_participants.sort_by_key(|participant| u16::from(*participant));

  let mut our_i = Some(our_i);
  let mut contiguous = HashMap::new();
  let mut i = 1;
  for participant in ordered_participants {
    // If this is the first participant after our own index, increment to account for our index
    if let Some(our_i_value) = our_i {
      if u16::from(participant) > u16::from(our_i_value) {
        i += 1;
        our_i = None;
      }
    }

    let contiguous_index = Participant::new(i).unwrap();
    let data = match transform(data.remove(&participant).unwrap()) {
      Ok(data) => data,
      Err(_) => Err(participant)?,
    };
    contiguous.insert(contiguous_index, data);
    i += 1;
  }
  Ok(contiguous)
}

fn handle_frost_error<T>(result: Result<T, FrostError>) -> Result<T, Participant> {
  match &result {
    Ok(_) => Ok(result.unwrap()),
    Err(FrostError::InvalidPreprocess(participant) | FrostError::InvalidShare(participant)) => {
      Err(*participant)
    }
    // All of these should be unreachable
    Err(
      FrostError::InternalError(_) |
      FrostError::InvalidParticipant(_, _) |
      FrostError::InvalidSigningSet(_) |
      FrostError::InvalidParticipantQuantity(_, _) |
      FrostError::DuplicatedParticipant(_) |
      FrostError::MissingParticipant(_),
    ) => {
      result.unwrap();
      unreachable!("continued execution after unwrapping Result::Err");
    }
  }
}

#[rustfmt::skip]
enum Signer {
  Preprocess { attempt: u32, seed: CachedPreprocess, preprocess: [u8; 64] },
  Share {
    attempt: u32,
    musig_validators: Vec<SeraiAddress>,
    share: [u8; 32],
    machine: Box<AlgorithmSignatureMachine<Ristretto, Schnorrkel>>,
  },
}

/// Performs the DKG Confirmation protocol.
pub(crate) struct ConfirmDkgTask<CD: DbTrait, TD: DbTrait> {
  db: CD,

  set: NewSetInformation,
  tributary_db: TD,

  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  signer: Option<Signer>,
}

impl<CD: DbTrait, TD: DbTrait> ConfirmDkgTask<CD, TD> {
  pub(crate) fn new(
    db: CD,
    set: NewSetInformation,
    tributary_db: TD,
    key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) -> Self {
    Self { db, set, tributary_db, key, signer: None }
  }

  fn slash(db: &mut CD, set: ExternalValidatorSet, validator: SeraiAddress) {
    let mut txn = db.txn();
    TributaryTransactionsFromDkgConfirmation::send(
      &mut txn,
      set,
      &Transaction::RemoveParticipant { participant: validator, signed: Default::default() },
    );
    txn.commit();
  }

  fn preprocess(
    db: &mut CD,
    set: ExternalValidatorSet,
    attempt: u32,
    key: Zeroizing<<Ristretto as Ciphersuite>::F>,
    signer: &mut Option<Signer>,
  ) {
    // Perform the preprocess
    let public_key = Ristretto::generator() * key.deref();
    let (machine, preprocess) = AlgorithmMachine::new(
      schnorrkel(),
      // We use a 1-of-1 Musig here as we don't know who will actually be in this Musig yet
      musig(musig_context(set.into()), key, &[public_key]).unwrap(),
    )
    .preprocess(&mut OsRng);
    // We take the preprocess so we can use it in a distinct machine with the actual Musig
    // parameters
    let seed = machine.cache();

    let mut preprocess_bytes = [0u8; 64];
    preprocess_bytes.copy_from_slice(&preprocess.serialize());
    let preprocess = preprocess_bytes;

    let mut txn = db.txn();
    // If this attempt has already been preprocessed for, the Tributary will de-duplicate it
    // This may mean the Tributary preprocess is distinct from ours, but we check for that later
    TributaryTransactionsFromDkgConfirmation::send(
      &mut txn,
      set,
      &Transaction::DkgConfirmationPreprocess { attempt, preprocess, signed: Default::default() },
    );
    txn.commit();

    *signer = Some(Signer::Preprocess { attempt, seed, preprocess });
  }
}

impl<CD: DbTrait, TD: DbTrait> ContinuallyRan for ConfirmDkgTask<CD, TD> {
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      // If we were sent a key to set, create the signer for it
      if self.signer.is_none() && KeysToConfirm::get(&self.db, self.set.set).is_some() {
        // Create and publish the initial preprocess
        Self::preprocess(&mut self.db, self.set.set, 0, self.key.clone(), &mut self.signer);

        made_progress = true;
      }

      // If we have keys to confirm, handle all messages from the tributary
      if let Some(key_pair) = KeysToConfirm::get(&self.db, self.set.set) {
        // Handle all messages from the Tributary
        loop {
          let mut tributary_txn = self.tributary_db.txn();
          let Some(msg) = DkgConfirmationMessages::try_recv(&mut tributary_txn, self.set.set)
          else {
            break;
          };

          match msg {
            messages::sign::CoordinatorMessage::Reattempt {
              id: messages::sign::SignId { attempt, .. },
            } => {
              // Create and publish the preprocess for the specified attempt
              Self::preprocess(
                &mut self.db,
                self.set.set,
                attempt,
                self.key.clone(),
                &mut self.signer,
              );
            }
            messages::sign::CoordinatorMessage::Preprocesses {
              id: messages::sign::SignId { attempt, .. },
              mut preprocesses,
            } => {
              // Confirm the preprocess we're expected to sign with is the one we locally have
              // It may be different if we rebooted and made a second preprocess for this attempt
              let Some(Signer::Preprocess { attempt: our_attempt, seed, preprocess }) =
                self.signer.take()
              else {
                // If this message is not expected, commit the txn to drop it and move on
                // At some point, we'll get a Reattempt and reset
                tributary_txn.commit();
                break;
              };

              // Determine the MuSig key signed with
              let musig_validators = {
                let mut ordered_participants = preprocesses.keys().copied().collect::<Vec<_>>();
                ordered_participants.sort_by_key(|participant| u16::from(*participant));

                let mut res = vec![];
                for participant in ordered_participants {
                  let (validator, _weight) =
                    self.set.validators[usize::from(u16::from(participant) - 1)];
                  res.push(validator);
                }
                res
              };

              let musig_public_keys = musig_validators
                .iter()
                .map(|key| {
                  Ristretto::read_G(&mut key.0.as_slice())
                    .expect("Serai validator had invalid public key")
                })
                .collect::<Vec<_>>();

              let keys =
                musig(musig_context(self.set.set.into()), self.key.clone(), &musig_public_keys)
                  .unwrap();

              // Rebuild the machine
              let (machine, preprocess_from_cache) =
                AlgorithmSignMachine::from_cache(schnorrkel(), keys, seed);
              assert_eq!(preprocess.as_slice(), preprocess_from_cache.serialize().as_slice());

              // Ensure this is a consistent signing session
              let our_i = our_i(&self.set, &self.key, &preprocesses);
              let consistent = (attempt == our_attempt) &&
                (preprocesses.remove(&our_i).unwrap().as_slice() == preprocess.as_slice());
              if !consistent {
                tributary_txn.commit();
                break;
              }

              // Reformat the preprocesses into the expected format for Musig
              let preprocesses = match make_contiguous(our_i, preprocesses, |preprocess| {
                machine.read_preprocess(&mut preprocess.as_slice())
              }) {
                Ok(preprocesses) => preprocesses,
                // This yields the *original participant index*
                Err(participant) => {
                  Self::slash(
                    &mut self.db,
                    self.set.set,
                    self.set.validators[usize::from(u16::from(participant) - 1)].0,
                  );
                  tributary_txn.commit();
                  break;
                }
              };

              // Calculate our share
              let (machine, share) = match handle_frost_error(
                machine.sign(preprocesses, &set_keys_message(&self.set.set, &key_pair)),
              ) {
                Ok((machine, share)) => (machine, share),
                // This yields the *musig participant index*
                Err(participant) => {
                  Self::slash(
                    &mut self.db,
                    self.set.set,
                    musig_validators[usize::from(u16::from(participant) - 1)],
                  );
                  tributary_txn.commit();
                  break;
                }
              };

              // Send our share
              let share = <[u8; 32]>::try_from(share.serialize()).unwrap();
              let mut txn = self.db.txn();
              TributaryTransactionsFromDkgConfirmation::send(
                &mut txn,
                self.set.set,
                &Transaction::DkgConfirmationShare { attempt, share, signed: Default::default() },
              );
              txn.commit();

              self.signer = Some(Signer::Share {
                attempt,
                musig_validators,
                share,
                machine: Box::new(machine),
              });
            }
            messages::sign::CoordinatorMessage::Shares {
              id: messages::sign::SignId { attempt, .. },
              mut shares,
            } => {
              let Some(Signer::Share { attempt: our_attempt, musig_validators, share, machine }) =
                self.signer.take()
              else {
                tributary_txn.commit();
                break;
              };

              // Ensure this is a consistent signing session
              let our_i = our_i(&self.set, &self.key, &shares);
              let consistent = (attempt == our_attempt) &&
                (shares.remove(&our_i).unwrap().as_slice() == share.as_slice());
              if !consistent {
                tributary_txn.commit();
                break;
              }

              // Reformat the shares into the expected format for Musig
              let shares = match make_contiguous(our_i, shares, |share| {
                machine.read_share(&mut share.as_slice())
              }) {
                Ok(shares) => shares,
                // This yields the *original participant index*
                Err(participant) => {
                  Self::slash(
                    &mut self.db,
                    self.set.set,
                    self.set.validators[usize::from(u16::from(participant) - 1)].0,
                  );
                  tributary_txn.commit();
                  break;
                }
              };

              match handle_frost_error(machine.complete(shares)) {
                Ok(signature) => {
                  // Create the bitvec of the participants
                  let mut signature_participants;
                  {
                    use bitvec::prelude::*;
                    signature_participants = bitvec![u8, Lsb0; 0; 0];
                    let mut i = 0;
                    for (validator, _) in &self.set.validators {
                      if Some(validator) == musig_validators.get(i) {
                        signature_participants.push(true);
                        i += 1;
                      } else {
                        signature_participants.push(false);
                      }
                    }
                  }

                  // This is safe to call multiple times as it'll just change which *valid*
                  // signature to publish
                  let mut txn = self.db.txn();
                  Keys::set(
                    &mut txn,
                    self.set.set,
                    key_pair.clone(),
                    signature_participants,
                    signature.into(),
                  );
                  txn.commit();
                }
                // This yields the *musig participant index*
                Err(participant) => {
                  Self::slash(
                    &mut self.db,
                    self.set.set,
                    musig_validators[usize::from(u16::from(participant) - 1)],
                  );
                  tributary_txn.commit();
                  break;
                }
              }
            }
          }

          // Because we successfully handled this message, note we made proress
          made_progress = true;
          tributary_txn.commit();
        }
      }

      // Check if the key has been set on Serai
      if KeysToConfirm::get(&self.db, self.set.set).is_some() &&
        KeySet::get(&self.db, self.set.set).is_some()
      {
        // Take the keys to confirm so we never instantiate the signer again
        let mut txn = self.db.txn();
        KeysToConfirm::take(&mut txn, self.set.set);
        KeySet::take(&mut txn, self.set.set);
        txn.commit();

        // Drop our own signer
        // The task won't die until the Tributary does, but now it'll never do anything again
        self.signer = None;

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
