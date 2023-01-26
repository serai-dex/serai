use std::collections::HashMap;

use rand_core::OsRng;

use ciphersuite::{Ciphersuite, Ristretto};

use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};

use dkg::{
  ThresholdParams,
  encryption::{EncryptionKeyMessage, EncryptedMessage},
  frost::{Commitments, SecretShare, KeyGenMachine},
};

async fn dkg<C: Ciphersuite>(
  i: u16,
  send: UnboundedSender<Vec<u8>>,
  mut recv: UnboundedReceiver<Vec<u8>>,
) {
  // Calculate the other participant's i
  let other_i = i ^ 0b11;

  // A 2-of-2 multisig
  let params = ThresholdParams::new(2, 2, i).unwrap();

  // Create a key gen machine
  let machine = KeyGenMachine::new(params, "DKG Example".to_string());
  // Generate coefficients
  let (machine, commitments) = machine.generate_coefficients(&mut OsRng);
  // Send everyone our commitments
  send.send(commitments.serialize()).unwrap();

  // Receive everyone else's commitments
  let other_commitments = EncryptionKeyMessage::<C, Commitments<C>>::read::<&[u8]>(
    &mut recv.recv().await.unwrap().as_ref(),
    params,
  )
  .unwrap();
  let mut all_commitments = HashMap::new();
  all_commitments.insert(other_i, other_commitments);

  // Generate secret shares
  let (machine, shares) = machine.generate_secret_shares(&mut OsRng, all_commitments).unwrap();
  // Send everyone else their secret shares
  send.send(shares[&other_i].serialize()).unwrap();

  // Receive our shares from everyone else
  let share = EncryptedMessage::<C, SecretShare<C::F>>::read::<&[u8]>(
    &mut recv.recv().await.unwrap().as_ref(),
    params,
  )
  .unwrap();
  let mut all_shares = HashMap::new();
  all_shares.insert(other_i, share);

  // Calculate our share
  let (machine, _key) = machine.calculate_share(&mut OsRng, all_shares).unwrap();
  // Assume the process succeeded, though this should only be done ater everyone votes on the key
  let _keys = machine.complete();
}

#[tokio::main]
async fn main() {
  // Create a pair of channels
  let (alice_send, alice_recv) = mpsc::unbounded_channel();
  let (bob_send, bob_recv) = mpsc::unbounded_channel();

  // Spawn Alice
  let alice = dkg::<Ristretto>(1, alice_send, bob_recv);
  // Spawn Bob
  let bob = dkg::<Ristretto>(2, bob_send, alice_recv);
  tokio::join!(alice, bob);
}
