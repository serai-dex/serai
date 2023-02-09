use core::marker::PhantomData;
use std::collections::HashMap;

use rand_core::OsRng;

use group::GroupEncoding;
use frost::{
  curve::Ciphersuite,
  dkg::{ThresholdParams, ThresholdCore, ThresholdKeys, encryption::*, frost::*},
};

use log::info;
use tokio::sync::mpsc;

use validator_sets_primitives::ValidatorSetInstance;
use messages::key_gen::*;

use crate::Db;

#[derive(Debug)]
pub enum KeyGenOrder {
  CoordinatorMessage(CoordinatorMessage),
}

#[derive(Debug)]
pub enum KeyGenEvent<C: Ciphersuite> {
  KeyConfirmed { set: ValidatorSetInstance, keys: ThresholdKeys<C> },
  ProcessorMessage(ProcessorMessage),
}

pub type KeyGenOrderChannel = mpsc::UnboundedSender<KeyGenOrder>;
pub type KeyGenEventChannel<C> = mpsc::UnboundedReceiver<KeyGenEvent<C>>;

#[derive(Clone, Debug)]
struct KeyGenDb<C: Ciphersuite, D: Db>(D, PhantomData<C>);
impl<C: Ciphersuite, D: Db> KeyGenDb<C, D> {
  fn key_gen_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [b"KEY_GEN", dst, key.as_ref()].concat().to_vec()
  }

  fn params_key(set: &ValidatorSetInstance) -> Vec<u8> {
    Self::key_gen_key(b"params", bincode::serialize(set).unwrap())
  }
  fn save_params(&mut self, set: &ValidatorSetInstance, params: &ThresholdParams) {
    self.0.put(Self::params_key(set), bincode::serialize(params).unwrap());
  }
  fn params(&self, set: &ValidatorSetInstance) -> ThresholdParams {
    // Directly unwraps the .get() as this will only be called after being set
    bincode::deserialize(&self.0.get(Self::params_key(set)).unwrap()).unwrap()
  }

  // Not scoped to the set since that'd have latter attempts overwrite former
  // A former attempt may become the finalized attempt, even if it doesn't in a timely manner
  // Overwriting its commitments would be accordingly poor
  fn commitments_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"commitments", bincode::serialize(id).unwrap())
  }
  fn save_commitments(&mut self, id: &KeyGenId, commitments: &HashMap<u16, Vec<u8>>) {
    self.0.put(Self::commitments_key(id), bincode::serialize(commitments).unwrap());
  }
  fn commitments(
    &self,
    id: &KeyGenId,
    params: ThresholdParams,
  ) -> HashMap<u16, EncryptionKeyMessage<C, Commitments<C>>> {
    bincode::deserialize::<HashMap<u16, Vec<u8>>>(&self.0.get(Self::commitments_key(id)).unwrap())
      .unwrap()
      .drain()
      .map(|(i, bytes)| {
        (
          i,
          EncryptionKeyMessage::<C, Commitments<C>>::read::<&[u8]>(&mut bytes.as_ref(), params)
            .unwrap(),
        )
      })
      .collect()
  }

  fn generated_keys_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"generated_keys", bincode::serialize(id).unwrap())
  }
  fn save_keys(&mut self, id: &KeyGenId, keys: &ThresholdCore<C>) {
    self.0.put(Self::generated_keys_key(id), keys.serialize());
  }

  fn keys_key(key: &C::G) -> Vec<u8> {
    Self::key_gen_key(b"keys", key.to_bytes())
  }
  fn confirm_keys(&mut self, id: &KeyGenId) -> ThresholdKeys<C> {
    let keys_vec = self.0.get(Self::generated_keys_key(id)).unwrap();
    let keys = ThresholdKeys::new(ThresholdCore::read::<&[u8]>(&mut keys_vec.as_ref()).unwrap());
    self.0.put(Self::keys_key(&keys.group_key()), keys_vec);
    keys
  }
  fn keys(&self, key: &C::G) -> ThresholdKeys<C> {
    ThresholdKeys::new(
      ThresholdCore::read::<&[u8]>(&mut self.0.get(Self::keys_key(key)).unwrap().as_ref()).unwrap(),
    )
  }
}

/// Coded so if the processor spontaneously reboots, one of two paths occur:
/// 1) It either didn't send its response, so the attempt will be aborted
/// 2) It did send its response, and has locally saved enough data to continue
#[derive(Debug)]
pub struct KeyGen<C: Ciphersuite, D: Db> {
  db: KeyGenDb<C, D>,

  active_commit: HashMap<ValidatorSetInstance, SecretShareMachine<C>>,
  active_share: HashMap<ValidatorSetInstance, KeyMachine<C>>,

  orders: mpsc::UnboundedReceiver<KeyGenOrder>,
  events: mpsc::UnboundedSender<KeyGenEvent<C>>,
}

#[derive(Debug)]
pub struct KeyGenHandle<C: Ciphersuite, D: Db> {
  db: KeyGenDb<C, D>,
  pub orders: KeyGenOrderChannel,
  pub events: KeyGenEventChannel<C>,
}
impl<C: Ciphersuite, D: Db> KeyGenHandle<C, D> {
  pub fn keys(&self, key: &C::G) -> ThresholdKeys<C> {
    self.db.keys(key)
  }
}

impl<C: Ciphersuite, D: Db> KeyGen<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D) -> KeyGenHandle<C, D> {
    if db.get(KeyGenDb::<C, D>::key_gen_key(b"corrupt", b"")).is_some() {
      panic!("key gen DB is corrupt");
    }

    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    let db = KeyGenDb(db, PhantomData::<C>);
    tokio::spawn(
      KeyGen {
        db: db.clone(),
        active_commit: HashMap::new(),
        active_share: HashMap::new(),
        orders: orders_recv,
        events: events_send,
      }
      .run(),
    );
    KeyGenHandle { db, orders: orders_send, events: events_recv }
  }

  // An async function, to be spawned on a task, to handle key generations
  async fn run(mut self) {
    const CHANNEL_MSG: &str = "Key Gen handler was dropped. Shutting down?";
    let handle_recv = |channel: Option<_>| {
      if channel.is_none() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };
    let handle_send = |channel: Result<_, _>| {
      if channel.is_err() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };

    let key_gen_machine = |id: &KeyGenId, params| {
      // TODO: Also embed the chain ID/genesis block
      let context = format!(
        "Serai Key Gen. Session: {}, Index: {}, Attempt: {}",
        id.set.session.0, id.set.index.0, id.attempt
      );

      // TODO: Seeded RNG
      KeyGenMachine::new(params, context).generate_coefficients(&mut OsRng)
    };

    // Handle any new messages
    loop {
      match {
        match handle_recv(self.orders.recv().await) {
          None => return,
          Some(order) => order,
        }
      } {
        KeyGenOrder::CoordinatorMessage(CoordinatorMessage::GenerateKey { id, params }) => {
          info!("Generating new key. ID: {:?} Params: {:?}", id, params);

          // Remove old attempts
          if self.active_commit.remove(&id.set).is_none() &&
            self.active_share.remove(&id.set).is_none()
          {
            // If we haven't handled this set before, save the params
            // This may overwrite previously written params if we rebooted, yet that isn't a
            // concern
            self.db.save_params(&id.set, &params);
          }

          let (machine, commitments) = key_gen_machine(&id, params);
          self.active_commit.insert(id.set, machine);

          if handle_send(self.events.send(KeyGenEvent::ProcessorMessage(
            ProcessorMessage::Commitments { id, commitments: commitments.serialize() },
          )))
          .is_err()
          {
            return;
          }
        }

        KeyGenOrder::CoordinatorMessage(CoordinatorMessage::Commitments { id, commitments }) => {
          info!("Received commitments for {:?}", id);

          if self.active_share.contains_key(&id.set) {
            // We should've been told of a new attempt before receiving commitments again
            // The coordinator is either missing messages or repeating itself
            // Either way, it's faulty
            panic!("commitments when already handled commitments");
          }

          let params = self.db.params(&id.set);

          // Parse the commitments
          let parsed = match commitments
            .iter()
            .map(|(i, commitments)| {
              EncryptionKeyMessage::<C, Commitments<C>>::read::<&[u8]>(
                &mut commitments.as_ref(),
                params,
              )
              .map(|commitments| (*i, commitments))
            })
            .collect()
          {
            Ok(commitments) => commitments,
            Err(e) => todo!("malicious signer: {:?}", e),
          };

          // Get the machine, rebuilding it if we don't have it
          // We won't if the processor rebooted
          // This *may* be inconsistent if we receive a KeyGen for attempt x, then commitments for
          // attempt y
          // The coordinator is trusted to be proper in this regard
          let machine =
            self.active_commit.remove(&id.set).unwrap_or_else(|| key_gen_machine(&id, params).0);

          // Doesn't use a seeded RNG since this just determines ephemeral encryption keys
          let (machine, mut shares) = match machine.generate_secret_shares(&mut OsRng, parsed) {
            Ok(res) => res,
            Err(e) => todo!("malicious signer: {:?}", e),
          };
          self.active_share.insert(id.set, machine);
          self.db.save_commitments(&id, &commitments);

          if handle_send(self.events.send(KeyGenEvent::ProcessorMessage(
            ProcessorMessage::Shares {
              id,
              shares: shares.drain().map(|(i, share)| (i, share.serialize())).collect(),
            },
          )))
          .is_err()
          {
            return;
          }
        }

        KeyGenOrder::CoordinatorMessage(CoordinatorMessage::Shares { id, mut shares }) => {
          info!("Received shares for {:?}", id);

          let params = self.db.params(&id.set);

          // Parse the shares
          let shares = match shares
            .drain()
            .map(|(i, share)| {
              EncryptedMessage::<C, SecretShare<C::F>>::read::<&[u8]>(&mut share.as_ref(), params)
                .map(|share| (i, share))
            })
            .collect()
          {
            Ok(shares) => shares,
            Err(e) => todo!("malicious signer: {:?}", e),
          };

          // Same commentary on inconsistency as above exists
          let machine = self.active_share.remove(&id.set).unwrap_or_else(|| {
            key_gen_machine(&id, params)
              .0
              .generate_secret_shares(&mut OsRng, self.db.commitments(&id, params))
              .unwrap()
              .0
          });

          // TODO: Handle the blame machine properly
          let keys = (match machine.calculate_share(&mut OsRng, shares) {
            Ok(res) => res,
            Err(e) => todo!("malicious signer: {:?}", e),
          })
          .complete();
          self.db.save_keys(&id, &keys);

          if handle_send(self.events.send(KeyGenEvent::ProcessorMessage(
            ProcessorMessage::GeneratedKey {
              id,
              key: keys.group_key().to_bytes().as_ref().to_vec(),
            },
          )))
          .is_err()
          {
            return;
          }
        }

        KeyGenOrder::CoordinatorMessage(CoordinatorMessage::ConfirmKey { id }) => {
          info!("Confirmed key from {:?}", id);

          let keys = self.db.confirm_keys(&id);
          if handle_send(self.events.send(KeyGenEvent::KeyConfirmed { set: id.set, keys })).is_err()
          {
            return;
          }
        }
      }
    }
  }
}
