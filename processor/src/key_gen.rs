use core::marker::PhantomData;
use std::collections::HashMap;

use rand_core::OsRng;

use tokio::sync::mpsc;

use group::GroupEncoding;
use frost::{
  curve::Ciphersuite,
  dkg::{ThresholdParams, ThresholdCore, encryption::*, frost::*},
};

use validator_sets_primitives::ValidatorSetInstance;
use messages::key_gen::*;

use crate::Db;

const CHANNEL_EXPECT: &str = "Key Gen handler was dropped. Shutting down?";

pub type KeyGenCoordinatorChannel = mpsc::UnboundedSender<CoordinatorMessage>;
pub type KeyGenProcessorChannel = mpsc::UnboundedReceiver<ProcessorMessage>;

#[derive(Debug)]
struct KeyGenDb<C: Ciphersuite, D: Db>(D, PhantomData<C>);
impl<C: Ciphersuite, D: Db> KeyGenDb<C, D> {
  fn key_gen_key(dst: &'static [u8], key: &[u8]) -> Vec<u8> {
    [b"KEY_GEN", dst, key].concat().to_vec()
  }

  fn params_key(set: &ValidatorSetInstance) -> Vec<u8> {
    Self::key_gen_key(b"params", &bincode::serialize(set).unwrap())
  }
  fn save_params(&mut self, set: &ValidatorSetInstance, params: &ThresholdParams) {
    self.0.put(&Self::params_key(set), &bincode::serialize(params).unwrap())
  }
  fn params(&self, set: &ValidatorSetInstance) -> ThresholdParams {
    // Directly unwraps the .get()  as this will only be called after being set
    bincode::deserialize(&self.0.get(&Self::params_key(set)).unwrap()).unwrap()
  }

  fn commitments_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"commitments", &bincode::serialize(id).unwrap())
  }
  fn save_commitments(&mut self, id: &KeyGenId, commitments: &HashMap<u16, Vec<u8>>) {
    self.0.put(&Self::commitments_key(id), &bincode::serialize(commitments).unwrap())
  }
  fn commitments(
    &self,
    id: &KeyGenId,
    params: ThresholdParams,
  ) -> HashMap<u16, EncryptionKeyMessage<C, Commitments<C>>> {
    bincode::deserialize::<HashMap<u16, Vec<u8>>>(&self.0.get(&Self::commitments_key(id)).unwrap())
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

  fn keys_key(set: &ValidatorSetInstance) -> Vec<u8> {
    Self::key_gen_key(b"keys", &bincode::serialize(set).unwrap())
  }
  fn save_keys(&mut self, set: &ValidatorSetInstance, keys: &ThresholdCore<C>) {
    self.0.put(&Self::keys_key(set), &keys.serialize())
  }
}

#[derive(Debug)]
pub struct KeyGen<C: Ciphersuite, D: Db> {
  db: KeyGenDb<C, D>,

  active_commit: HashMap<ValidatorSetInstance, SecretShareMachine<C>>,
  active_share: HashMap<ValidatorSetInstance, KeyMachine<C>>,

  incoming: mpsc::UnboundedReceiver<CoordinatorMessage>,
  outgoing: mpsc::UnboundedSender<ProcessorMessage>,
}

#[derive(Debug)]
pub struct KeyGenHandle {
  pub coordinator: KeyGenCoordinatorChannel,
  pub processor: KeyGenProcessorChannel,
}

// Coded so if the processor spontaneously reboot, one of two paths occur:
// 1) It either didn't send its response, so the attempt will be aborted
// 2) It did send its response, and has locally saved enough data to continue
impl<C: 'static + Send + Ciphersuite, D: Db> KeyGen<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D) -> KeyGenHandle {
    let (coordinator_send, coordinator_recv) = mpsc::unbounded_channel();
    let (processor_send, processor_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      KeyGen {
        db: KeyGenDb(db, PhantomData::<C>),
        active_commit: HashMap::new(),
        active_share: HashMap::new(),
        incoming: coordinator_recv,
        outgoing: processor_send,
      }
      .run(),
    );
    KeyGenHandle { coordinator: coordinator_send, processor: processor_recv }
  }

  // An async function, to be spawned on a task, to handle key generations
  async fn run(mut self) {
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
      match self.incoming.recv().await.expect(CHANNEL_EXPECT) {
        CoordinatorMessage::KeyGen { id, params } => {
          // Remove old attempts
          if self.active_commit.remove(&id.set).is_none() &&
            self.active_share.remove(&id.set).is_none()
          {
            self.db.save_params(&id.set, &params);
          }

          let (machine, commitments) = key_gen_machine(&id, params);
          self.active_commit.insert(id.set, machine);

          self
            .outgoing
            .send(ProcessorMessage::KeyGenCommitments { id, commitments: commitments.serialize() })
            .expect(CHANNEL_EXPECT);
        }

        CoordinatorMessage::KeyGenCommitments { id, commitments } => {
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

          // Rebuild the machine. Necessary if the processor rebooted
          let machine =
            self.active_commit.remove(&id.set).unwrap_or_else(|| key_gen_machine(&id, params).0);

          // Doesn't use a seeded RNG since this just determines ephemeral encryption keys
          let (machine, mut shares) = match machine.generate_secret_shares(&mut OsRng, parsed) {
            Ok(res) => res,
            Err(e) => todo!("malicious signer: {:?}", e),
          };
          self.active_share.insert(id.set, machine);
          self.db.save_commitments(&id, &commitments);

          self
            .outgoing
            .send(ProcessorMessage::KeyGenShares {
              id,
              shares: shares.drain().map(|(i, share)| (i, share.serialize())).collect(),
            })
            .expect(CHANNEL_EXPECT);
        }

        CoordinatorMessage::KeyGenShares { id, mut shares } => {
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
          self.db.save_keys(&id.set, &keys);

          self
            .outgoing
            .send(ProcessorMessage::KeyGenCompletion {
              id,
              key: keys.group_key().to_bytes().as_ref().to_vec(),
            })
            .expect(CHANNEL_EXPECT);
        }
      }
    }
  }
}
