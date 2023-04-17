use core::marker::PhantomData;
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use group::GroupEncoding;
use frost::{
  curve::{Ciphersuite, Ristretto},
  dkg::{Participant, ThresholdParams, ThresholdCore, ThresholdKeys, encryption::*, frost::*},
};

use log::info;

use serai_client::{primitives::BlockHash, validator_sets::primitives::ValidatorSet};
use messages::{SubstrateContext, key_gen::*};

use crate::{Get, DbTxn, Db, coins::Coin};

#[derive(Debug)]
pub struct KeyConfirmed<C: Ciphersuite> {
  pub activation_block: BlockHash,
  pub substrate_keys: ThresholdKeys<Ristretto>,
  pub coin_keys: ThresholdKeys<C>,
}

#[derive(Clone, Debug)]
struct KeyGenDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> KeyGenDb<C, D> {
  fn key_gen_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"KEY_GEN", dst, key)
  }

  fn params_key(set: &ValidatorSet) -> Vec<u8> {
    Self::key_gen_key(b"params", bincode::serialize(set).unwrap())
  }
  fn save_params(txn: &mut D::Transaction<'_>, set: &ValidatorSet, params: &ThresholdParams) {
    txn.put(Self::params_key(set), bincode::serialize(params).unwrap());
  }
  fn params(&self, set: &ValidatorSet) -> ThresholdParams {
    // Directly unwraps the .get() as this will only be called after being set
    bincode::deserialize(&self.0.get(Self::params_key(set)).unwrap()).unwrap()
  }

  // Not scoped to the set since that'd have latter attempts overwrite former
  // A former attempt may become the finalized attempt, even if it doesn't in a timely manner
  // Overwriting its commitments would be accordingly poor
  fn commitments_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"commitments", bincode::serialize(id).unwrap())
  }
  fn save_commitments(
    txn: &mut D::Transaction<'_>,
    id: &KeyGenId,
    commitments: &HashMap<Participant, Vec<u8>>,
  ) {
    txn.put(Self::commitments_key(id), bincode::serialize(commitments).unwrap());
  }
  fn commitments(&self, id: &KeyGenId) -> HashMap<Participant, Vec<u8>> {
    bincode::deserialize::<HashMap<Participant, Vec<u8>>>(
      &self.0.get(Self::commitments_key(id)).unwrap(),
    )
    .unwrap()
  }

  fn generated_keys_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"generated_keys", bincode::serialize(id).unwrap())
  }
  fn save_keys(
    txn: &mut D::Transaction<'_>,
    id: &KeyGenId,
    substrate_keys: &ThresholdCore<Ristretto>,
    coin_keys: &ThresholdCore<C::Curve>,
  ) {
    let mut keys = substrate_keys.serialize();
    keys.extend(coin_keys.serialize().iter());
    txn.put(Self::generated_keys_key(id), keys);
  }

  fn keys_key(key: &<C::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::key_gen_key(b"keys", key.to_bytes())
  }
  #[allow(clippy::type_complexity)]
  fn read_keys<G: Get>(
    getter: &G,
    key: &[u8],
  ) -> (Vec<u8>, (ThresholdKeys<Ristretto>, ThresholdKeys<C::Curve>)) {
    let keys_vec = getter.get(key).unwrap();
    let mut keys_ref: &[u8] = keys_vec.as_ref();
    let substrate_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
    let mut coin_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
    C::tweak_keys(&mut coin_keys);
    (keys_vec, (substrate_keys, coin_keys))
  }
  fn confirm_keys(
    txn: &mut D::Transaction<'_>,
    id: &KeyGenId,
  ) -> (ThresholdKeys<Ristretto>, ThresholdKeys<C::Curve>) {
    let (keys_vec, keys) = Self::read_keys(txn, &Self::generated_keys_key(id));
    txn.put(Self::keys_key(&keys.1.group_key()), keys_vec);
    keys
  }
  fn keys(
    &self,
    key: &<C::Curve as Ciphersuite>::G,
  ) -> (ThresholdKeys<Ristretto>, ThresholdKeys<C::Curve>) {
    Self::read_keys(&self.0, &Self::keys_key(key)).1
  }
}

/// Coded so if the processor spontaneously reboots, one of two paths occur:
/// 1) It either didn't send its response, so the attempt will be aborted
/// 2) It did send its response, and has locally saved enough data to continue
#[derive(Debug)]
pub struct KeyGen<C: Coin, D: Db> {
  db: KeyGenDb<C, D>,
  entropy: Zeroizing<[u8; 32]>,

  active_commit:
    HashMap<ValidatorSet, (SecretShareMachine<Ristretto>, SecretShareMachine<C::Curve>)>,
  active_share: HashMap<ValidatorSet, (KeyMachine<Ristretto>, KeyMachine<C::Curve>)>,
}

impl<C: Coin, D: Db> KeyGen<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, entropy: Zeroizing<[u8; 32]>) -> KeyGen<C, D> {
    KeyGen {
      db: KeyGenDb(db, PhantomData::<C>),
      entropy,

      active_commit: HashMap::new(),
      active_share: HashMap::new(),
    }
  }

  pub fn keys(
    &self,
    key: &<C::Curve as Ciphersuite>::G,
  ) -> (ThresholdKeys<Ristretto>, ThresholdKeys<C::Curve>) {
    self.db.keys(key)
  }

  pub async fn handle(&mut self, msg: CoordinatorMessage) -> ProcessorMessage {
    let context = |id: &KeyGenId| {
      // TODO2: Also embed the chain ID/genesis block
      format!(
        "Serai Key Gen. Session: {:?}, Network: {:?}, Attempt: {}",
        id.set.session, id.set.network, id.attempt
      )
    };

    let rng = |label, id: KeyGenId| {
      let mut transcript = RecommendedTranscript::new(label);
      transcript.append_message(b"entropy", &self.entropy);
      transcript.append_message(b"context", context(&id));
      ChaCha20Rng::from_seed(transcript.rng_seed(b"rng"))
    };
    let coefficients_rng = |id| rng(b"Key Gen Coefficients", id);
    let secret_shares_rng = |id| rng(b"Key Gen Secret Shares", id);
    let share_rng = |id| rng(b"Key Gen Share", id);

    let key_gen_machines = |id, params| {
      let mut rng = coefficients_rng(id);
      let substrate = KeyGenMachine::new(params, context(&id)).generate_coefficients(&mut rng);
      let coin = KeyGenMachine::new(params, context(&id)).generate_coefficients(&mut rng);
      ((substrate.0, coin.0), (substrate.1, coin.1))
    };

    match msg {
      CoordinatorMessage::GenerateKey { id, params } => {
        info!("Generating new key. ID: {:?} Params: {:?}", id, params);

        // Remove old attempts
        if self.active_commit.remove(&id.set).is_none() &&
          self.active_share.remove(&id.set).is_none()
        {
          // If we haven't handled this set before, save the params
          // This may overwrite previously written params if we rebooted, yet that isn't a
          // concern
          let mut txn = self.db.0.txn();
          KeyGenDb::<C, D>::save_params(&mut txn, &id.set, &params);
          txn.commit();
        }

        let (machines, commitments) = key_gen_machines(id, params);
        let mut serialized = commitments.0.serialize();
        serialized.extend(commitments.1.serialize());
        self.active_commit.insert(id.set, machines);

        ProcessorMessage::Commitments { id, commitments: serialized }
      }

      CoordinatorMessage::Commitments { id, commitments } => {
        info!("Received commitments for {:?}", id);

        if self.active_share.contains_key(&id.set) {
          // We should've been told of a new attempt before receiving commitments again
          // The coordinator is either missing messages or repeating itself
          // Either way, it's faulty
          panic!("commitments when already handled commitments");
        }

        let params = self.db.params(&id.set);

        // Unwrap the machines, rebuilding them if we didn't have them in our cache
        // We won't if the processor rebooted
        // This *may* be inconsistent if we receive a KeyGen for attempt x, then commitments for
        // attempt y
        // The coordinator is trusted to be proper in this regard
        let machines =
          self.active_commit.remove(&id.set).unwrap_or_else(|| key_gen_machines(id, params).0);

        let mut rng = secret_shares_rng(id);

        let mut commitments_ref: HashMap<Participant, &[u8]> =
          commitments.iter().map(|(i, commitments)| (*i, commitments.as_ref())).collect();

        #[allow(clippy::type_complexity)]
        fn handle_machine<C: Ciphersuite>(
          rng: &mut ChaCha20Rng,
          params: ThresholdParams,
          machine: SecretShareMachine<C>,
          commitments_ref: &mut HashMap<Participant, &[u8]>,
        ) -> (KeyMachine<C>, HashMap<Participant, EncryptedMessage<C, SecretShare<C::F>>>) {
          // Parse the commitments
          let parsed = match commitments_ref
            .iter_mut()
            .map(|(i, commitments)| {
              EncryptionKeyMessage::<C, Commitments<C>>::read(commitments, params)
                .map(|commitments| (*i, commitments))
            })
            .collect()
          {
            Ok(commitments) => commitments,
            Err(e) => todo!("malicious signer: {:?}", e),
          };

          match machine.generate_secret_shares(rng, parsed) {
            Ok(res) => res,
            Err(e) => todo!("malicious signer: {:?}", e),
          }
        }

        let (substrate_machine, mut substrate_shares) =
          handle_machine::<Ristretto>(&mut rng, params, machines.0, &mut commitments_ref);
        let (coin_machine, coin_shares) =
          handle_machine(&mut rng, params, machines.1, &mut commitments_ref);

        self.active_share.insert(id.set, (substrate_machine, coin_machine));

        let mut shares: HashMap<_, _> =
          substrate_shares.drain().map(|(i, share)| (i, share.serialize())).collect();
        for (i, share) in shares.iter_mut() {
          share.extend(coin_shares[i].serialize());
        }

        let mut txn = self.db.0.txn();
        KeyGenDb::<C, D>::save_commitments(&mut txn, &id, &commitments);
        txn.commit();

        ProcessorMessage::Shares { id, shares }
      }

      CoordinatorMessage::Shares { id, shares } => {
        info!("Received shares for {:?}", id);

        let params = self.db.params(&id.set);

        // Same commentary on inconsistency as above exists
        let machines = self.active_share.remove(&id.set).unwrap_or_else(|| {
          let machines = key_gen_machines(id, params).0;
          let mut rng = secret_shares_rng(id);
          let commitments = self.db.commitments(&id);

          let mut commitments_ref: HashMap<Participant, &[u8]> =
            commitments.iter().map(|(i, commitments)| (*i, commitments.as_ref())).collect();

          fn parse_commitments<C: Ciphersuite>(
            params: ThresholdParams,
            commitments_ref: &mut HashMap<Participant, &[u8]>,
          ) -> HashMap<Participant, EncryptionKeyMessage<C, Commitments<C>>> {
            commitments_ref
              .iter_mut()
              .map(|(i, commitments)| {
                (*i, EncryptionKeyMessage::<C, Commitments<C>>::read(commitments, params).unwrap())
              })
              .collect()
          }

          (
            machines
              .0
              .generate_secret_shares(&mut rng, parse_commitments(params, &mut commitments_ref))
              .unwrap()
              .0,
            machines
              .1
              .generate_secret_shares(&mut rng, parse_commitments(params, &mut commitments_ref))
              .unwrap()
              .0,
          )
        });

        let mut rng = share_rng(id);

        let mut shares_ref: HashMap<Participant, &[u8]> =
          shares.iter().map(|(i, shares)| (*i, shares.as_ref())).collect();

        fn handle_machine<C: Ciphersuite>(
          rng: &mut ChaCha20Rng,
          params: ThresholdParams,
          machine: KeyMachine<C>,
          shares_ref: &mut HashMap<Participant, &[u8]>,
        ) -> ThresholdCore<C> {
          // Parse the shares
          let shares = match shares_ref
            .iter_mut()
            .map(|(i, share)| {
              EncryptedMessage::<C, SecretShare<C::F>>::read(share, params).map(|share| (*i, share))
            })
            .collect()
          {
            Ok(shares) => shares,
            Err(e) => todo!("malicious signer: {:?}", e),
          };

          // TODO2: Handle the blame machine properly
          (match machine.calculate_share(rng, shares) {
            Ok(res) => res,
            Err(e) => todo!("malicious signer: {:?}", e),
          })
          .complete()
        }

        let substrate_keys = handle_machine(&mut rng, params, machines.0, &mut shares_ref);
        let coin_keys = handle_machine(&mut rng, params, machines.1, &mut shares_ref);

        let mut txn = self.db.0.txn();
        KeyGenDb::<C, D>::save_keys(&mut txn, &id, &substrate_keys, &coin_keys);
        txn.commit();

        let mut coin_keys = ThresholdKeys::new(coin_keys);
        C::tweak_keys(&mut coin_keys);
        ProcessorMessage::GeneratedKeyPair {
          id,
          substrate_key: substrate_keys.group_key().to_bytes(),
          coin_key: coin_keys.group_key().to_bytes().as_ref().to_vec(),
        }
      }
    }
  }

  pub async fn confirm(
    &mut self,
    context: SubstrateContext,
    id: KeyGenId,
  ) -> KeyConfirmed<C::Curve> {
    let mut txn = self.db.0.txn();
    let (substrate_keys, coin_keys) = KeyGenDb::<C, D>::confirm_keys(&mut txn, &id);
    txn.commit();

    info!(
      "Confirmed key pair {} {} from {:?}",
      hex::encode(substrate_keys.group_key().to_bytes()),
      hex::encode(coin_keys.group_key().to_bytes()),
      id
    );

    KeyConfirmed {
      activation_block: context.coin_latest_finalized_block,
      substrate_keys,
      coin_keys,
    }
  }
}
