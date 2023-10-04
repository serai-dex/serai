use core::marker::PhantomData;
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::GroupEncoding;
use frost::{
  curve::{Ciphersuite, Ristretto},
  dkg::{Participant, ThresholdParams, ThresholdCore, ThresholdKeys, encryption::*, frost::*},
};

use log::info;

use scale::Encode;
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair};
use messages::key_gen::*;

use crate::{Get, DbTxn, Db, networks::Network};

#[derive(Debug)]
pub struct KeyConfirmed<C: Ciphersuite> {
  pub substrate_keys: ThresholdKeys<Ristretto>,
  pub network_keys: ThresholdKeys<C>,
}

#[derive(Clone, Debug)]
struct KeyGenDb<N: Network, D: Db>(PhantomData<D>, PhantomData<N>);
impl<N: Network, D: Db> KeyGenDb<N, D> {
  fn key_gen_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"KEY_GEN", dst, key)
  }

  fn params_key(set: &ValidatorSet) -> Vec<u8> {
    Self::key_gen_key(b"params", set.encode())
  }
  fn save_params(txn: &mut D::Transaction<'_>, set: &ValidatorSet, params: &ThresholdParams) {
    txn.put(Self::params_key(set), bincode::serialize(params).unwrap());
  }
  fn params<G: Get>(getter: &G, set: &ValidatorSet) -> Option<ThresholdParams> {
    getter.get(Self::params_key(set)).map(|bytes| bincode::deserialize(&bytes).unwrap())
  }

  // Not scoped to the set since that'd have latter attempts overwrite former
  // A former attempt may become the finalized attempt, even if it doesn't in a timely manner
  // Overwriting its commitments would be accordingly poor
  fn commitments_key(id: &KeyGenId) -> Vec<u8> {
    Self::key_gen_key(b"commitments", id.encode())
  }
  fn save_commitments(
    txn: &mut D::Transaction<'_>,
    id: &KeyGenId,
    commitments: &HashMap<Participant, Vec<u8>>,
  ) {
    txn.put(Self::commitments_key(id), bincode::serialize(commitments).unwrap());
  }
  fn commitments<G: Get>(getter: &G, id: &KeyGenId) -> HashMap<Participant, Vec<u8>> {
    bincode::deserialize::<HashMap<Participant, Vec<u8>>>(
      &getter.get(Self::commitments_key(id)).unwrap(),
    )
    .unwrap()
  }

  fn generated_keys_key(set: ValidatorSet, key_pair: (&[u8; 32], &[u8])) -> Vec<u8> {
    Self::key_gen_key(b"generated_keys", (set, key_pair).encode())
  }
  fn save_keys(
    txn: &mut D::Transaction<'_>,
    id: &KeyGenId,
    substrate_keys: &ThresholdCore<Ristretto>,
    network_keys: &ThresholdKeys<N::Curve>,
  ) {
    let mut keys = substrate_keys.serialize();
    keys.extend(network_keys.serialize().iter());
    txn.put(
      Self::generated_keys_key(
        id.set,
        (&substrate_keys.group_key().to_bytes(), network_keys.group_key().to_bytes().as_ref()),
      ),
      keys,
    );
  }

  fn keys_key(key: &<N::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::key_gen_key(b"keys", key.to_bytes())
  }
  #[allow(clippy::type_complexity)]
  fn read_keys<G: Get>(
    getter: &G,
    key: &[u8],
  ) -> Option<(Vec<u8>, (ThresholdKeys<Ristretto>, ThresholdKeys<N::Curve>))> {
    let keys_vec = getter.get(key)?;
    let mut keys_ref: &[u8] = keys_vec.as_ref();
    let substrate_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
    let mut network_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
    N::tweak_keys(&mut network_keys);
    Some((keys_vec, (substrate_keys, network_keys)))
  }
  fn confirm_keys(
    txn: &mut D::Transaction<'_>,
    set: ValidatorSet,
    key_pair: KeyPair,
  ) -> (ThresholdKeys<Ristretto>, ThresholdKeys<N::Curve>) {
    let (keys_vec, keys) =
      Self::read_keys(txn, &Self::generated_keys_key(set, (&key_pair.0 .0, key_pair.1.as_ref())))
        .unwrap();
    assert_eq!(key_pair.0 .0, keys.0.group_key().to_bytes());
    assert_eq!(
      {
        let network_key: &[u8] = key_pair.1.as_ref();
        network_key
      },
      keys.1.group_key().to_bytes().as_ref(),
    );
    txn.put(Self::keys_key(&keys.1.group_key()), keys_vec);
    keys
  }
  fn keys<G: Get>(
    getter: &G,
    key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(ThresholdKeys<Ristretto>, ThresholdKeys<N::Curve>)> {
    let res = Self::read_keys(getter, &Self::keys_key(key))?.1;
    assert_eq!(&res.1.group_key(), key);
    Some(res)
  }
}

/// Coded so if the processor spontaneously reboots, one of two paths occur:
/// 1) It either didn't send its response, so the attempt will be aborted
/// 2) It did send its response, and has locally saved enough data to continue
#[derive(Debug)]
pub struct KeyGen<N: Network, D: Db> {
  db: D,
  entropy: Zeroizing<[u8; 32]>,

  active_commit:
    HashMap<ValidatorSet, (SecretShareMachine<Ristretto>, SecretShareMachine<N::Curve>)>,
  active_share: HashMap<ValidatorSet, (KeyMachine<Ristretto>, KeyMachine<N::Curve>)>,
}

impl<N: Network, D: Db> KeyGen<N, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, entropy: Zeroizing<[u8; 32]>) -> KeyGen<N, D> {
    KeyGen { db, entropy, active_commit: HashMap::new(), active_share: HashMap::new() }
  }

  pub fn in_set(&self, set: &ValidatorSet) -> bool {
    // We determine if we're in set using if we have the parameters for a set's key generation
    KeyGenDb::<N, D>::params(&self.db, set).is_some()
  }

  pub fn keys(
    &self,
    key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(ThresholdKeys<Ristretto>, ThresholdKeys<N::Curve>)> {
    // This is safe, despite not having a txn, since it's a static value
    // The only concern is it may not be set when expected, or it may be set unexpectedly
    //
    // They're only expected to be set on boot, if confirmed. If they were confirmed yet the
    // transaction wasn't committed, their confirmation will be re-handled
    //
    // The only other concern is if it's set when it's not safe to use
    // The keys are only written on confirmation, and the transaction writing them is atomic to
    // every associated operation
    KeyGenDb::<N, D>::keys(&self.db, key)
  }

  pub async fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> ProcessorMessage {
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
      let network = KeyGenMachine::new(params, context(&id)).generate_coefficients(&mut rng);
      ((substrate.0, network.0), (substrate.1, network.1))
    };

    match msg {
      CoordinatorMessage::GenerateKey { id, params } => {
        info!("Generating new key. ID: {:?} Params: {:?}", id, params);

        // Remove old attempts
        if self.active_commit.remove(&id.set).is_none() &&
          self.active_share.remove(&id.set).is_none()
        {
          // If we haven't handled this set before, save the params
          KeyGenDb::<N, D>::save_params(txn, &id.set, &params);
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

        let params = KeyGenDb::<N, D>::params(txn, &id.set).unwrap();

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
        let (network_machine, network_shares) =
          handle_machine(&mut rng, params, machines.1, &mut commitments_ref);

        for (_, commitments) in commitments_ref {
          if !commitments.is_empty() {
            todo!("malicious signer: extra bytes");
          }
        }

        self.active_share.insert(id.set, (substrate_machine, network_machine));

        let mut shares: HashMap<_, _> =
          substrate_shares.drain().map(|(i, share)| (i, share.serialize())).collect();
        for (i, share) in shares.iter_mut() {
          share.extend(network_shares[i].serialize());
        }

        KeyGenDb::<N, D>::save_commitments(txn, &id, &commitments);

        ProcessorMessage::Shares { id, shares }
      }

      CoordinatorMessage::Shares { id, shares } => {
        info!("Received shares for {:?}", id);

        let params = KeyGenDb::<N, D>::params(txn, &id.set).unwrap();

        // Same commentary on inconsistency as above exists
        let machines = self.active_share.remove(&id.set).unwrap_or_else(|| {
          let machines = key_gen_machines(id, params).0;
          let mut rng = secret_shares_rng(id);
          let commitments = KeyGenDb::<N, D>::commitments(txn, &id);

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
        let network_keys = handle_machine(&mut rng, params, machines.1, &mut shares_ref);

        for (_, shares) in shares_ref {
          if !shares.is_empty() {
            todo!("malicious signer: extra bytes");
          }
        }

        let mut network_keys = ThresholdKeys::new(network_keys);
        N::tweak_keys(&mut network_keys);

        KeyGenDb::<N, D>::save_keys(txn, &id, &substrate_keys, &network_keys);

        ProcessorMessage::GeneratedKeyPair {
          id,
          substrate_key: substrate_keys.group_key().to_bytes(),
          network_key: network_keys.group_key().to_bytes().as_ref().to_vec(),
        }
      }
    }
  }

  pub async fn confirm(
    &mut self,
    txn: &mut D::Transaction<'_>,
    set: ValidatorSet,
    key_pair: KeyPair,
  ) -> KeyConfirmed<N::Curve> {
    let (substrate_keys, network_keys) = KeyGenDb::<N, D>::confirm_keys(txn, set, key_pair);

    info!(
      "Confirmed key pair {} {} for set {:?}",
      hex::encode(substrate_keys.group_key().to_bytes()),
      hex::encode(network_keys.group_key().to_bytes()),
      set,
    );

    KeyConfirmed { substrate_keys, network_keys }
  }
}
