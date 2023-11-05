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

use crate::{Get, DbTxn, Db, create_db, networks::Network};

#[derive(Debug)]
pub struct KeyConfirmed<C: Ciphersuite> {
  pub substrate_keys: Vec<ThresholdKeys<Ristretto>>,
  pub network_keys: Vec<ThresholdKeys<C>>,
}

create_db!(
  KeyGenDb {
    ParamsDb: (key: &ValidatorSet) -> (ThresholdParams, u16),
    // Not scoped to the set since that'd have latter attempts overwrite former
    // A former attempt may become the finalized attempt, even if it doesn't in a timely manner
    // Overwriting its commitments would be accordingly poor
    CommitmentsDb: (key: &KeyGenId) -> HashMap<Participant, Vec<u8>>,
    GeneratedKeysDb: (set: &ValidatorSet, substrate_key: &[u8; 32], network_key: &[u8]) -> Vec<u8>,
    KeysDb: (network_key: &[u8]) -> Vec<u8>
  }
);

impl GeneratedKeysDb {
  #[allow(clippy::type_complexity)]
  fn read_keys<N: Network>(
    getter: &impl Get,
    key: &[u8],
  ) -> Option<(Vec<u8>, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    let keys_vec = getter.get(key)?;
    let mut keys_ref: &[u8] = keys_vec.as_ref();

    let mut substrate_keys = vec![];
    let mut network_keys = vec![];
    while !keys_ref.is_empty() {
      substrate_keys.push(ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap()));
      let mut these_network_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys_ref).unwrap());
      N::tweak_keys(&mut these_network_keys);
      network_keys.push(these_network_keys);
    }
    Some((keys_vec, (substrate_keys, network_keys)))
  }

  fn save_keys<N: Network>(
    txn: &mut impl DbTxn,
    id: &KeyGenId,
    substrate_keys: &[ThresholdCore<Ristretto>],
    network_keys: &[ThresholdKeys<N::Curve>],
  ) {
    let mut keys = Zeroizing::new(vec![]);
    for (substrate_keys, network_keys) in substrate_keys.iter().zip(network_keys) {
      keys.extend(substrate_keys.serialize().as_slice());
      keys.extend(network_keys.serialize().as_slice());
    }
    txn.put(
      Self::key(
        &id.set,
        &substrate_keys[0].group_key().to_bytes(),
        network_keys[0].group_key().to_bytes().as_ref(),
      ),
      keys,
    );
  }
}

impl KeysDb {
  fn confirm_keys<N: Network>(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    key_pair: KeyPair,
  ) -> (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>) {
    let (keys_vec, keys) = GeneratedKeysDb::read_keys::<N>(
      txn,
      &GeneratedKeysDb::key(&set, &key_pair.0 .0, key_pair.1.as_ref()),
    )
    .unwrap();
    assert_eq!(key_pair.0 .0, keys.0[0].group_key().to_bytes());
    assert_eq!(
      {
        let network_key: &[u8] = key_pair.1.as_ref();
        network_key
      },
      keys.1[0].group_key().to_bytes().as_ref(),
    );
    txn.put(KeysDb::key(keys.1[0].group_key().to_bytes().as_ref()), keys_vec);
    keys
  }

  #[allow(clippy::type_complexity)]
  fn keys<N: Network>(
    getter: &impl Get,
    network_key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>)> {
    let res =
      GeneratedKeysDb::read_keys::<N>(getter, &Self::key(network_key.to_bytes().as_ref()))?.1;
    assert_eq!(&res.1[0].group_key(), network_key);
    Some(res)
  }
}

type SecretShareMachines<N> =
  Vec<(SecretShareMachine<Ristretto>, SecretShareMachine<<N as Network>::Curve>)>;
type KeyMachines<N> = Vec<(KeyMachine<Ristretto>, KeyMachine<<N as Network>::Curve>)>;

#[derive(Debug)]
pub struct KeyGen<N: Network, D: Db> {
  db: D,
  entropy: Zeroizing<[u8; 32]>,

  active_commit: HashMap<ValidatorSet, (SecretShareMachines<N>, Vec<Vec<u8>>)>,
  #[allow(clippy::type_complexity)]
  active_share: HashMap<ValidatorSet, (KeyMachines<N>, Vec<HashMap<Participant, Vec<u8>>>)>,
}

impl<N: Network, D: Db> KeyGen<N, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, entropy: Zeroizing<[u8; 32]>) -> KeyGen<N, D> {
    KeyGen { db, entropy, active_commit: HashMap::new(), active_share: HashMap::new() }
  }

  pub fn in_set(&self, set: &ValidatorSet) -> bool {
    // We determine if we're in set using if we have the parameters for a set's key generation
    ParamsDb::get(&self.db, set).is_some()
  }

  #[allow(clippy::type_complexity)]
  pub fn keys(
    &self,
    key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>)> {
    // This is safe, despite not having a txn, since it's a static value
    // It doesn't change over time/in relation to other operations
    KeysDb::keys::<N>(&self.db, key)
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

    let key_gen_machines = |id, params: ThresholdParams, shares| {
      let mut rng = coefficients_rng(id);
      let mut machines = vec![];
      let mut commitments = vec![];
      for s in 0 .. shares {
        let params = ThresholdParams::new(
          params.t(),
          params.n(),
          Participant::new(u16::from(params.i()) + s).unwrap(),
        )
        .unwrap();
        let substrate = KeyGenMachine::new(params, context(&id)).generate_coefficients(&mut rng);
        let network = KeyGenMachine::new(params, context(&id)).generate_coefficients(&mut rng);
        machines.push((substrate.0, network.0));
        let mut serialized = vec![];
        substrate.1.write(&mut serialized).unwrap();
        network.1.write(&mut serialized).unwrap();
        commitments.push(serialized);
      }
      (machines, commitments)
    };

    let secret_share_machines =
      |id,
       params: ThresholdParams,
       (machines, our_commitments): (SecretShareMachines<N>, Vec<Vec<u8>>),
       commitments: HashMap<Participant, Vec<u8>>| {
        let mut rng = secret_shares_rng(id);

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

        let mut key_machines = vec![];
        let mut shares = vec![];
        for (m, (substrate_machine, network_machine)) in machines.into_iter().enumerate() {
          let mut commitments_ref: HashMap<Participant, &[u8]> =
            commitments.iter().map(|(i, commitments)| (*i, commitments.as_ref())).collect();
          for (i, our_commitments) in our_commitments.iter().enumerate() {
            if m != i {
              assert!(commitments_ref
                .insert(
                  Participant::new(u16::from(params.i()) + u16::try_from(i).unwrap()).unwrap(),
                  our_commitments.as_ref(),
                )
                .is_none());
            }
          }

          let (substrate_machine, mut substrate_shares) =
            handle_machine::<Ristretto>(&mut rng, params, substrate_machine, &mut commitments_ref);
          let (network_machine, network_shares) =
            handle_machine(&mut rng, params, network_machine, &mut commitments_ref);
          key_machines.push((substrate_machine, network_machine));

          for (_, commitments) in commitments_ref {
            if !commitments.is_empty() {
              todo!("malicious signer: extra bytes");
            }
          }

          let mut these_shares: HashMap<_, _> =
            substrate_shares.drain().map(|(i, share)| (i, share.serialize())).collect();
          for (i, share) in these_shares.iter_mut() {
            share.extend(network_shares[i].serialize());
          }
          shares.push(these_shares);
        }
        (key_machines, shares)
      };

    match msg {
      CoordinatorMessage::GenerateKey { id, params, shares } => {
        info!("Generating new key. ID: {id:?} Params: {params:?} Shares: {shares}");

        // Remove old attempts
        if self.active_commit.remove(&id.set).is_none() &&
          self.active_share.remove(&id.set).is_none()
        {
          // If we haven't handled this set before, save the params
          ParamsDb::set(txn, &id.set, &(params, shares));
        }

        let (machines, commitments) = key_gen_machines(id, params, shares);
        self.active_commit.insert(id.set, (machines, commitments.clone()));

        ProcessorMessage::Commitments { id, commitments }
      }

      CoordinatorMessage::Commitments { id, commitments } => {
        info!("Received commitments for {:?}", id);

        if self.active_share.contains_key(&id.set) {
          // We should've been told of a new attempt before receiving commitments again
          // The coordinator is either missing messages or repeating itself
          // Either way, it's faulty
          panic!("commitments when already handled commitments");
        }

        let (params, share_quantity) = ParamsDb::get(txn, &id.set).unwrap();

        // Unwrap the machines, rebuilding them if we didn't have them in our cache
        // We won't if the processor rebooted
        // This *may* be inconsistent if we receive a KeyGen for attempt x, then commitments for
        // attempt y
        // The coordinator is trusted to be proper in this regard
        let prior = self
          .active_commit
          .remove(&id.set)
          .unwrap_or_else(|| key_gen_machines(id, params, share_quantity));

        CommitmentsDb::set(txn, &id, &commitments);
        let (machines, shares) = secret_share_machines(id, params, prior, commitments);

        self.active_share.insert(id.set, (machines, shares.clone()));

        ProcessorMessage::Shares { id, shares }
      }

      CoordinatorMessage::Shares { id, shares } => {
        info!("Received shares for {:?}", id);

        let (params, share_quantity) = ParamsDb::get(txn, &id.set).unwrap();

        // Same commentary on inconsistency as above exists
        let (machines, our_shares) = self.active_share.remove(&id.set).unwrap_or_else(|| {
          let prior = key_gen_machines(id, params, share_quantity);
          secret_share_machines(id, params, prior, CommitmentsDb::get(txn, &id).unwrap())
        });

        let mut rng = share_rng(id);

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

        let mut substrate_keys = vec![];
        let mut network_keys = vec![];
        for (m, machines) in machines.into_iter().enumerate() {
          let mut shares_ref: HashMap<Participant, &[u8]> =
            shares[m].iter().map(|(i, shares)| (*i, shares.as_ref())).collect();
          for (i, our_shares) in our_shares.iter().enumerate() {
            if m != i {
              assert!(shares_ref
                .insert(
                  Participant::new(u16::from(params.i()) + u16::try_from(i).unwrap()).unwrap(),
                  our_shares
                    [&Participant::new(u16::from(params.i()) + u16::try_from(m).unwrap()).unwrap()]
                    .as_ref(),
                )
                .is_none());
            }
          }

          let these_substrate_keys = handle_machine(&mut rng, params, machines.0, &mut shares_ref);
          let these_network_keys = handle_machine(&mut rng, params, machines.1, &mut shares_ref);

          for (_, shares) in shares_ref {
            if !shares.is_empty() {
              todo!("malicious signer: extra bytes");
            }
          }

          let mut these_network_keys = ThresholdKeys::new(these_network_keys);
          N::tweak_keys(&mut these_network_keys);

          substrate_keys.push(these_substrate_keys);
          network_keys.push(these_network_keys);
        }

        let mut generated_substrate_key = None;
        let mut generated_network_key = None;
        for keys in substrate_keys.iter().zip(&network_keys) {
          if generated_substrate_key.is_none() {
            generated_substrate_key = Some(keys.0.group_key());
            generated_network_key = Some(keys.1.group_key());
          } else {
            assert_eq!(generated_substrate_key, Some(keys.0.group_key()));
            assert_eq!(generated_network_key, Some(keys.1.group_key()));
          }
        }

        GeneratedKeysDb::save_keys::<N>(txn, &id, &substrate_keys, &network_keys);

        ProcessorMessage::GeneratedKeyPair {
          id,
          substrate_key: generated_substrate_key.unwrap().to_bytes(),
          network_key: generated_network_key.unwrap().to_bytes().as_ref().to_vec(),
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
    info!(
      "Confirmed key pair {} {} for set {:?}",
      hex::encode(key_pair.0),
      hex::encode(&key_pair.1),
      set,
    );

    let (substrate_keys, network_keys) = KeysDb::confirm_keys::<N>(txn, set, key_pair);

    KeyConfirmed { substrate_keys, network_keys }
  }
}
