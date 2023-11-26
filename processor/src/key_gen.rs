use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::GroupEncoding;
use frost::{
  curve::{Ciphersuite, Ristretto},
  dkg::{
    DkgError, Participant, ThresholdParams, ThresholdCore, ThresholdKeys, encryption::*, frost::*,
  },
};

use log::info;

use scale::Encode;
use serai_client::validator_sets::primitives::{Session, KeyPair};
use messages::key_gen::*;

use crate::{Get, DbTxn, Db, create_db, networks::Network};

#[derive(Debug)]
pub struct KeyConfirmed<C: Ciphersuite> {
  pub substrate_keys: Vec<ThresholdKeys<Ristretto>>,
  pub network_keys: Vec<ThresholdKeys<C>>,
}

create_db!(
  KeyGenDb {
    ParamsDb: (session: &Session) -> (ThresholdParams, u16),
    // Not scoped to the set since that'd have latter attempts overwrite former
    // A former attempt may become the finalized attempt, even if it doesn't in a timely manner
    // Overwriting its commitments would be accordingly poor
    CommitmentsDb: (key: &KeyGenId) -> HashMap<Participant, Vec<u8>>,
    GeneratedKeysDb: (session: &Session, substrate_key: &[u8; 32], network_key: &[u8]) -> Vec<u8>,
    // These do assume a key is only used once across sets, which holds true so long as a single
    // participant is honest in their execution of the protocol
    KeysDb: (network_key: &[u8]) -> Vec<u8>,
    SessionDb: (network_key: &[u8]) -> Session,
    NetworkKeyDb: (session: Session) -> Vec<u8>,
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
        &id.session,
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
    session: Session,
    key_pair: KeyPair,
  ) -> (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>) {
    let (keys_vec, keys) = GeneratedKeysDb::read_keys::<N>(
      txn,
      &GeneratedKeysDb::key(&session, &key_pair.0 .0, key_pair.1.as_ref()),
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
    txn.put(Self::key(key_pair.1.as_ref()), keys_vec);
    NetworkKeyDb::set(txn, session, &key_pair.1.clone().into_inner());
    SessionDb::set(txn, key_pair.1.as_ref(), &session);
    keys
  }

  #[allow(clippy::type_complexity)]
  fn keys<N: Network>(
    getter: &impl Get,
    network_key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Session, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    let res =
      GeneratedKeysDb::read_keys::<N>(getter, &Self::key(network_key.to_bytes().as_ref()))?.1;
    assert_eq!(&res.1[0].group_key(), network_key);
    Some((SessionDb::get(getter, network_key.to_bytes().as_ref()).unwrap(), res))
  }

  pub fn substrate_keys_by_session<N: Network>(
    getter: &impl Get,
    session: Session,
  ) -> Option<Vec<ThresholdKeys<Ristretto>>> {
    let network_key = NetworkKeyDb::get(getter, session)?;
    Some(GeneratedKeysDb::read_keys::<N>(getter, &Self::key(&network_key))?.1 .0)
  }
}

type SecretShareMachines<N> =
  Vec<(SecretShareMachine<Ristretto>, SecretShareMachine<<N as Network>::Curve>)>;
type KeyMachines<N> = Vec<(KeyMachine<Ristretto>, KeyMachine<<N as Network>::Curve>)>;

#[derive(Debug)]
pub struct KeyGen<N: Network, D: Db> {
  db: D,
  entropy: Zeroizing<[u8; 32]>,

  active_commit: HashMap<Session, (SecretShareMachines<N>, Vec<Vec<u8>>)>,
  #[allow(clippy::type_complexity)]
  active_share: HashMap<Session, (KeyMachines<N>, Vec<HashMap<Participant, Vec<u8>>>)>,
}

impl<N: Network, D: Db> KeyGen<N, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, entropy: Zeroizing<[u8; 32]>) -> KeyGen<N, D> {
    KeyGen { db, entropy, active_commit: HashMap::new(), active_share: HashMap::new() }
  }

  pub fn in_set(&self, session: &Session) -> bool {
    // We determine if we're in set using if we have the parameters for a session's key generation
    ParamsDb::get(&self.db, session).is_some()
  }

  #[allow(clippy::type_complexity)]
  pub fn keys(
    &self,
    key: &<N::Curve as Ciphersuite>::G,
  ) -> Option<(Session, (Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<N::Curve>>))> {
    // This is safe, despite not having a txn, since it's a static value
    // It doesn't change over time/in relation to other operations
    KeysDb::keys::<N>(&self.db, key)
  }

  pub fn substrate_keys_by_session(
    &self,
    session: Session,
  ) -> Option<Vec<ThresholdKeys<Ristretto>>> {
    KeysDb::substrate_keys_by_session::<N>(&self.db, session)
  }

  pub async fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> ProcessorMessage {
    const SUBSTRATE_KEY_CONTEXT: &str = "substrate";
    const NETWORK_KEY_CONTEXT: &str = "network";
    let context = |id: &KeyGenId, key| {
      // TODO2: Also embed the chain ID/genesis block
      format!(
        "Serai Key Gen. Session: {:?}, Network: {:?}, Attempt: {}, Key: {}",
        id.session,
        N::NETWORK,
        id.attempt,
        key,
      )
    };

    let rng = |label, id: KeyGenId| {
      let mut transcript = RecommendedTranscript::new(label);
      transcript.append_message(b"entropy", &self.entropy);
      transcript.append_message(b"context", context(&id, "rng"));
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
        let substrate = KeyGenMachine::new(params, context(&id, SUBSTRATE_KEY_CONTEXT))
          .generate_coefficients(&mut rng);
        let network = KeyGenMachine::new(params, context(&id, NETWORK_KEY_CONTEXT))
          .generate_coefficients(&mut rng);
        machines.push((substrate.0, network.0));
        let mut serialized = vec![];
        substrate.1.write(&mut serialized).unwrap();
        network.1.write(&mut serialized).unwrap();
        commitments.push(serialized);
      }
      (machines, commitments)
    };

    let secret_share_machines = |id,
                                 params: ThresholdParams,
                                 machines: SecretShareMachines<N>,
                                 commitments: HashMap<Participant, Vec<u8>>|
     -> Result<_, ProcessorMessage> {
      let mut rng = secret_shares_rng(id);

      #[allow(clippy::type_complexity)]
      fn handle_machine<C: Ciphersuite>(
        rng: &mut ChaCha20Rng,
        id: KeyGenId,
        machine: SecretShareMachine<C>,
        commitments: HashMap<Participant, EncryptionKeyMessage<C, Commitments<C>>>,
      ) -> Result<
        (KeyMachine<C>, HashMap<Participant, EncryptedMessage<C, SecretShare<C::F>>>),
        ProcessorMessage,
      > {
        match machine.generate_secret_shares(rng, commitments) {
          Ok(res) => Ok(res),
          Err(e) => match e {
            DkgError::ZeroParameter(_, _) |
            DkgError::InvalidThreshold(_, _) |
            DkgError::InvalidParticipant(_, _) |
            DkgError::InvalidSigningSet |
            DkgError::InvalidShare { .. } => unreachable!("{e:?}"),
            DkgError::InvalidParticipantQuantity(_, _) |
            DkgError::DuplicatedParticipant(_) |
            DkgError::MissingParticipant(_) => {
              panic!("coordinator sent invalid DKG commitments: {e:?}")
            }
            DkgError::InvalidCommitments(i) => {
              Err(ProcessorMessage::InvalidCommitments { id, faulty: i })?
            }
          },
        }
      }

      let mut substrate_commitments = HashMap::new();
      let mut network_commitments = HashMap::new();
      for i in 1 ..= params.n() {
        let i = Participant::new(i).unwrap();
        let mut commitments = commitments[&i].as_slice();
        substrate_commitments.insert(
          i,
          EncryptionKeyMessage::<Ristretto, Commitments<Ristretto>>::read(&mut commitments, params)
            .map_err(|_| ProcessorMessage::InvalidCommitments { id, faulty: i })?,
        );
        network_commitments.insert(
          i,
          EncryptionKeyMessage::<N::Curve, Commitments<N::Curve>>::read(&mut commitments, params)
            .map_err(|_| ProcessorMessage::InvalidCommitments { id, faulty: i })?,
        );
        if !commitments.is_empty() {
          // Malicious Participant included extra bytes in their commitments
          // (a potential DoS attack)
          Err(ProcessorMessage::InvalidCommitments { id, faulty: i })?;
        }
      }

      let mut key_machines = vec![];
      let mut shares = vec![];
      for (m, (substrate_machine, network_machine)) in machines.into_iter().enumerate() {
        let actual_i = Participant::new(u16::from(params.i()) + u16::try_from(m).unwrap()).unwrap();

        let mut substrate_commitments = substrate_commitments.clone();
        substrate_commitments.remove(&actual_i);
        let (substrate_machine, mut substrate_shares) =
          handle_machine::<Ristretto>(&mut rng, id, substrate_machine, substrate_commitments)?;

        let mut network_commitments = network_commitments.clone();
        network_commitments.remove(&actual_i);
        let (network_machine, network_shares) =
          handle_machine(&mut rng, id, network_machine, network_commitments.clone())?;

        key_machines.push((substrate_machine, network_machine));

        let mut these_shares: HashMap<_, _> =
          substrate_shares.drain().map(|(i, share)| (i, share.serialize())).collect();
        for (i, share) in these_shares.iter_mut() {
          share.extend(network_shares[i].serialize());
        }
        shares.push(these_shares);
      }
      Ok((key_machines, shares))
    };

    match msg {
      CoordinatorMessage::GenerateKey { id, params, shares } => {
        info!("Generating new key. ID: {id:?} Params: {params:?} Shares: {shares}");

        // Remove old attempts
        if self.active_commit.remove(&id.session).is_none() &&
          self.active_share.remove(&id.session).is_none()
        {
          // If we haven't handled this session before, save the params
          ParamsDb::set(txn, &id.session, &(params, shares));
        }

        let (machines, commitments) = key_gen_machines(id, params, shares);
        self.active_commit.insert(id.session, (machines, commitments.clone()));

        ProcessorMessage::Commitments { id, commitments }
      }

      CoordinatorMessage::Commitments { id, mut commitments } => {
        info!("Received commitments for {:?}", id);

        if self.active_share.contains_key(&id.session) {
          // We should've been told of a new attempt before receiving commitments again
          // The coordinator is either missing messages or repeating itself
          // Either way, it's faulty
          panic!("commitments when already handled commitments");
        }

        let (params, share_quantity) = ParamsDb::get(txn, &id.session).unwrap();

        // Unwrap the machines, rebuilding them if we didn't have them in our cache
        // We won't if the processor rebooted
        // This *may* be inconsistent if we receive a KeyGen for attempt x, then commitments for
        // attempt y
        // The coordinator is trusted to be proper in this regard
        let (prior, our_commitments) = self
          .active_commit
          .remove(&id.session)
          .unwrap_or_else(|| key_gen_machines(id, params, share_quantity));

        for (i, our_commitments) in our_commitments.into_iter().enumerate() {
          assert!(commitments
            .insert(
              Participant::new(u16::from(params.i()) + u16::try_from(i).unwrap()).unwrap(),
              our_commitments,
            )
            .is_none());
        }

        CommitmentsDb::set(txn, &id, &commitments);

        match secret_share_machines(id, params, prior, commitments) {
          Ok((machines, shares)) => {
            self.active_share.insert(id.session, (machines, shares.clone()));
            ProcessorMessage::Shares { id, shares }
          }
          Err(e) => e,
        }
      }

      CoordinatorMessage::Shares { id, shares } => {
        info!("Received shares for {:?}", id);

        let (params, share_quantity) = ParamsDb::get(txn, &id.session).unwrap();

        // Same commentary on inconsistency as above exists
        let (machines, our_shares) = self.active_share.remove(&id.session).unwrap_or_else(|| {
          let prior = key_gen_machines(id, params, share_quantity).0;
          let (machines, shares) =
            secret_share_machines(id, params, prior, CommitmentsDb::get(txn, &id).unwrap())
              .expect("got Shares for a key gen which faulted");
          (machines, shares)
        });

        let mut rng = share_rng(id);

        fn handle_machine<C: Ciphersuite>(
          rng: &mut ChaCha20Rng,
          id: KeyGenId,
          // These are the params of our first share, not this machine's shares
          params: ThresholdParams,
          m: usize,
          machine: KeyMachine<C>,
          shares_ref: &mut HashMap<Participant, &[u8]>,
        ) -> Result<ThresholdCore<C>, ProcessorMessage> {
          let params = ThresholdParams::new(
            params.t(),
            params.n(),
            Participant::new(u16::from(params.i()) + u16::try_from(m).unwrap()).unwrap(),
          )
          .unwrap();

          // Parse the shares
          let mut shares = HashMap::new();
          for i in 1 ..= params.n() {
            let i = Participant::new(i).unwrap();
            let Some(share) = shares_ref.get_mut(&i) else { continue };
            shares.insert(
              i,
              EncryptedMessage::<C, SecretShare<C::F>>::read(share, params).map_err(|_| {
                ProcessorMessage::InvalidShare { id, accuser: params.i(), faulty: i, blame: None }
              })?,
            );
          }

          Ok(
            (match machine.calculate_share(rng, shares) {
              Ok(res) => res,
              Err(e) => match e {
                DkgError::ZeroParameter(_, _) |
                DkgError::InvalidThreshold(_, _) |
                DkgError::InvalidParticipant(_, _) |
                DkgError::InvalidSigningSet |
                DkgError::InvalidCommitments(_) => unreachable!("{e:?}"),
                DkgError::InvalidParticipantQuantity(_, _) |
                DkgError::DuplicatedParticipant(_) |
                DkgError::MissingParticipant(_) => {
                  panic!("coordinator sent invalid DKG shares: {e:?}")
                }
                DkgError::InvalidShare { participant, blame } => {
                  Err(ProcessorMessage::InvalidShare {
                    id,
                    accuser: params.i(),
                    faulty: participant,
                    blame: Some(blame.map(|blame| blame.serialize())).flatten(),
                  })?
                }
              },
            })
            .complete(),
          )
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

          let these_substrate_keys =
            match handle_machine(&mut rng, id, params, m, machines.0, &mut shares_ref) {
              Ok(keys) => keys,
              Err(msg) => return msg,
            };
          let these_network_keys =
            match handle_machine(&mut rng, id, params, m, machines.1, &mut shares_ref) {
              Ok(keys) => keys,
              Err(msg) => return msg,
            };

          for i in 1 ..= params.n() {
            let i = Participant::new(i).unwrap();
            let Some(shares) = shares_ref.get(&i) else { continue };
            if !shares.is_empty() {
              return ProcessorMessage::InvalidShare {
                id,
                accuser: these_substrate_keys.params().i(),
                faulty: i,
                blame: None,
              };
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

      CoordinatorMessage::VerifyBlame { id, accuser, accused, share, blame } => {
        let params = ParamsDb::get(txn, &id.session).unwrap().0;

        let mut share_ref = share.as_slice();
        let Ok(substrate_share) = EncryptedMessage::<
          Ristretto,
          SecretShare<<Ristretto as Ciphersuite>::F>,
        >::read(&mut share_ref, params) else {
          return ProcessorMessage::Blame { id, participant: accused };
        };
        let Ok(network_share) = EncryptedMessage::<
          N::Curve,
          SecretShare<<N::Curve as Ciphersuite>::F>,
        >::read(&mut share_ref, params) else {
          return ProcessorMessage::Blame { id, participant: accused };
        };
        if !share_ref.is_empty() {
          return ProcessorMessage::Blame { id, participant: accused };
        }

        let mut substrate_commitment_msgs = HashMap::new();
        let mut network_commitment_msgs = HashMap::new();
        let commitments = CommitmentsDb::get(txn, &id).unwrap();
        for (i, commitments) in commitments {
          let mut commitments = commitments.as_slice();
          substrate_commitment_msgs
            .insert(i, EncryptionKeyMessage::<_, _>::read(&mut commitments, params).unwrap());
          network_commitment_msgs
            .insert(i, EncryptionKeyMessage::<_, _>::read(&mut commitments, params).unwrap());
        }

        // There is a mild DoS here where someone with a valid blame bloats it to the maximum size
        // Given the ambiguity, and limited potential to DoS (this being called means *someone* is
        // getting fatally slashed) voids the need to ensure blame is minimal
        let substrate_blame =
          blame.clone().and_then(|blame| EncryptionKeyProof::read(&mut blame.as_slice()).ok());
        let network_blame =
          blame.clone().and_then(|blame| EncryptionKeyProof::read(&mut blame.as_slice()).ok());

        let substrate_blame = AdditionalBlameMachine::new(
          &mut rand_core::OsRng,
          context(&id, SUBSTRATE_KEY_CONTEXT),
          params.n(),
          substrate_commitment_msgs,
        )
        .unwrap()
        .blame(accuser, accused, substrate_share, substrate_blame);
        let network_blame = AdditionalBlameMachine::new(
          &mut rand_core::OsRng,
          context(&id, NETWORK_KEY_CONTEXT),
          params.n(),
          network_commitment_msgs,
        )
        .unwrap()
        .blame(accuser, accused, network_share, network_blame);

        // If thw accused was blamed for either, mark them as at fault
        if (substrate_blame == accused) || (network_blame == accused) {
          return ProcessorMessage::Blame { id, participant: accused };
        }

        ProcessorMessage::Blame { id, participant: accuser }
      }
    }
  }

  pub async fn confirm(
    &mut self,
    txn: &mut D::Transaction<'_>,
    session: Session,
    key_pair: KeyPair,
  ) -> KeyConfirmed<N::Curve> {
    info!(
      "Confirmed key pair {} {} for {:?}",
      hex::encode(key_pair.0),
      hex::encode(&key_pair.1),
      session,
    );

    let (substrate_keys, network_keys) = KeysDb::confirm_keys::<N>(txn, session, key_pair);

    KeyConfirmed { substrate_keys, network_keys }
  }
}
