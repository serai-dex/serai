/*
  A MuSig-based signing protocol executed with the validators' keys.

  This is used for confirming the results of a DKG on-chain, an operation requiring all validators
  which aren't specified as removed while still satisfying a supermajority.

  Since we're using the validator's keys, as needed for their being the root of trust, the
  coordinator must perform the signing. This is distinct from all other group-signing operations,
  as they're all done by the processor.

  The MuSig-aggregation achieves on-chain efficiency and enables a more secure design pattern.
  While we could individually tack votes, that'd require logic to prevent voting multiple times and
  tracking the accumulated votes. MuSig-aggregation simply requires checking the list is sorted and
  the list's weight exceeds the threshold.

  Instead of maintaining state in memory, a combination of the DB and re-execution are used. This
  is deemed acceptable re: performance as:

  1) This is only done prior to a DKG being confirmed on Substrate and is assumed infrequent.
  2) This is an O(n) algorithm.
  3) The size of the validator set is bounded by MAX_KEY_SHARES_PER_SET.

  Accordingly, this should be tolerable.

  As for safety, it is explicitly unsafe to reuse nonces across signing sessions. This raises
  concerns regarding our re-execution which is dependent on fixed nonces. Safety is derived from
  the nonces being context-bound under a BFT protocol. The flow is as follows:

  1) Decide the nonce.
  2) Publish the nonces' commitments, receiving everyone elses *and potentially the message to be
     signed*.
  3) Sign and publish the signature share.

  In order for nonce re-use to occur, the received nonce commitments (or the message to be signed)
  would have to be distinct and sign would have to be called again.

  Before we act on any received messages, they're ordered and finalized by a BFT algorithm. The
  only way to operate on distinct received messages would be if:

  1) A logical flaw exists, letting new messages over write prior messages
  2) A reorganization occurred from chain A to chain B, and with it, different messages

  Reorganizations are not supported, as BFT is assumed by the presence of a BFT algorithm. While
  a significant amount of processes may be byzantine, leading to BFT being broken, that still will
  not trigger a reorganization. The only way to move to a distinct chain, with distinct messages,
  would be by rebuilding the local process (this time following chain B). Upon any complete
  rebuild, we'd re-decide nonces, achieving safety. This does set a bound preventing partial
  rebuilds which is accepted.

  Additionally, to ensure a rebuilt service isn't flagged as malicious, we have to check the
  commitments generated from the decided nonces are in fact its commitments on-chain (TODO).

  TODO: We also need to review how we're handling Processor preprocesses and likely implement the
  same on-chain-preprocess-matches-presumed-preprocess check before publishing shares.
*/

use core::ops::Deref;
use std::collections::{HashSet, HashMap};

use zeroize::{Zeroize, Zeroizing};

use rand_core::OsRng;

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};
use frost::{
  FrostError,
  dkg::{Participant, musig::musig},
  ThresholdKeys,
  sign::*,
};
use frost_schnorrkel::Schnorrkel;

use scale::Encode;

#[rustfmt::skip]
use serai_client::validator_sets::primitives::{ValidatorSet, KeyPair, musig_context, set_keys_message};

use serai_db::*;

use crate::tributary::TributarySpec;

create_db!(
  SigningProtocolDb {
    CachedPreprocesses: (context: &impl Encode) -> [u8; 32]
    DataSignedWith: (context: &impl Encode) -> (Vec<u8>, HashMap<Participant, Vec<u8>>),
  }
);

struct SigningProtocol<'a, T: DbTxn, C: Encode> {
  pub(crate) key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub(crate) spec: &'a TributarySpec,
  pub(crate) txn: &'a mut T,
  pub(crate) context: C,
}

impl<T: DbTxn, C: Encode> SigningProtocol<'_, T, C> {
  fn preprocess_internal(
    &mut self,
    participants: &[<Ristretto as Ciphersuite>::G],
  ) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // Encrypt the cached preprocess as recovery of it will enable recovering the private key
    // While the DB isn't expected to be arbitrarily readable, it isn't a proper secret store and
    // shouldn't be trusted as one
    let mut encryption_key = {
      let mut encryption_key_preimage =
        Zeroizing::new(b"Cached Preprocess Encryption Key".to_vec());
      encryption_key_preimage.extend(self.context.encode());
      let repr = Zeroizing::new(self.key.to_repr());
      encryption_key_preimage.extend(repr.deref());
      Blake2s256::digest(&encryption_key_preimage)
    };
    let encryption_key_slice: &mut [u8] = encryption_key.as_mut();

    // Create the MuSig keys
    let keys: ThresholdKeys<Ristretto> =
      musig(&musig_context(self.spec.set()), self.key, participants)
        .expect("signing for a set we aren't in/validator present multiple times")
        .into();

    // Define the algorithm
    let algorithm = Schnorrkel::new(b"substrate");

    // Check if we've prior preprocessed
    if CachedPreprocesses::get(self.txn, &self.context).is_none() {
      // If we haven't, we create a machine solely to obtain the preprocess with
      let (machine, _) =
        AlgorithmMachine::new(algorithm.clone(), keys.clone()).preprocess(&mut OsRng);

      // Cache and save the preprocess to disk
      let mut cache = machine.cache();
      assert_eq!(cache.0.len(), 32);
      #[allow(clippy::needless_range_loop)]
      for b in 0 .. 32 {
        cache.0[b] ^= encryption_key_slice[b];
      }

      CachedPreprocesses::set(self.txn, &self.context, &cache.0);
    }

    // We're now guaranteed to have the preprocess, hence why this `unwrap` is safe
    let cached = CachedPreprocesses::get(self.txn, &self.context).unwrap();
    let mut cached = Zeroizing::new(cached);
    #[allow(clippy::needless_range_loop)]
    for b in 0 .. 32 {
      cached[b] ^= encryption_key_slice[b];
    }
    encryption_key_slice.zeroize();
    // Create the machine from the cached preprocess
    let (machine, preprocess) =
      AlgorithmSignMachine::from_cache(algorithm, keys, CachedPreprocess(cached));

    (machine, preprocess.serialize().try_into().unwrap())
  }

  fn share_internal(
    &mut self,
    participants: &[<Ristretto as Ciphersuite>::G],
    mut serialized_preprocesses: HashMap<Participant, Vec<u8>>,
    msg: &[u8],
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    // We can't clear the preprocess as we sitll need it to accumulate all of the shares
    // We do save the message we signed so any future calls with distinct messages panic
    // This assumes the txn deciding this data is committed before the share is broaadcast
    if let Some((existing_msg, existing_preprocesses)) =
      DataSignedWith::get(self.txn, &self.context)
    {
      assert_eq!(msg, &existing_msg, "obtaining a signature share for a distinct message");
      assert_eq!(
        &serialized_preprocesses, &existing_preprocesses,
        "obtaining a signature share with a distinct set of preprocesses"
      );
    } else {
      DataSignedWith::set(
        self.txn,
        &self.context,
        &(msg.to_vec(), serialized_preprocesses.clone()),
      );
    }

    // Get the preprocessed machine
    let (machine, _) = self.preprocess_internal(participants);

    // Deserialize all the preprocesses
    let mut participants = serialized_preprocesses.keys().copied().collect::<Vec<_>>();
    participants.sort();
    let mut preprocesses = HashMap::new();
    for participant in participants {
      preprocesses.insert(
        participant,
        machine
          .read_preprocess(&mut serialized_preprocesses.remove(&participant).unwrap().as_slice())
          .map_err(|_| participant)?,
      );
    }

    // Sign the share
    let (machine, share) = machine.sign(preprocesses, msg).map_err(|e| match e {
      FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
      FrostError::InvalidParticipant(_, _) |
      FrostError::InvalidSigningSet(_) |
      FrostError::InvalidParticipantQuantity(_, _) |
      FrostError::DuplicatedParticipant(_) |
      FrostError::MissingParticipant(_) => panic!("unexpected error during sign: {e:?}"),
      FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
    })?;

    Ok((machine, share.serialize().try_into().unwrap()))
  }

  fn complete_internal(
    machine: AlgorithmSignatureMachine<Ristretto, Schnorrkel>,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    let shares = shares
      .into_iter()
      .map(|(p, share)| {
        machine.read_share(&mut share.as_slice()).map(|share| (p, share)).map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let signature = machine.complete(shares).map_err(|e| match e {
      FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
      FrostError::InvalidParticipant(_, _) |
      FrostError::InvalidSigningSet(_) |
      FrostError::InvalidParticipantQuantity(_, _) |
      FrostError::DuplicatedParticipant(_) |
      FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
      FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
    })?;
    Ok(signature.to_bytes())
  }
}

// Get the keys of the participants, noted by their threshold is, and return a new map indexed by
// their MuSig is.
fn threshold_i_map_to_keys_and_musig_i_map(
  spec: &TributarySpec,
  our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  mut map: HashMap<Participant, Vec<u8>>,
) -> (Vec<<Ristretto as Ciphersuite>::G>, HashMap<Participant, Vec<u8>>) {
  // Insert our own index so calculations aren't offset
  let our_threshold_i = spec
    .i(<Ristretto as Ciphersuite>::generator() * our_key.deref())
    .expect("not in a set we're signing for")
    .start;
  // Asserts we weren't unexpectedly already present
  assert!(map.insert(our_threshold_i, vec![]).is_none());

  let spec_validators = spec.validators();
  let key_from_threshold_i = |threshold_i| {
    for (key, _) in &spec_validators {
      if threshold_i == spec.i(*key).expect("validator wasn't in a set they're in").start {
        return *key;
      }
    }
    panic!("requested info for threshold i which doesn't exist")
  };

  let mut sorted = vec![];
  let mut threshold_is = map.keys().copied().collect::<Vec<_>>();
  threshold_is.sort();
  for threshold_i in threshold_is {
    sorted.push((
      threshold_i,
      key_from_threshold_i(threshold_i),
      map.remove(&threshold_i).unwrap(),
    ));
  }

  // Now that signers are sorted, with their shares, create a map with the is needed for MuSig
  let mut participants = vec![];
  let mut map = HashMap::new();
  let mut our_musig_i = None;
  for (raw_i, (threshold_i, key, share)) in sorted.into_iter().enumerate() {
    let musig_i = Participant::new(u16::try_from(raw_i).unwrap() + 1).unwrap();
    if threshold_i == our_threshold_i {
      our_musig_i = Some(musig_i);
    }
    participants.push(key);
    map.insert(musig_i, share);
  }

  map.remove(&our_musig_i.unwrap()).unwrap();

  (participants, map)
}

type DkgConfirmerSigningProtocol<'a, T> =
  SigningProtocol<'a, T, (&'static [u8; 12], ValidatorSet, u32)>;

pub(crate) struct DkgConfirmer<'a, T: DbTxn> {
  key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &'a TributarySpec,
  txn: &'a mut T,
  attempt: u32,
}

impl<T: DbTxn> DkgConfirmer<'_, T> {
  pub(crate) fn new<'a>(
    key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &'a TributarySpec,
    txn: &'a mut T,
    attempt: u32,
  ) -> DkgConfirmer<'a, T> {
    DkgConfirmer { key, spec, txn, attempt }
  }

  fn signing_protocol(&mut self) -> DkgConfirmerSigningProtocol<'_, T> {
    let context = (b"DkgConfirmer", self.spec.set(), self.attempt);
    SigningProtocol { key: self.key, spec: self.spec, txn: self.txn, context }
  }

  fn preprocess_internal(&mut self) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // This preprocesses with just us as we only decide the participants after obtaining
    // preprocesses
    let participants = vec![<Ristretto as Ciphersuite>::generator() * self.key.deref()];
    self.signing_protocol().preprocess_internal(&participants)
  }
  // Get the preprocess for this confirmation.
  pub(crate) fn preprocess(&mut self) -> [u8; 64] {
    self.preprocess_internal().1
  }

  fn share_internal(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let (participants, preprocesses) =
      threshold_i_map_to_keys_and_musig_i_map(self.spec, self.key, preprocesses);
    let msg = set_keys_message(&self.spec.set(), key_pair);
    self.signing_protocol().share_internal(&participants, preprocesses, &msg)
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  pub(crate) fn share(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<[u8; 32], Participant> {
    self.share_internal(preprocesses, key_pair).map(|(_, share)| share)
  }

  pub(crate) fn complete(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    assert_eq!(preprocesses.keys().collect::<HashSet<_>>(), shares.keys().collect::<HashSet<_>>());

    let shares = threshold_i_map_to_keys_and_musig_i_map(self.spec, self.key, shares).1;

    let machine = self
      .share_internal(preprocesses, key_pair)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

    DkgConfirmerSigningProtocol::<'_, T>::complete_internal(machine, shares)
  }
}
