use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{Ciphersuite, Ristretto};
use frost::{
  FrostError,
  dkg::{Participant, musig::musig},
  sign::*,
};
use frost_schnorrkel::Schnorrkel;

use serai_client::{
  Signature,
  validator_sets::primitives::{ValidatorSet, KeyPair, musig_context, set_keys_message},
  subxt::utils::Encoded,
  Serai,
};

use tokio::sync::mpsc::UnboundedSender;

use tributary::{
  Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, decode_evidence},
    TendermintNetwork,
  },
};

use serai_db::{Get, DbTxn};

use crate::{
  Db,
  tributary::handle::handle_application_tx,
  processors::Processors,
  tributary::{TributaryDb, TributarySpec, Transaction},
  P2p,
};

const DKG_CONFIRMATION_NONCES: &[u8] = b"dkg_confirmation_nonces";
const DKG_CONFIRMATION_SHARES: &[u8] = b"dkg_confirmation_shares";

// Instead of maintaing state, this simply re-creates the machine(s) in-full on every call.
// This simplifies data flow and prevents requiring multiple paths.
// While more expensive, this only runs an O(n) algorithm, which is tolerable to run multiple
// times.
struct DkgConfirmer;
impl DkgConfirmer {
  fn preprocess_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // TODO: Does Substrate already have a validator-uniqueness check?
    let validators = spec.validators().iter().map(|val| val.0).collect::<Vec<_>>();

    let context = musig_context(spec.set());
    let mut chacha = ChaCha20Rng::from_seed({
      let mut entropy_transcript = RecommendedTranscript::new(b"DkgConfirmer Entropy");
      entropy_transcript.append_message(b"spec", spec.serialize());
      entropy_transcript.append_message(b"key", Zeroizing::new(key.to_bytes()));
      // TODO: This is incredibly insecure unless message-bound (or bound via the attempt)
      Zeroizing::new(entropy_transcript).rng_seed(b"preprocess")
    });
    let (machine, preprocess) = AlgorithmMachine::new(
      Schnorrkel::new(b"substrate"),
      musig(&context, key, &validators)
        .expect("confirming the DKG for a set we aren't in/validator present multiple times")
        .into(),
    )
    .preprocess(&mut chacha);

    (machine, preprocess.serialize().try_into().unwrap())
  }
  // Get the preprocess for this confirmation.
  fn preprocess(spec: &TributarySpec, key: &Zeroizing<<Ristretto as Ciphersuite>::F>) -> [u8; 64] {
    Self::preprocess_internal(spec, key).1
  }

  fn share_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let machine = Self::preprocess_internal(spec, key).0;
    let preprocesses = preprocesses
      .into_iter()
      .map(|(p, preprocess)| {
        machine
          .read_preprocess(&mut preprocess.as_slice())
          .map(|preprocess| (p, preprocess))
          .map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let (machine, share) = machine
      .sign(preprocesses, &set_keys_message(&spec.set(), key_pair))
      .map_err(|e| match e {
        FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
        FrostError::InvalidParticipant(_, _) |
        FrostError::InvalidSigningSet(_) |
        FrostError::InvalidParticipantQuantity(_, _) |
        FrostError::DuplicatedParticipant(_) |
        FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
        FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
      })?;

    Ok((machine, share.serialize().try_into().unwrap()))
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  fn share(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<[u8; 32], Participant> {
    Self::share_internal(spec, key, preprocesses, key_pair).map(|(_, share)| share)
  }

  fn complete(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    let machine = Self::share_internal(spec, key, preprocesses, key_pair)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

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

#[allow(clippy::too_many_arguments)] // TODO
fn read_known_to_exist_data<D: Db, G: Get>(
  getter: &G,
  spec: &TributarySpec,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  label: &'static [u8],
  id: [u8; 32],
  needed: u16,
  attempt: u32,
  bytes: Vec<u8>,
  signed: Option<&Signed>,
) -> HashMap<Participant, Vec<u8>> {
  let mut data = HashMap::new();
  for validator in spec.validators().iter().map(|validator| validator.0) {
    data.insert(
      spec.i(validator).unwrap(),
      if Some(&validator) == signed.map(|signed| &signed.signer) {
        bytes.clone()
      } else if let Some(data) =
        TributaryDb::<D>::data(label, getter, spec.genesis(), id, attempt, validator)
      {
        data
      } else {
        continue;
      },
    );
  }
  assert_eq!(data.len(), usize::from(needed));

  // Remove our own piece of data
  assert!(data
    .remove(
      &spec
        .i(Ristretto::generator() * key.deref())
        .expect("handling a message for a Tributary we aren't part of")
    )
    .is_some());

  data
}

pub fn dkg_confirmation_nonces(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
) -> [u8; 64] {
  DkgConfirmer::preprocess(spec, key)
}

#[allow(clippy::needless_pass_by_ref_mut)]
pub fn generated_key_pair<D: Db>(
  txn: &mut D::Transaction<'_>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  key_pair: &KeyPair,
) -> Result<[u8; 32], Participant> {
  TributaryDb::<D>::save_currently_completing_key_pair(txn, spec.genesis(), key_pair);

  let attempt = 0; // TODO
  let preprocesses = read_known_to_exist_data::<D, _>(
    txn,
    spec,
    key,
    DKG_CONFIRMATION_NONCES,
    [0; 32],
    spec.n(),
    attempt,
    vec![],
    None,
  );
  DkgConfirmer::share(spec, key, preprocesses, key_pair)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecognizedIdType {
  Block,
  Plan,
}

// Handle a specific Tributary block
#[allow(clippy::needless_pass_by_ref_mut)] // False positive?
async fn handle_block<
  D: Db,
  Pro: Processors,
  F: Future<Output = ()>,
  PST: Fn(ValidatorSet, Encoded) -> F,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  block: Block<Transaction>,
) {
  log::info!("found block for Tributary {:?}", spec.set());

  let genesis = spec.genesis();
  let hash = block.hash();

  let mut event_id = 0; // TODO: should start from -1 so that we need only 1 event_id += 1?
  #[allow(clippy::explicit_counter_loop)] // event_id isn't TX index. It just currently lines up
  for tx in block.transactions {
    if TributaryDb::<D>::handled_event(&db.0, hash, event_id) {
      event_id += 1;
      continue;
    }

    let mut txn = db.0.txn();

    match tx {
      TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
        // since the evidence is on the chain, it already
        // should be valid. So we can just punish the signer.
        let msgs = decode_evidence::<TendermintNetwork<D, Transaction, P>>(&ev).unwrap();

        // mark the node as fatally slashed
        TributaryDb::<D>::set_fatally_slashed(&mut txn, genesis, msgs[0].msg.sender);

        // TODO: disconnect the node from network
      },
      TributaryTransaction::Tendermint(TendermintTx::SlashVote(_, _)) => {
        // TODO: make sure same signer doesn't vote twice

        // increment the counter for this vote
        let vote_key = TributaryDb::<D>::slash_vote_key(genesis, vote.id, vote.target);
        let mut count =
          txn.get(&vote_key).map_or(0, |c| u32::from_le_bytes(c.try_into().unwrap()));
        count += 1;
        txn.put(vote_key, count.to_le_bytes());

        // TODO: check whether 2/3 of all validators voted.
        // and increment the slash points if yes.
        // if a node has a certain number more than the median slash points,
        // the node should be removed.
      }
      TributaryTransaction::Application(tx) => {
        handle_application_tx::<D, Pro>(
          tx,
          spec,
          processors,
          genesis,
          key,
          recognized_id,
          &mut txn,
        )
        .await;
      }
    }

    TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
    txn.commit();

    event_id += 1;
  }

  // TODO: Trigger any necessary re-attempts
}

pub async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  F: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> F,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = db.last_block(genesis);
  while let Some(next) = tributary.block_after(&last_block) {
    let block = tributary.block(&next).unwrap();
    handle_block<_, _, _, _, P>(db, key, recognized_id, processors, publish_serai_tx.clone(), spec, block).await;
    last_block = next;
    db.set_last_block(genesis, next);
  }
}
