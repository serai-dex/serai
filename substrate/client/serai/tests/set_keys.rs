use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore as _, OsRng};

use sp_core::{Pair as _, sr25519::Pair};
use sp_application_crypto::RuntimePublic as _;

use ciphersuite::{group::GroupEncoding as _, GroupIo, WrappedGroup as _};
use musig::{Participant, ThresholdKeys, musig};
use dalek_ff_group::Ristretto;
use schnorrkel::Schnorrkel;

use serai_client_serai::{
  abi::{
    primitives::{
      BlockHash,
      crypto::{Public, EmbeddedEllipticCurveKeys, ExternalKey, KeyPair},
      network_id::ExternalNetworkId,
      validator_sets::{Session, ExternalValidatorSet, ValidatorSet},
    },
    Transaction,
    validator_sets::Event as ValidatorSetsEvent,
  },
  Serai, ValidatorSets,
};

/// Publish a transaction, yielding the hash of the block which included it.
pub async fn publish_tx(serai: &Serai, tx: &Transaction) -> BlockHash {
  serai.publish_transaction(tx).await.unwrap();

  // Get the block it was included in
  // TODO: Add an RPC method for this/check the guarantee on the subscription
  for _ in 0 .. 60 {
    tokio::time::sleep(Duration::from_secs(1)).await;

    let latest = serai.latest_finalized_block_number().await.unwrap();
    let block = serai.block_by_number(latest).await.unwrap().unwrap();

    for transaction in &block.transactions {
      if transaction == tx {
        return block.header.hash();
      }
    }
  }
  panic!("transaction wasn't included in a finalized block within 60 seconds");
}

/// Set a validator set's keys on the Serai network.
///
/// This requires the pairs to be declared in the exact order they'll be expected in on-chain.
pub async fn set_keys(
  serai: &Serai,
  set: ExternalValidatorSet,
  key_pair: KeyPair,
  pairs: &[Pair],
) -> BlockHash {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key = <Ristretto as GroupIo>::read_G(pair.public().0.as_slice()).unwrap();
    pub_keys.push(public_key);
  }

  let mut musig_keys = HashMap::new();
  for i in 0 .. pairs.len() {
    let secret_key =
      <Ristretto as GroupIo>::read_F(&pairs[i].as_ref().secret.to_bytes()[.. 32]).unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    let keys = musig::<Ristretto>(
      ValidatorSet::from(set).musig_context(),
      Zeroizing::new(secret_key),
      &pub_keys,
    )
    .unwrap();
    assert_eq!(
      sp_core::sr25519::Public::from(keys.group_key().to_bytes()),
      ValidatorSet::from(set)
        .musig_key(&pub_keys.iter().map(|pub_key| pub_key.to_bytes().into()).collect::<Vec<_>>())
        .unwrap()
    );
    musig_keys.insert(keys.params().i(), keys);
  }

  // Map from the `Ristretto` ciphersuite used for MuSig to the `Ristretto` ciphersuite used for
  // signing, the former preferring Blake2b and the latter derived from FROST's IRTF standard
  let musig_keys = musig_keys
    .into_iter()
    .map(|(i, keys)| {
      (
        i,
        ThresholdKeys::<frost::curve::Ristretto>::new(
          keys.params(),
          keys.interpolation().clone(),
          keys.original_secret_share().clone(),
          (1 ..= keys.params().n())
            .map(|i| {
              let i = Participant::new(i).unwrap();
              (i, keys.original_verification_share(i))
            })
            .collect::<HashMap<_, _>>(),
        )
        .unwrap(),
      )
    })
    .collect::<HashMap<_, _>>();

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys),
    &set.set_keys_message(&key_pair),
  );
  assert!(
    sp_core::sr25519::Public::from(musig_keys.values().next().unwrap().group_key().to_bytes())
      .verify(&set.set_keys_message(&key_pair), &sig.to_bytes().into())
  );

  // Set the key pair
  let block = publish_tx(
    serai,
    &ValidatorSets::set_keys(
      set.network,
      key_pair.clone(),
      {
        let mut signature_participants = bitvec::vec::BitVec::new();
        for _ in 0 .. pairs.len() {
          signature_participants.push(true);
        }
        signature_participants.try_into().unwrap()
      },
      sig.into(),
    ),
  )
  .await;

  assert_eq!(
    serai
      .events(block)
      .await
      .unwrap()
      .validator_sets()
      .set_keys_events()
      .cloned()
      .collect::<Vec<_>>(),
    vec![ValidatorSetsEvent::SetKeys { set, key_pair: key_pair.clone() }]
  );
  assert_eq!(serai.state().await.unwrap().keys(set).await.unwrap(), Some(key_pair));

  block
}

#[tokio::test]
async fn test_set_keys() {
  let mut test = dockertest::DockerTest::new();
  let (composition, handle) = serai_substrate_tests::composition(
    "alice",
    serai_docker_tests::fresh_logs_folder(true, "serai-client/set_keys"),
  );
  test.provide_container(
    composition
      .replace_cmd(["serai-node", "--network", "solo"].into_iter().map(str::to_owned).collect())
      .replace_env([("RUST_LOG".to_owned(), "runtime=debug".to_owned())].into()),
  );

  test
    .run_async(async |ops| {
      let serai = serai_substrate_tests::rpc(&ops, handle).await;

      'outer: {
        for _ in 0 .. (5 * 10) {
          tokio::time::sleep(Duration::from_secs(6)).await;

          let latest_finalized = serai.latest_finalized_block_number().await.unwrap();
          if latest_finalized > 0 {
            break 'outer;
          }
        }
        panic!("finalized block remained the genesis block for over five minutes");
      };

      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      let aux_keys = Pair::from_string("//Alice", None).unwrap();
      {
        let mut found = false;
        let genesis_block = serai.block_by_number(0).await.unwrap().unwrap();
        let events = serai.events(genesis_block.header.hash()).await.unwrap();
        for event in events.validator_sets().set_embedded_elliptic_curve_keys_events() {
          if let ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
            validator: _,
            keys: EmbeddedEllipticCurveKeys::Serai(key),
          } = event
          {
            assert_eq!(*key, <[u8; 32]>::from(aux_keys.public()));
            found = true;
          }
        }
        assert!(found);
      }

      let key_pair = KeyPair(
        {
          let mut public = [0; 32];
          OsRng.fill_bytes(&mut public);
          Public(public)
        },
        {
          #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
          let mut external_key =
            vec![0; (OsRng.next_u64() as usize) % (ExternalKey::MAX_SIZE as usize)];
          OsRng.fill_bytes(&mut external_key);
          ExternalKey(external_key.try_into().unwrap())
        },
      );

      set_keys(&serai, set, key_pair, &[aux_keys]).await;
    })
    .await;
}
