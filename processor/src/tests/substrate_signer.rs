use std::{
  time::{Duration, SystemTime},
  collections::HashMap,
};

use rand_core::OsRng;

use group::GroupEncoding;
use frost::{
  curve::Ristretto,
  Participant,
  dkg::tests::{key_gen, clone_without},
};

use tokio::time::timeout;

use scale::Encode;
use sp_application_crypto::{RuntimePublic, sr25519::Public};

use serai_db::MemDb;

use serai_client::{primitives::*, in_instructions::primitives::*};

use messages::{sign::SignId, coordinator::*};
use crate::substrate_signer::{SubstrateSignerEvent, SubstrateSigner};

#[tokio::test]
async fn test_substrate_signer() {
  let mut keys = key_gen::<_, Ristretto>(&mut OsRng);

  let participant_one = Participant::new(1).unwrap();

  let block = BlockHash([0xaa; 32]);
  let actual_id =
    SignId { key: keys[&participant_one].group_key().to_bytes().to_vec(), id: block.0, attempt: 0 };

  let batch = Batch {
    network: MONERO_NET_ID,
    id: 5,
    block,
    instructions: vec![
      InInstructionWithBalance {
        instruction: InInstruction::Transfer(SeraiAddress([0xbb; 32])),
        balance: Balance { coin: BITCOIN, amount: Amount(1000) },
      },
      InInstructionWithBalance {
        instruction: InInstruction::Call(ApplicationCall {
          application: Application::DEX,
          data: Data::new(vec![0xcc; 128]).unwrap(),
        }),
        balance: Balance { coin: MONERO, amount: Amount(9999999999999999) },
      },
    ],
  };

  let signing_set = actual_id.signing_set(&keys[&participant_one].params());
  for these_keys in keys.values() {
    assert_eq!(actual_id.signing_set(&these_keys.params()), signing_set);
  }

  let start = SystemTime::now();
  let mut signers = HashMap::new();
  for i in 1 ..= keys.len() {
    let i = Participant::new(u16::try_from(i).unwrap()).unwrap();
    let signer = SubstrateSigner::new(MemDb::new(), keys.remove(&i).unwrap());
    signer.sign(start, batch.clone()).await;
    signers.insert(i, signer);
  }

  let mut preprocesses = HashMap::new();
  for i in &signing_set {
    if let Some(SubstrateSignerEvent::ProcessorMessage(ProcessorMessage::BatchPreprocess {
      id,
      preprocess,
    })) = signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, actual_id);
      preprocesses.insert(*i, preprocess);
    } else {
      panic!("didn't get preprocess back");
    }
  }

  let mut shares = HashMap::new();
  for i in &signing_set {
    signers[i]
      .handle(CoordinatorMessage::BatchPreprocesses {
        id: actual_id.clone(),
        preprocesses: clone_without(&preprocesses, i),
      })
      .await;
    if let Some(SubstrateSignerEvent::ProcessorMessage(ProcessorMessage::BatchShare {
      id,
      share,
    })) = signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(id, actual_id);
      shares.insert(*i, share);
    } else {
      panic!("didn't get share back");
    }
  }

  for i in &signing_set {
    signers[i]
      .handle(CoordinatorMessage::BatchShares {
        id: actual_id.clone(),
        shares: clone_without(&shares, i),
      })
      .await;

    if let Some(SubstrateSignerEvent::SignedBatch(signed_batch)) =
      signers.get_mut(i).unwrap().events.recv().await
    {
      assert_eq!(signed_batch.batch, batch);
      assert!(Public::from_raw(actual_id.key.clone().try_into().unwrap())
        .verify(&batch.encode(), &signed_batch.signature));
    } else {
      panic!("didn't get signed batch back");
    }
  }

  // Make sure the signers not included didn't do anything
  let mut excluded = (1 ..= signers.len())
    .map(|i| Participant::new(u16::try_from(i).unwrap()).unwrap())
    .collect::<Vec<_>>();
  for i in signing_set {
    excluded.remove(excluded.binary_search(&i).unwrap());
  }
  for i in excluded {
    assert!(timeout(
      Duration::from_secs(5),
      signers.get_mut(&Participant::new(u16::try_from(i).unwrap()).unwrap()).unwrap().events.recv()
    )
    .await
    .is_err());
  }
}
