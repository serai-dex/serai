use std::{
  time::Duration,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};

use dkg::Participant;

use serai_client::{
  PairTrait, PairSigner,
  primitives::{
    NetworkId, Coin, Amount, Balance, BlockHash, SeraiAddress, ExternalAddress,
    insecure_pair_from_name,
  },
  tokens::{
    primitives::{OutInstruction, OutInstructionWithBalance},
    TokensEvent,
  },
  in_instructions::primitives::{InInstruction, InInstructionWithBalance, Batch},
};
use messages::{sign::SignId, SubstrateContext, CoordinatorMessage};

use crate::{*, tests::*};

pub async fn sign<C: Ciphersuite>(
  processors: &mut [Processor],
  network_key: &Zeroizing<C::F>,
  plan_id: [u8; 32],
) {
  let id = SignId {
    key: (C::generator() * **network_key).to_bytes().as_ref().to_vec(),
    id: plan_id,
    attempt: 0,
  };

  // Select a random participant to exclude, so we know for sure who *is* participating
  assert_eq!(COORDINATORS - THRESHOLD, 1);
  let excluded_signer =
    usize::try_from(OsRng.next_u64() % u64::try_from(processors.len()).unwrap()).unwrap();
  for (i, processor) in processors.iter_mut().enumerate() {
    if i == excluded_signer {
      continue;
    }

    processor
      .send_message(messages::sign::ProcessorMessage::Preprocess {
        id: id.clone(),
        preprocess: [u8::try_from(i).unwrap(); 64].to_vec(),
      })
      .await;
  }
  // Before this plan is signed, the Tributary will agree the triggering Substrate block occurred,
  // adding an extra step of latency
  wait_for_tributary().await;
  wait_for_tributary().await;

  // Send from the excluded signer so they don't stay stuck
  processors[excluded_signer]
    .send_message(messages::sign::ProcessorMessage::Preprocess {
      id: id.clone(),
      preprocess: [u8::try_from(excluded_signer).unwrap(); 64].to_vec(),
    })
    .await;

  // Read from a known signer to find out who was selected to sign
  let known_signer = (excluded_signer + 1) % COORDINATORS;
  let participants = match processors[known_signer].recv_message().await {
    CoordinatorMessage::Sign(messages::sign::CoordinatorMessage::Preprocesses {
      id: this_id,
      preprocesses,
    }) => {
      assert_eq!(&id, &this_id);
      assert_eq!(preprocesses.len(), THRESHOLD - 1);
      assert!(!preprocesses
        .contains_key(&Participant::new(u16::try_from(known_signer).unwrap() + 1).unwrap()));

      let mut participants =
        preprocesses.keys().map(|p| usize::from(u16::from(*p)) - 1).collect::<HashSet<_>>();
      for (p, preprocess) in preprocesses {
        assert_eq!(preprocess, vec![u8::try_from(u16::from(p)).unwrap() - 1; 64]);
      }
      participants.insert(known_signer);
      participants
    }
    _ => panic!("coordinator didn't send back Preprocesses"),
  };

  for i in participants.clone() {
    if i == known_signer {
      continue;
    }

    let processor = &mut processors[i];
    let mut preprocesses = participants
      .clone()
      .into_iter()
      .map(|i| {
        (
          Participant::new(u16::try_from(i + 1).unwrap()).unwrap(),
          [u8::try_from(i).unwrap(); 64].to_vec(),
        )
      })
      .collect::<HashMap<_, _>>();
    preprocesses.remove(&Participant::new(u16::try_from(i + 1).unwrap()).unwrap());

    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::Sign(messages::sign::CoordinatorMessage::Preprocesses {
        id: id.clone(),
        preprocesses
      })
    );
  }

  for i in participants.clone() {
    let processor = &mut processors[i];
    processor
      .send_message(messages::sign::ProcessorMessage::Share {
        id: id.clone(),
        share: vec![u8::try_from(i).unwrap(); 32],
      })
      .await;
  }
  wait_for_tributary().await;
  for i in participants.clone() {
    let processor = &mut processors[i];
    let mut shares = participants
      .clone()
      .into_iter()
      .map(|i| {
        (
          Participant::new(u16::try_from(i + 1).unwrap()).unwrap(),
          vec![u8::try_from(i).unwrap(); 32],
        )
      })
      .collect::<HashMap<_, _>>();
    shares.remove(&Participant::new(u16::try_from(i + 1).unwrap()).unwrap());

    assert_eq!(
      processor.recv_message().await,
      CoordinatorMessage::Sign(messages::sign::CoordinatorMessage::Shares {
        id: id.clone(),
        shares,
      })
    );
  }

  // TODO: Completed flow
}

#[tokio::test]
async fn sign_test() {
  let (processors, test) = new_test();

  test
    .run_async(|ops| async move {
      // Wait for the Serai node to boot, and for the Tendermint chain to get past the first block
      // TODO: Replace this with a Coordinator RPC
      tokio::time::sleep(Duration::from_secs(150)).await;

      // Sleep even longer if in the CI due to it being slower than commodity hardware
      if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
        tokio::time::sleep(Duration::from_secs(120)).await;
      }

      // Connect to the Message Queues as the processor
      let mut new_processors: Vec<Processor> = vec![];
      for (handles, key) in processors {
        new_processors.push(Processor::new(NetworkId::Bitcoin, &ops, handles, key).await);
      }
      let mut processors = new_processors;

      let (substrate_key, network_key) = key_gen::<Secp256k1>(&mut processors).await;

      // 'Send' external coins into Serai
      let serai = processors[0].serai().await;
      let (serai_pair, serai_addr) = {
        let mut name = [0; 4];
        OsRng.fill_bytes(&mut name);
        let pair = insecure_pair_from_name(&hex::encode(name));
        let address = SeraiAddress::from(pair.public());

        // Fund the new account to pay for fees
        serai
          .publish(
            &serai
              .sign(
                &PairSigner::new(insecure_pair_from_name("Ferdie")),
                &Serai::transfer_sri(address, Amount(1_000_000_000)),
                0,
                Default::default(),
              )
              .unwrap(),
          )
          .await
          .unwrap();

        (PairSigner::new(pair), address)
      };

      #[allow(clippy::inconsistent_digit_grouping)]
      let amount = Amount(1_000_000_00);
      let balance = Balance { coin: Coin::Bitcoin, amount };

      let coin_block = BlockHash([0x33; 32]);
      let block_included_in = batch::<Secp256k1>(
        &mut processors,
        &substrate_key,
        &network_key,
        Batch {
          network: NetworkId::Bitcoin,
          id: 0,
          block: coin_block,
          instructions: vec![InInstructionWithBalance {
            instruction: InInstruction::Transfer(serai_addr),
            balance,
          }],
        },
      )
      .await;

      let block_included_in_hash =
        serai.get_block_by_number(block_included_in).await.unwrap().unwrap().hash();

      assert_eq!(
        serai.get_sri_balance(block_included_in_hash, serai_addr).await.unwrap(),
        1_000_000_000
      );

      // Verify the mint occurred as expected
      assert_eq!(
        serai.get_mint_events(block_included_in_hash).await.unwrap(),
        vec![TokensEvent::Mint { address: serai_addr, balance }]
      );
      assert_eq!(
        serai.get_token_supply(block_included_in_hash, Coin::Bitcoin).await.unwrap(),
        amount
      );
      assert_eq!(
        serai.get_token_balance(block_included_in_hash, Coin::Bitcoin, serai_addr).await.unwrap(),
        amount
      );

      // Trigger a burn
      let out_instruction =
        OutInstruction { address: ExternalAddress::new(b"external".to_vec()).unwrap(), data: None };
      serai
        .publish(
          &serai
            .sign(
              &serai_pair,
              &Serai::burn(balance, out_instruction.clone()),
              0,
              Default::default(),
            )
            .unwrap(),
        )
        .await
        .unwrap();

      // TODO: We *really* need a helper for this pattern
      let mut last_serai_block = block_included_in;
      'outer: for _ in 0 .. 20 {
        tokio::time::sleep(Duration::from_secs(6)).await;
        if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
          tokio::time::sleep(Duration::from_secs(6)).await;
        }

        while last_serai_block <= serai.get_latest_block().await.unwrap().number() {
          let burn_events = serai
            .get_burn_events(
              serai.get_block_by_number(last_serai_block).await.unwrap().unwrap().hash(),
            )
            .await
            .unwrap();

          if !burn_events.is_empty() {
            assert_eq!(burn_events.len(), 1);
            assert_eq!(
              burn_events[0],
              TokensEvent::Burn {
                address: serai_addr,
                balance,
                instruction: out_instruction.clone()
              }
            );
            break 'outer;
          }
          last_serai_block += 1;
        }
      }

      let last_serai_block = serai.get_block_by_number(last_serai_block).await.unwrap().unwrap();
      let last_serai_block_hash = last_serai_block.hash();
      assert_eq!(
        serai.get_token_supply(last_serai_block_hash, Coin::Bitcoin).await.unwrap(),
        Amount(0)
      );
      assert_eq!(
        serai.get_token_balance(last_serai_block_hash, Coin::Bitcoin, serai_addr).await.unwrap(),
        Amount(0)
      );

      let mut plan_id = [0; 32];
      OsRng.fill_bytes(&mut plan_id);
      let plan_id = plan_id;

      // We should now get a SubstrateBlock
      for processor in processors.iter_mut() {
        assert_eq!(
          processor.recv_message().await,
          messages::CoordinatorMessage::Substrate(
            messages::substrate::CoordinatorMessage::SubstrateBlock {
              context: SubstrateContext {
                serai_time: last_serai_block.time().unwrap() / 1000,
                network_latest_finalized_block: coin_block,
              },
              network: NetworkId::Bitcoin,
              block: last_serai_block.number(),
              key: (Secp256k1::generator() * *network_key).to_bytes().to_vec(),
              burns: vec![OutInstructionWithBalance {
                instruction: out_instruction.clone(),
                balance: Balance { coin: Coin::Bitcoin, amount }
              }],
              batches: vec![],
            }
          )
        );

        // Send the ACK, claiming there's a plan to sign
        processor
          .send_message(messages::ProcessorMessage::Coordinator(
            messages::coordinator::ProcessorMessage::SubstrateBlockAck {
              network: NetworkId::Bitcoin,
              block: last_serai_block.number(),
              plans: vec![plan_id],
            },
          ))
          .await;
      }

      sign::<Secp256k1>(&mut processors, &network_key, plan_id).await;
    })
    .await;
}
