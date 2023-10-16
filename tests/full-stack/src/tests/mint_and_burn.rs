use std::{
  sync::{Arc, Mutex},
  time::{Duration, Instant},
  collections::HashSet,
};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use scale::Encode;

use serai_client::{
  primitives::{
    NetworkId, Coin, Amount, Balance, SeraiAddress, ExternalAddress, insecure_pair_from_name,
  },
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::primitives::Shorthand,
  coins::primitives::OutInstruction,
  PairTrait, PairSigner, SeraiCoins,
};

use crate::tests::*;

// TODO: Break this test out into functions re-usable across processor, processor e2e, and full
// stack tests
#[tokio::test]
async fn mint_and_burn_test() {
  let _one_at_a_time = ONE_AT_A_TIME.get_or_init(|| Mutex::new(())).lock();
  let (handles, test) = new_test();

  test
    .run_async(|ops| async move {
      let ops = Arc::new(ops);
      let serai = handles[0].serai(&ops).await;

      // Helper to mine a block on each network
      async fn mine_blocks(
        handles: &Vec<Handles>,
        ops: &DockerOperations,
        producer: &mut usize,
        count: usize,
      ) {
        // Pick a block producer via a round robin
        let producer_handles = &handles[*producer];
        *producer += 1;
        *producer %= handles.len();

        // Mine a Bitcoin block
        let bitcoin_blocks = {
          use bitcoin_serai::bitcoin::{
            secp256k1::{SECP256K1, SecretKey},
            PrivateKey, PublicKey,
            consensus::Encodable,
            network::constants::Network,
            address::Address,
          };

          let addr = Address::p2pkh(
            &PublicKey::from_private_key(
              SECP256K1,
              &PrivateKey::new(SecretKey::from_slice(&[0x01; 32]).unwrap(), Network::Bitcoin),
            ),
            Network::Regtest,
          );

          let rpc = producer_handles.bitcoin(ops).await;
          let mut res = Vec::with_capacity(count);
          for _ in 0 .. count {
            let hash = rpc
              .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, addr]))
              .await
              .unwrap()
              .swap_remove(0);

            let mut bytes = vec![];
            rpc
              .get_block(&hex::decode(hash).unwrap().try_into().unwrap())
              .await
              .unwrap()
              .consensus_encode(&mut bytes)
              .unwrap();
            res.push(serde_json::json!([hex::encode(bytes)]));
          }
          res
        };

        // Mine a Monero block
        let monero_blocks = {
          use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
          use monero_serai::wallet::{
            ViewPair,
            address::{Network, AddressSpec},
          };

          let addr = ViewPair::new(ED25519_BASEPOINT_POINT, Zeroizing::new(Scalar::ONE))
            .address(Network::Mainnet, AddressSpec::Standard)
            .to_string();

          let rpc = producer_handles.monero(ops).await;
          let mut res = Vec::with_capacity(count);
          for _ in 0 .. count {
            let block =
              rpc.get_block(rpc.generate_blocks(&addr, 1).await.unwrap()[0]).await.unwrap();

            let mut txs = Vec::with_capacity(block.txs.len());
            for tx in &block.txs {
              txs.push(rpc.get_transaction(*tx).await.unwrap());
            }
            res.push((serde_json::json!([hex::encode(block.serialize())]), txs));
          }
          res
        };

        // Relay it to all other nodes
        // If the producer is 0, the producer variable will be 1 since we already incremented
        // it
        // With 4 nodes, this will run 1 .. 4, which is the correct range
        for receiver in *producer .. (*producer + (handles.len() - 1)) {
          let receiver = receiver % handles.len();
          let handles = &handles[receiver];

          {
            let rpc = handles.bitcoin(ops).await;
            for block in &bitcoin_blocks {
              let _: () = rpc.rpc_call("submitblock", block.clone()).await.unwrap();
            }
          }

          {
            let rpc = handles.monero(ops).await;

            for (block, txs) in &monero_blocks {
              // Broadcast the Monero TXs, as they're not simply included with the block
              for tx in txs {
                // Ignore any errors since the TX already being present will return an error
                let _ = rpc.publish_transaction(tx).await;
              }

              #[derive(Debug, serde::Deserialize)]
              struct EmptyResponse {}
              let _: EmptyResponse =
                rpc.json_rpc_call("submit_block", Some(block.clone())).await.unwrap();
            }
          }
        }
      }

      // Mine blocks to create mature funds
      mine_blocks(&handles, &ops, &mut 0, 101).await;

      // Spawn a background task to mine blocks on Bitcoin/Monero
      let keep_mining = Arc::new(Mutex::new(true));
      {
        let keep_mining = keep_mining.clone();
        let existing = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic| {
          // On panic, set keep_mining to false
          if let Ok(mut keep_mining) = keep_mining.lock() {
            *keep_mining = false;
          } else {
            println!("panic which poisoned keep_mining");
          }
          existing(panic);
        }));
      }

      let mining_task = {
        let ops = ops.clone();
        let handles = handles.clone();
        let keep_mining = keep_mining.clone();
        tokio::spawn(async move {
          let start = Instant::now();
          let mut producer = 0;
          while {
            // Ensure this is deref'd to a bool, not any permutation of the lock
            let keep_mining: bool = *keep_mining.lock().unwrap();
            // Bound execution to 60m
            keep_mining && (Instant::now().duration_since(start) < Duration::from_secs(60 * 60))
          } {
            // Mine a block every 5s
            tokio::time::sleep(Duration::from_secs(5)).await;
            mine_blocks(&handles, &ops, &mut producer, 1).await;
          }
        })
      };

      // Get the generated keys
      let (bitcoin_key_pair, monero_key_pair) = {
        let key_pair = {
          let serai = &serai;
          move |additional, network| async move {
            // If this is an additional key pair, it should've completed with the first barring
            // misc latency, so only sleep up to 5 minutes
            // If this is the first key pair, wait up to 10 minutes
            let halt_at = if additional { 5 * 10 } else { 10 * 10 };
            let print_at = halt_at / 2;
            for i in 0 .. halt_at {
              if let Some(key_pair) = serai
                .with_current_latest_block()
                .await
                .unwrap()
                .validator_sets()
                .keys(ValidatorSet { network, session: Session(0) })
                .await
                .unwrap()
              {
                return key_pair;
              }

              if i == print_at {
                println!(
                  "waiting for {}key gen to complete, it has been {} minutes",
                  if additional { "another " } else { "" },
                  print_at / 10,
                );
              }
              tokio::time::sleep(Duration::from_secs(6)).await;
            }

            panic!(
              "{}key gen did not complete within {} minutes",
              if additional { "another " } else { "" },
              halt_at / 10,
            );
          }
        };

        (key_pair(false, NetworkId::Bitcoin).await, key_pair(true, NetworkId::Monero).await)
      };

      // Create a Serai address to receive the sriBTC/sriXMR to
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
                &SeraiCoins::transfer_sri(address, Amount(1_000_000_000)),
                0,
                Default::default(),
              )
              .unwrap(),
          )
          .await
          .unwrap();

        (PairSigner::new(pair), address)
      };

      // Send in BTC
      {
        use bitcoin_serai::bitcoin::{
          secp256k1::{SECP256K1, SecretKey, Message},
          PrivateKey, PublicKey,
          key::{XOnlyPublicKey, TweakedPublicKey},
          sighash::{EcdsaSighashType, SighashCache},
          script::{PushBytesBuf, Script, ScriptBuf, Builder},
          absolute::LockTime,
          address::Payload,
          Sequence, Witness, OutPoint, TxIn, TxOut, Transaction, Network,
        };

        let private_key =
          PrivateKey::new(SecretKey::from_slice(&[0x01; 32]).unwrap(), Network::Bitcoin);
        let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        let addr = Payload::p2pkh(&public_key);

        // Use the first block's coinbase
        let rpc = handles[0].bitcoin(&ops).await;
        let tx =
          rpc.get_block(&rpc.get_block_hash(1).await.unwrap()).await.unwrap().txdata.swap_remove(0);
        #[allow(clippy::inconsistent_digit_grouping)]
        let mut tx = Transaction {
          version: 2,
          lock_time: LockTime::ZERO,
          input: vec![TxIn {
            previous_output: OutPoint { txid: tx.txid(), vout: 0 },
            script_sig: Script::empty().into(),
            sequence: Sequence(u32::MAX),
            witness: Witness::default(),
          }],
          output: vec![
            TxOut {
              value: 1_100_000_00,
              script_pubkey: Payload::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                XOnlyPublicKey::from_slice(&bitcoin_key_pair.1[1 ..]).unwrap(),
              ))
              .script_pubkey(),
            },
            TxOut {
              // change = amount spent - fee
              value: tx.output[0].value - 1_100_000_00 - 1_000_00,
              script_pubkey: Payload::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                XOnlyPublicKey::from_slice(&public_key.inner.serialize()[1 ..]).unwrap(),
              ))
              .script_pubkey(),
            },
            TxOut {
              value: 0,
              script_pubkey: ScriptBuf::new_op_return(
                &PushBytesBuf::try_from(Shorthand::transfer(None, serai_addr).encode()).unwrap(),
              ),
            },
          ],
        };

        let mut der = SECP256K1
          .sign_ecdsa_low_r(
            &Message::from(
              SighashCache::new(&tx)
                .legacy_signature_hash(0, &addr.script_pubkey(), EcdsaSighashType::All.to_u32())
                .unwrap()
                .to_raw_hash(),
            ),
            &private_key.inner,
          )
          .serialize_der()
          .to_vec();
        der.push(1);
        tx.input[0].script_sig = Builder::new()
          .push_slice(PushBytesBuf::try_from(der).unwrap())
          .push_key(&public_key)
          .into_script();

        rpc.send_raw_transaction(&tx).await.unwrap();
      }

      // Send in XMR
      {
        use curve25519_dalek::{
          constants::ED25519_BASEPOINT_POINT, scalar::Scalar, edwards::CompressedEdwardsY,
        };
        use monero_serai::{
          Protocol,
          transaction::Timelock,
          wallet::{
            ViewPair, Scanner, Decoys, Change, FeePriority, SignableTransaction,
            address::{Network, AddressType, AddressMeta, MoneroAddress},
          },
        };

        // Grab the first output on the chain
        let rpc = handles[0].monero(&ops).await;
        let view_pair = ViewPair::new(ED25519_BASEPOINT_POINT, Zeroizing::new(Scalar::ONE));
        let mut scanner = Scanner::from_view(view_pair.clone(), Some(HashSet::new()));
        let output = scanner
          .scan(&rpc, &rpc.get_block_by_number(1).await.unwrap())
          .await
          .unwrap()
          .swap_remove(0)
          .unlocked(Timelock::Block(rpc.get_height().await.unwrap()))
          .unwrap()
          .swap_remove(0);

        let decoys = Decoys::select(
          &mut OsRng,
          &rpc,
          Protocol::v16.ring_len(),
          rpc.get_height().await.unwrap() - 1,
          &[output.clone()],
        )
        .await
        .unwrap()
        .swap_remove(0);

        let tx = SignableTransaction::new(
          Protocol::v16,
          None,
          vec![(output, decoys)],
          vec![(
            MoneroAddress::new(
              AddressMeta::new(
                Network::Mainnet,
                AddressType::Featured { guaranteed: true, subaddress: false, payment_id: None },
              ),
              CompressedEdwardsY(monero_key_pair.1.to_vec().try_into().unwrap())
                .decompress()
                .unwrap(),
              ED25519_BASEPOINT_POINT *
                processor::additional_key::<processor::networks::monero::Monero>(0).0,
            ),
            1_100_000_000_000,
          )],
          Some(Change::new(&view_pair, false)),
          vec![Shorthand::transfer(None, serai_addr).encode()],
          rpc.get_fee(Protocol::v16, FeePriority::Low).await.unwrap(),
        )
        .unwrap()
        .sign(&mut OsRng, &Zeroizing::new(Scalar::ONE))
        .unwrap();

        rpc.publish_transaction(&tx).await.unwrap()
      }

      // Wait for Batch publication
      // TODO: Merge this block with the above one
      // (take in a lambda for the specific checks to execute?)
      {
        let wait_for_batch = {
          let serai = &serai;
          move |additional, network| async move {
            let halt_at = if additional { 5 * 10 } else { 10 * 10 };
            let print_at = halt_at / 2;
            for i in 0 .. halt_at {
              if serai
                .with_current_latest_block()
                .await
                .unwrap()
                .in_instructions()
                .last_batch_for_network(network)
                .await
                .unwrap()
                .is_some()
              {
                return;
              }

              if i == print_at {
                println!(
                  "waiting for {}batch to complete, it has been {} minutes",
                  if additional { "another " } else { "" },
                  print_at / 10,
                );
              }
              tokio::time::sleep(Duration::from_secs(6)).await;
            }

            panic!(
              "{}batch did not complete within {} minutes",
              if additional { "another " } else { "" },
              halt_at / 10,
            );
          }
        };
        wait_for_batch(false, NetworkId::Bitcoin).await;
        wait_for_batch(true, NetworkId::Monero).await;
      }

      // TODO: Verify the mints

      // Create a random Bitcoin/Monero address
      let bitcoin_addr = {
        use bitcoin_serai::bitcoin::{network::constants::Network, key::PublicKey, address::Address};
        // Uses Network::Bitcoin since it doesn't actually matter, Serai strips it out
        // TODO: Move Serai to Payload from Address
        Address::p2pkh(
          &loop {
            let mut bytes = [0; 33];
            OsRng.fill_bytes(&mut bytes);
            bytes[0] %= 4;
            if let Ok(key) = PublicKey::from_slice(&bytes) {
              break key;
            }
          },
          Network::Bitcoin,
        )
      };

      let (monero_spend, monero_view, monero_addr) = {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
        let spend = ED25519_BASEPOINT_TABLE * &Scalar::random(&mut OsRng);
        let view = Scalar::random(&mut OsRng);

        use monero_serai::wallet::address::{Network, AddressType, AddressMeta, MoneroAddress};
        let addr = MoneroAddress::new(
          AddressMeta::new(Network::Mainnet, AddressType::Standard),
          spend,
          ED25519_BASEPOINT_TABLE * &view,
        );

        (spend, view, addr)
      };

      // Get the current blocks
      let mut start_bitcoin_block =
        handles[0].bitcoin(&ops).await.get_latest_block_number().await.unwrap();
      let mut start_monero_block = handles[0].monero(&ops).await.get_height().await.unwrap();

      // Burn the sriBTC/sriXMR
      {
        let burn = {
          let serai = &serai;
          let serai_pair = &serai_pair;
          move |nonce, coin, amount, address| async move {
            let out_instruction = OutInstruction { address, data: None };

            serai
              .publish(
                &serai
                  .sign(
                    serai_pair,
                    &SeraiCoins::burn(Balance { coin, amount: Amount(amount) }, out_instruction),
                    nonce,
                    Default::default(),
                  )
                  .unwrap(),
              )
              .await
              .unwrap();
          }
        };

        #[allow(clippy::inconsistent_digit_grouping)]
        burn(
          0,
          Coin::Bitcoin,
          1_000_000_00,
          ExternalAddress::new(
            serai_client::networks::bitcoin::Address(bitcoin_addr.clone()).try_into().unwrap(),
          )
          .unwrap(),
        )
        .await;

        burn(
          1,
          Coin::Monero,
          1_000_000_000_000,
          ExternalAddress::new(
            serai_client::networks::monero::Address::new(monero_addr).unwrap().try_into().unwrap(),
          )
          .unwrap(),
        )
        .await;
      }

      // TODO: Verify the burns

      // Verify the received Bitcoin TX
      #[allow(clippy::inconsistent_digit_grouping)]
      {
        let rpc = handles[0].bitcoin(&ops).await;

        // Check for up to 5 minutes
        let mut found = false;
        let mut i = 0;
        while i < (5 * 6) {
          if let Ok(hash) = rpc.get_block_hash(start_bitcoin_block).await {
            let block = rpc.get_block(&hash).await.unwrap();
            start_bitcoin_block += 1;

            if block.txdata.len() > 1 {
              assert_eq!(block.txdata.len(), 2);
              assert_eq!(block.txdata[1].output.len(), 2);

              let received_output = block.txdata[1]
                .output
                .iter()
                .find(|output| output.script_pubkey == bitcoin_addr.script_pubkey())
                .unwrap();

              let tx_fee = 1_100_000_00 -
                block.txdata[1].output.iter().map(|output| output.value).sum::<u64>();

              assert_eq!(received_output.value, 1_000_000_00 - tx_fee);
              found = true;
            }
          } else {
            i += 1;
            tokio::time::sleep(Duration::from_secs(10)).await;
          }
        }
        if !found {
          panic!("couldn't find the expected Bitcoin transaction within 5 minutes");
        }
      }

      // Verify the received Monero TX
      {
        use monero_serai::wallet::{ViewPair, Scanner};
        let rpc = handles[0].monero(&ops).await;
        let mut scanner = Scanner::from_view(
          ViewPair::new(monero_spend, Zeroizing::new(monero_view)),
          Some(HashSet::new()),
        );

        // Check for up to 5 minutes
        let mut found = false;
        let mut i = 0;
        while i < (5 * 6) {
          if let Ok(block) = rpc.get_block_by_number(start_monero_block).await {
            start_monero_block += 1;
            let outputs = scanner.scan(&rpc, &block).await.unwrap();
            if !outputs.is_empty() {
              assert_eq!(outputs.len(), 1);
              let outputs = outputs[0].not_locked();
              assert_eq!(outputs.len(), 1);

              assert_eq!(block.txs.len(), 1);
              let tx = rpc.get_transaction(block.txs[0]).await.unwrap();
              let tx_fee = tx.rct_signatures.base.fee;

              assert_eq!(outputs[0].commitment().amount, 1_000_000_000_000 - tx_fee);
              found = true;
            }
          } else {
            i += 1;
            tokio::time::sleep(Duration::from_secs(10)).await;
          }
        }
        if !found {
          panic!("couldn't find the expected Monero transaction within 5 minutes");
        }
      }

      *keep_mining.lock().unwrap() = false;
      mining_task.await.unwrap();
    })
    .await;
}
