use std::{
  sync::{OnceLock, Arc, Mutex},
  time::{Duration, Instant},
};

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use scale::Encode;

use serai_client::{
  coins::primitives::{OutInstruction, OutInstructionWithBalance},
  in_instructions::primitives::Shorthand,
  primitives::{
    insecure_pair_from_name, Amount, Balance, Coin, ExternalAddress, ExternalBalance, ExternalCoin,
    SeraiAddress,
  },
  validator_sets::primitives::{ExternalValidatorSet, Session},
  PairTrait, SeraiCoins,
};

use crate::tests::*;

// TODO: Break this test out into functions re-usable across processor, processor e2e, and full
// stack tests
#[tokio::test]
async fn mint_and_burn_test() {
  new_test(|ops, handles: Vec<Handles>| async move {
    let ops = Arc::new(ops);
    let serai = handles[0].serai(&ops).await;

    // Helper to mine a block on each network
    async fn mine_blocks(
      handles: &[Handles],
      ops: &DockerOperations,
      producer: &mut usize,
      count: usize,
    ) {
      static MINE_BLOCKS_CALL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

      // Only let one instance of this function run at a time
      let _lock = MINE_BLOCKS_CALL.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;

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
          network::Network,
          address::Address,
        };

        let addr = Address::p2pkh(
          PublicKey::from_private_key(
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
        use monero_wallet::{rpc::Rpc, ViewPair, address::Network};

        let addr = ViewPair::new(ED25519_BASEPOINT_POINT, Zeroizing::new(Scalar::ONE))
          .unwrap()
          .legacy_address(Network::Mainnet);

        let rpc = producer_handles.monero(ops).await;
        let mut res = Vec::with_capacity(count);
        for _ in 0 .. count {
          let block =
            rpc.get_block(rpc.generate_blocks(&addr, 1).await.unwrap().0[0]).await.unwrap();

          let mut txs = Vec::with_capacity(block.transactions.len());
          for tx in &block.transactions {
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
          use monero_wallet::rpc::Rpc;

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
          // Mine a block every 3s
          tokio::time::sleep(Duration::from_secs(3)).await;
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
              .as_of_latest_finalized_block()
              .await
              .unwrap()
              .validator_sets()
              .keys(ExternalValidatorSet { network, session: Session(0) })
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

      (
        key_pair(false, ExternalNetworkId::Bitcoin).await,
        key_pair(true, ExternalNetworkId::Monero).await,
      )
    };

    // Because the initial keys only become active when the network's time matches the Serai
    // time, the Serai time is real yet the network time may be significantly delayed due to
    // potentially being a median, mine a bunch of blocks now
    mine_blocks(&handles, &ops, &mut 0, 100).await;

    // Create a Serai address to receive the sriBTC/sriXMR to
    let (serai_pair, serai_addr) = {
      let mut name = [0; 4];
      OsRng.fill_bytes(&mut name);
      let pair = insecure_pair_from_name(&hex::encode(name));
      let address = SeraiAddress::from(pair.public());

      // Fund the new account to pay for fees
      let balance = Balance { coin: Coin::Serai, amount: Amount(1_000_000_000) };
      serai
        .publish(&serai.sign(
          &insecure_pair_from_name("Ferdie"),
          SeraiCoins::transfer(address, balance),
          0,
          Default::default(),
        ))
        .await
        .unwrap();

      (pair, address)
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
        transaction::{Version, Transaction},
        Sequence, Witness, OutPoint, TxIn, Amount, TxOut, Network, Address,
      };

      let private_key =
        PrivateKey::new(SecretKey::from_slice(&[0x01; 32]).unwrap(), Network::Bitcoin);
      let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
      let addr = Address::p2pkh(public_key, Network::Bitcoin);

      // Use the first block's coinbase
      let rpc = handles[0].bitcoin(&ops).await;
      let tx =
        rpc.get_block(&rpc.get_block_hash(1).await.unwrap()).await.unwrap().txdata.swap_remove(0);
      #[allow(clippy::inconsistent_digit_grouping)]
      let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint { txid: tx.compute_txid(), vout: 0 },
          script_sig: Script::new().into(),
          sequence: Sequence(u32::MAX),
          witness: Witness::default(),
        }],
        output: vec![
          TxOut {
            value: Amount::from_sat(1_100_000_00),
            script_pubkey: Address::p2tr_tweaked(
              TweakedPublicKey::dangerous_assume_tweaked(
                XOnlyPublicKey::from_slice(&bitcoin_key_pair.1[1 ..]).unwrap(),
              ),
              Network::Bitcoin,
            )
            .script_pubkey(),
          },
          TxOut {
            // change = amount spent - fee
            value: Amount::from_sat(tx.output[0].value.to_sat() - 1_100_000_00 - 1_000_00),
            script_pubkey: Address::p2tr_tweaked(
              TweakedPublicKey::dangerous_assume_tweaked(
                XOnlyPublicKey::from_slice(&public_key.inner.serialize()[1 ..]).unwrap(),
              ),
              Network::Bitcoin,
            )
            .script_pubkey(),
          },
          TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(
              PushBytesBuf::try_from(Shorthand::transfer(None, serai_addr).encode()).unwrap(),
            ),
          },
        ],
      };

      let mut der = SECP256K1
        .sign_ecdsa_low_r(
          &Message::from_digest_slice(
            SighashCache::new(&tx)
              .legacy_signature_hash(0, &addr.script_pubkey(), EcdsaSighashType::All.to_u32())
              .unwrap()
              .to_raw_hash()
              .as_ref(),
          )
          .unwrap(),
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
      use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
      use monero_wallet::{
        io::decompress_point,
        ringct::RctType,
        rpc::{FeePriority, Rpc},
        address::{Network, AddressType, MoneroAddress},
        ViewPair, Scanner, OutputWithDecoys,
        send::{Change, SignableTransaction},
      };

      // Grab the first output on the chain
      let rpc = handles[0].monero(&ops).await;
      let view_pair = ViewPair::new(ED25519_BASEPOINT_POINT, Zeroizing::new(Scalar::ONE)).unwrap();
      let mut scanner = Scanner::new(view_pair.clone());
      let output = scanner
        .scan(rpc.get_scannable_block_by_number(1).await.unwrap())
        .unwrap()
        .additional_timelock_satisfied_by(rpc.get_height().await.unwrap(), 0)
        .swap_remove(0);

      let input = OutputWithDecoys::fingerprintable_deterministic_new(
        &mut OsRng,
        &rpc,
        16,
        rpc.get_height().await.unwrap(),
        output.clone(),
      )
      .await
      .unwrap();

      let mut outgoing_view_key = Zeroizing::new([0; 32]);
      OsRng.fill_bytes(outgoing_view_key.as_mut());
      let tx = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing_view_key,
        vec![input],
        vec![(
          MoneroAddress::new(
            Network::Mainnet,
            AddressType::Featured { guaranteed: true, subaddress: false, payment_id: None },
            decompress_point(monero_key_pair.1.to_vec().try_into().unwrap()).unwrap(),
            ED25519_BASEPOINT_POINT *
              processor::additional_key::<processor::networks::monero::Monero>(0).0,
          ),
          1_100_000_000_000,
        )],
        Change::new(view_pair.clone(), None),
        vec![Shorthand::transfer(None, serai_addr).encode()],
        rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
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
              .as_of_latest_finalized_block()
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
      wait_for_batch(false, ExternalNetworkId::Bitcoin).await;
      wait_for_batch(true, ExternalNetworkId::Monero).await;
    }

    // TODO: Verify the mints

    // Create a random Bitcoin/Monero address
    let bitcoin_addr = {
      use bitcoin_serai::bitcoin::{key::PublicKey, ScriptBuf};
      ScriptBuf::new_p2pkh(
        &(loop {
          let mut bytes = [0; 33];
          OsRng.fill_bytes(&mut bytes);
          bytes[0] %= 4;
          if let Ok(key) = PublicKey::from_slice(&bytes) {
            break key;
          }
        })
        .pubkey_hash(),
      )
    };

    let (monero_spend, monero_view, monero_addr) = {
      use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
      let spend = ED25519_BASEPOINT_TABLE * &Scalar::random(&mut OsRng);
      let view = Scalar::random(&mut OsRng);

      use monero_wallet::address::{Network, AddressType, MoneroAddress};
      let addr = MoneroAddress::new(
        Network::Mainnet,
        AddressType::Legacy,
        spend,
        ED25519_BASEPOINT_TABLE * &view,
      );

      (spend, view, addr)
    };

    // Get the current blocks
    let mut start_bitcoin_block =
      handles[0].bitcoin(&ops).await.get_latest_block_number().await.unwrap();
    let mut start_monero_block = {
      use monero_wallet::rpc::Rpc;
      handles[0].monero(&ops).await.get_height().await.unwrap()
    };

    // Burn the sriBTC/sriXMR
    {
      let burn = {
        let serai = &serai;
        let serai_pair = &serai_pair;
        move |nonce, coin, amount, address| async move {
          let out_instruction = OutInstructionWithBalance {
            balance: ExternalBalance { coin, amount: Amount(amount) },
            instruction: OutInstruction { address, data: None },
          };

          serai
            .publish(&serai.sign(
              serai_pair,
              SeraiCoins::burn_with_instruction(out_instruction),
              nonce,
              Default::default(),
            ))
            .await
            .unwrap();
        }
      };

      #[allow(clippy::inconsistent_digit_grouping)]
      burn(
        0,
        ExternalCoin::Bitcoin,
        1_000_000_00,
        ExternalAddress::new(
          serai_client::networks::bitcoin::Address::new(bitcoin_addr.clone()).unwrap().into(),
        )
        .unwrap(),
      )
      .await;

      burn(
        1,
        ExternalCoin::Monero,
        1_000_000_000_000,
        ExternalAddress::new(
          serai_client::networks::monero::Address::new(monero_addr).unwrap().into(),
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

      // Check for up to 15 minutes
      let mut found = false;
      let mut i = 0;
      while i < (15 * 6) {
        if let Ok(hash) = rpc.get_block_hash(start_bitcoin_block).await {
          let block = rpc.get_block(&hash).await.unwrap();
          start_bitcoin_block += 1;

          if block.txdata.len() > 1 {
            assert_eq!(block.txdata.len(), 2);
            assert_eq!(block.txdata[1].output.len(), 2);

            let received_output = block.txdata[1]
              .output
              .iter()
              .find(|output| output.script_pubkey == bitcoin_addr)
              .unwrap();

            let tx_fee = 1_100_000_00 -
              block.txdata[1].output.iter().map(|output| output.value.to_sat()).sum::<u64>();

            assert_eq!(received_output.value.to_sat(), 1_000_000_00 - tx_fee);
            found = true;
          }
        } else {
          i += 1;
          tokio::time::sleep(Duration::from_secs(10)).await;
        }
      }
      if !found {
        panic!("couldn't find the expected Bitcoin transaction within 15 minutes");
      }
    }

    // Verify the received Monero TX
    {
      use monero_wallet::{transaction::Transaction, rpc::Rpc, ViewPair, Scanner};
      let rpc = handles[0].monero(&ops).await;
      let mut scanner =
        Scanner::new(ViewPair::new(monero_spend, Zeroizing::new(monero_view)).unwrap());

      // Check for up to 5 minutes
      let mut found = false;
      let mut i = 0;
      while i < (5 * 6) {
        if let Ok(block) = rpc.get_block_by_number(start_monero_block).await {
          start_monero_block += 1;
          let outputs = scanner
            .scan(rpc.get_scannable_block(block.clone()).await.unwrap())
            .unwrap()
            .not_additionally_locked();
          if !outputs.is_empty() {
            assert_eq!(outputs.len(), 1);

            assert_eq!(block.transactions.len(), 1);
            let tx = rpc.get_transaction(block.transactions[0]).await.unwrap();
            let tx_fee = match &tx {
              Transaction::V2 { proofs: Some(proofs), .. } => proofs.base.fee,
              _ => panic!("fetched TX wasn't a signed V2 TX"),
            };

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
