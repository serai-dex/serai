use rand_core::{RngCore, OsRng};

use sp_core::{sr25519::Signature, Pair};
use subxt::{config::extrinsic_params::BaseExtrinsicParamsBuilder};

use serai_client::{
  primitives::{
    BITCOIN_NET_ID, BITCOIN, BlockHash, SeraiAddress, Amount, Balance, Data, ExternalAddress,
    insecure_pair_from_name,
  },
  in_instructions::{
    InInstructionsEvent,
    primitives::{InInstruction, InInstructionWithBalance, Batch, SignedBatch},
  },
  tokens::{primitives::OutInstruction, TokensEvent},
  PairSigner, Serai,
};

mod runner;
use runner::{URL, publish_tx, provide_batch};

serai_test!(
  async fn burn() {
    let network = BITCOIN_NET_ID;
    let id = 0;

    let mut block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block_hash.0);

    let pair = insecure_pair_from_name("Alice");
    let public = pair.public();
    let address = SeraiAddress::from(public);

    let coin = BITCOIN;
    let amount = Amount(OsRng.next_u64().saturating_add(1));
    let balance = Balance { coin, amount };

    let batch = Batch {
      network,
      id,
      block: block_hash,
      instructions: vec![InInstructionWithBalance {
        instruction: InInstruction::Transfer(address),
        balance,
      }],
    };
    let signed = SignedBatch { batch, signature: Signature::from_raw([0; 64]) };
    let block = provide_batch(signed).await;

    let serai = Serai::new(URL).await.unwrap();
    let batches = serai.get_batch_events(block).await.unwrap();
    assert_eq!(batches, vec![InInstructionsEvent::Batch { network, id, block: block_hash }]);

    assert_eq!(
      serai.get_mint_events(block).await.unwrap(),
      vec![TokensEvent::Mint { address, balance }]
    );
    assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), amount);
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), amount);

    // Now burn it
    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let external_address = ExternalAddress::new(rand_bytes).unwrap();

    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let data = Data::new(rand_bytes).unwrap();

    let out = OutInstruction { address: external_address, data: Some(data) };
    let burn = Serai::burn(balance, out.clone());

    let signer = PairSigner::new(pair);
    let block = publish_tx(
      &serai,
      &serai.sign(&signer, &burn, 0, BaseExtrinsicParamsBuilder::new()).unwrap(),
    )
    .await;

    let events = serai.get_burn_events(block).await.unwrap();
    assert_eq!(events, vec![TokensEvent::Burn { address, balance, instruction: out }]);
    assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), Amount(0));
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), Amount(0));
  }
);
