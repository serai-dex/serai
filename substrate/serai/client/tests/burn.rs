use core::time::Duration;

use rand_core::{RngCore, OsRng};

use sp_core::Pair;
use serai_runtime::in_instructions::{Batch, Update};

use tokio::time::sleep;

use subxt::tx::{PolkadotExtrinsicParamsBuilder, PairSigner};

use serai_client::{
  primitives::{
    BITCOIN, BlockNumber, BlockHash, SeraiAddress, Amount, WithAmount, Balance, Data,
    ExternalAddress, insecure_pair_from_name,
  },
  in_instructions::primitives::InInstruction,
  tokens::{primitives::OutInstruction, TokensEvent},
  Serai,
};

mod runner;
use runner::{URL, provide_updates};

serai_test!(
  async fn burn() {
    let coin = BITCOIN;
    let mut id = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut id.0);
    let block_number = BlockNumber(u32::try_from(OsRng.next_u64() >> 32).unwrap());

    let pair = insecure_pair_from_name("Alice");
    let public = pair.public();
    let address = SeraiAddress::from(public);

    let amount = Amount(OsRng.next_u64());
    let balance = Balance { coin, amount };

    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let external_address = ExternalAddress::new(rand_bytes).unwrap();

    let mut rand_bytes = vec![0; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let data = Data::new(rand_bytes).unwrap();

    let batch = Batch {
      id,
      instructions: vec![WithAmount { data: InInstruction::Transfer(address), amount }],
    };
    let update = Update { block_number, batches: vec![batch] };
    let block = provide_updates(vec![Some(update)]).await;

    let serai = Serai::new(URL).await.unwrap();
    assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), amount);

    let out = OutInstruction { address: external_address, data: Some(data) };
    let burn = Serai::burn(balance, out.clone());

    let signer = PairSigner::new(pair);
    serai
      .publish(&serai.sign(&signer, &burn, 0, PolkadotExtrinsicParamsBuilder::new()).unwrap())
      .await
      .unwrap();

    loop {
      let block = serai.get_latest_block_hash().await.unwrap();
      let events = serai.get_burn_events(block).await.unwrap();
      if events.is_empty() {
        sleep(Duration::from_millis(50)).await;
        continue;
      }
      assert_eq!(events, vec![TokensEvent::Burn { address, balance, instruction: out }]);
      assert_eq!(serai.get_token_supply(block, coin).await.unwrap(), Amount(0));
      assert_eq!(serai.get_token_balance(block, coin, address).await.unwrap(), Amount(0));
      break;
    }
  }
);
