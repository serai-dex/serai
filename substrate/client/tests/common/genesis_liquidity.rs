use std::collections::HashMap;

use rand_core::{RngCore, OsRng};
use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

use sp_core::{sr25519::Signature, Pair as PairTrait};

use serai_abi::{
  genesis_liquidity::primitives::{oraclize_values_message, Values},
  in_instructions::primitives::{Batch, InInstruction, InInstructionWithBalance},
  primitives::{
    insecure_pair_from_name, Amount, ExternalBalance, BlockHash, ExternalCoin, ExternalNetworkId,
    NetworkId, SeraiAddress, EXTERNAL_COINS,
  },
  validator_sets::primitives::{musig_context, Session, ValidatorSet},
};

use serai_client::{Serai, SeraiGenesisLiquidity};

use crate::common::{in_instructions::provide_batch, tx::publish_tx};

#[allow(dead_code)]
pub async fn set_up_genesis(
  serai: &Serai,
  values: &HashMap<ExternalCoin, u64>,
) -> (HashMap<ExternalCoin, Vec<(SeraiAddress, Amount)>>, HashMap<ExternalNetworkId, u32>) {
  // make accounts with amounts
  let mut accounts = HashMap::new();
  for coin in EXTERNAL_COINS {
    // make 5 accounts per coin
    let mut values = vec![];
    for _ in 0 .. 5 {
      let mut address = SeraiAddress::new([0; 32]);
      OsRng.fill_bytes(&mut address.0);
      values.push((address, Amount(OsRng.next_u64() % 10u64.pow(coin.decimals()))));
    }
    accounts.insert(coin, values);
  }

  // send a batch per coin
  let mut batch_ids: HashMap<ExternalNetworkId, u32> = HashMap::new();
  for coin in EXTERNAL_COINS {
    // set up instructions
    let instructions = accounts[&coin]
      .iter()
      .map(|(addr, amount)| InInstructionWithBalance {
        instruction: InInstruction::GenesisLiquidity(*addr),
        balance: ExternalBalance { coin, amount: *amount },
      })
      .collect::<Vec<_>>();

    // set up bloch hash
    let mut block = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut block.0);

    // set up batch id
    batch_ids
      .entry(coin.network())
      .and_modify(|v| {
        *v += 1;
      })
      .or_insert(0);

    let batch =
      Batch { network: coin.network(), id: batch_ids[&coin.network()], block, instructions };
    provide_batch(serai, batch).await;
  }

  // set values relative to each other. We can do that without checking for genesis period blocks
  // since we are running in test(fast-epoch) mode.
  // TODO: Random values here
  let values = Values {
    monero: values[&ExternalCoin::Monero],
    ether: values[&ExternalCoin::Ether],
    dai: values[&ExternalCoin::Dai],
  };
  set_values(serai, &values).await;

  (accounts, batch_ids)
}

#[allow(dead_code)]
async fn set_values(serai: &Serai, values: &Values) {
  // prepare a Musig tx to oraclize the relative values
  let pair = insecure_pair_from_name("Alice");
  let public = pair.public();
  // we publish the tx in set 1
  let set = ValidatorSet { session: Session(1), network: NetworkId::Serai };

  let public_key = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut public.0.as_ref()).unwrap();
  let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
    &mut pair.as_ref().secret.to_bytes()[.. 32].as_ref(),
  )
  .unwrap();

  assert_eq!(Ristretto::generator() * secret_key, public_key);
  let threshold_keys =
    musig::<Ristretto>(&musig_context(set), &Zeroizing::new(secret_key), &[public_key]).unwrap();

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(
      &mut OsRng,
      &Schnorrkel::new(b"substrate"),
      &HashMap::from([(threshold_keys.params().i(), threshold_keys.into())]),
    ),
    &oraclize_values_message(&set, values),
  );

  // oraclize values
  let _ =
    publish_tx(serai, &SeraiGenesisLiquidity::oraclize_values(*values, Signature(sig.to_bytes())))
      .await;
}
