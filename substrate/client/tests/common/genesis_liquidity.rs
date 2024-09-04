use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use sp_core::sr25519::Pair;

use serai_abi::{
  genesis_liquidity::primitives::{oraclize_values_message, Values},
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::primitives::{InInstruction, InInstructionWithBalance, Batch},
  primitives::{Amount, NetworkId, Coin, Balance, BlockHash, SeraiAddress},
};

use serai_client::{Serai, SeraiGenesisLiquidity};

use crate::common::{
  in_instructions::provide_batch,
  tx::{get_musig_of_pairs, publish_tx},
  validator_sets::get_ordered_keys,
};

#[allow(dead_code)]
pub async fn set_up_genesis(
  serai: &Serai,
  coins: &[Coin],
  pairs: &[Pair],
  values: &HashMap<Coin, u64>,
) -> (HashMap<Coin, Vec<(SeraiAddress, Amount)>>, HashMap<NetworkId, u32>) {
  // make accounts with amounts
  let mut accounts = HashMap::new();
  for coin in coins {
    // make 5 accounts per coin
    let mut values = vec![];
    for _ in 0 .. 5 {
      let mut address = SeraiAddress::new([0; 32]);
      OsRng.fill_bytes(&mut address.0);
      values.push((address, Amount(OsRng.next_u64() % 10u64.pow(coin.decimals()))));
    }
    accounts.insert(*coin, values);
  }

  // send a batch per coin
  let mut batch_ids: HashMap<NetworkId, u32> = HashMap::new();
  for coin in coins {
    // set up instructions
    let instructions = accounts[coin]
      .iter()
      .map(|(addr, amount)| InInstructionWithBalance {
        instruction: InInstruction::GenesisLiquidity(*addr),
        balance: Balance { coin: *coin, amount: *amount },
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
    provide_batch(serai, &get_ordered_keys(serai, coin.network(), pairs).await, batch).await;
  }

  // set values relative to each other. We can do that without checking for genesis period blocks
  // since we are running in test(fast-epoch) mode.
  // TODO: Random values here
  let values =
    Values { monero: values[&Coin::Monero], ether: values[&Coin::Ether], dai: values[&Coin::Dai] };
  set_values(serai, &get_ordered_keys(serai, NetworkId::Serai, pairs).await, &values).await;

  (accounts, batch_ids)
}

#[allow(dead_code)]
pub async fn set_values(serai: &Serai, pairs: &[Pair], values: &Values) {
  // we publish the tx in set 1
  let set = ValidatorSet { session: Session(1), network: NetworkId::Serai };

  // prepare a Musig tx to oraclize the relative values
  let sig = get_musig_of_pairs(pairs, set, &oraclize_values_message(&set, values));

  // oraclize values
  let _ = publish_tx(serai, &SeraiGenesisLiquidity::oraclize_values(*values, sig)).await;
}
