use std::collections::HashMap;

use alloy_core::primitives::U256;

use serai_client::{
  primitives::{NetworkId, Coin, Balance},
  networks::ethereum::Address,
};

use serai_db::Db;

use primitives::Payment;
use scanner::{KeyFor, AddressFor, EventualityFor};

use ethereum_schnorr::PublicKey;
use ethereum_router::Coin as EthereumCoin;

use crate::{DAI, transaction::Action, rpc::Rpc};

fn coin_to_ethereum_coin(coin: Coin) -> EthereumCoin {
  assert_eq!(coin.network(), NetworkId::Ethereum);
  match coin {
    Coin::Ether => EthereumCoin::Ether,
    Coin::Dai => EthereumCoin::Erc20(DAI),
    _ => unreachable!(),
  }
}

fn balance_to_ethereum_amount(balance: Balance) -> U256 {
  assert_eq!(balance.coin.network(), NetworkId::Ethereum);
  assert_eq!(balance.coin.decimals(), 8);
  // Restore 10 decimals so we go from 8 decimals to 18 decimals
  // TODO: Document the expectation all integrated coins have 18 decimals
  let factor = U256::from(10_000_000_000u64);
  U256::from(balance.amount.0) * factor
}

#[derive(Clone)]
pub(crate) struct SmartContract {
  pub(crate) chain_id: U256,
}
impl<D: Db> smart_contract_scheduler::SmartContract<Rpc<D>> for SmartContract {
  type SignableTransaction = Action;

  fn rotate(
    &self,
    nonce: u64,
    _retiring_key: KeyFor<Rpc<D>>,
    new_key: KeyFor<Rpc<D>>,
  ) -> (Self::SignableTransaction, EventualityFor<Rpc<D>>) {
    let action = Action::SetKey {
      chain_id: self.chain_id,
      nonce,
      key: PublicKey::new(new_key).expect("rotating to an invald key"),
    };
    (action.clone(), action.eventuality())
  }

  fn fulfill(
    &self,
    mut nonce: u64,
    _key: KeyFor<Rpc<D>>,
    payments: Vec<Payment<AddressFor<Rpc<D>>>>,
  ) -> Vec<(Self::SignableTransaction, EventualityFor<Rpc<D>>)> {
    // Sort by coin
    let mut outs = HashMap::<_, _>::new();
    for payment in payments {
      let coin = payment.balance().coin;
      outs
        .entry(coin)
        .or_insert_with(|| Vec::with_capacity(1))
        .push((payment.address().clone(), balance_to_ethereum_amount(payment.balance())));
    }

    let mut res = vec![];
    for coin in [Coin::Ether, Coin::Dai] {
      let Some(outs) = outs.remove(&coin) else { continue };
      assert!(!outs.is_empty());

      let fee_per_gas = match coin {
        // 10 gwei
        Coin::Ether => {
          U256::try_from(10u64).unwrap() * alloy_core::primitives::utils::Unit::GWEI.wei()
        }
        // 0.0003 DAI
        Coin::Dai => {
          U256::try_from(30u64).unwrap() * alloy_core::primitives::utils::Unit::TWEI.wei()
        }
        _ => unreachable!(),
      };

      // The gas required to perform any interaction with the Router.
      const BASE_GAS: u32 = 0; // TODO

      // The gas required to handle an additional payment to an address, in the worst case.
      const ADDRESS_PAYMENT_GAS: u32 = 0; // TODO

      // The gas required to handle an additional payment to an smart contract, in the worst case.
      // This does not include the explicit gas budget defined within the address specification.
      const CONTRACT_PAYMENT_GAS: u32 = 0; // TODO

      // The maximum amount of gas for a batch.
      const BATCH_GAS_LIMIT: u32 = 10_000_000;

      // Split these outs into batches, respecting BATCH_GAS_LIMIT
      let mut batches = vec![vec![]];
      let mut current_gas = BASE_GAS;
      for out in outs {
        let payment_gas = match &out.0 {
          Address::Address(_) => ADDRESS_PAYMENT_GAS,
          Address::Contract(deployment) => CONTRACT_PAYMENT_GAS + deployment.gas_limit(),
        };
        if (current_gas + payment_gas) > BATCH_GAS_LIMIT {
          assert!(!batches.last().unwrap().is_empty());
          batches.push(vec![]);
          current_gas = BASE_GAS;
        }
        batches.last_mut().unwrap().push(out);
        current_gas += payment_gas;
      }

      // Push each batch onto the result
      for mut outs in batches {
        let mut total_gas = 0;

        let base_gas_per_payment = BASE_GAS.div_ceil(u32::try_from(outs.len()).unwrap());
        // Deduce the fee from each out
        for out in &mut outs {
          let payment_gas = base_gas_per_payment +
            match &out.0 {
              Address::Address(_) => ADDRESS_PAYMENT_GAS,
              Address::Contract(deployment) => CONTRACT_PAYMENT_GAS + deployment.gas_limit(),
            };
          total_gas += payment_gas;

          let payment_gas_cost = U256::try_from(payment_gas).unwrap() * fee_per_gas;
          out.1 -= payment_gas_cost;
        }

        res.push(Action::Batch {
          chain_id: self.chain_id,
          nonce,
          coin: coin_to_ethereum_coin(coin),
          fee: U256::try_from(total_gas).unwrap() * fee_per_gas,
          outs,
        });
        nonce += 1;
      }
    }
    // Ensure we handled all payments we're supposed to
    assert!(outs.is_empty());

    res.into_iter().map(|action| (action.clone(), action.eventuality())).collect()
  }
}

pub(crate) type Scheduler<D> = smart_contract_scheduler::Scheduler<Rpc<D>, SmartContract>;
