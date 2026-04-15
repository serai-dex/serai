use std::{
  sync::{Arc, OnceLock},
  collections::HashMap,
};

use alloy_core::primitives::U256;

use serai_primitives::{network_id::ExternalNetworkId, coin::ExternalCoin, balance::ExternalBalance};
use serai_client_ethereum::ADDRESS_GAS_LIMIT;
use ethereum_router::{OutInstructions, Router};

use serai_db::Db;

use primitives::Payment;
use scanner::{KeyFor, AddressFor, EventualityFor};

use ethereum_schnorr::PublicKey;
use ethereum_router::Coin as EthereumCoin;

use crate::{DAI, transaction::Action, rpc::Rpc};

// The maximum amount of gas for a batch.
#[expect(clippy::as_conversions)]
const BATCH_GAS_LIMIT: u64 = {
  use revm_primitives::eip7825::TX_GAS_LIMIT_CAP;
  const BATCH_GAS_SAFETY_FACTOR: u32 = 2;

  let batch_gas_limit = TX_GAS_LIMIT_CAP / (BATCH_GAS_SAFETY_FACTOR as u64);
  // Confirm the division didn't truncate any values
  assert!(((BATCH_GAS_SAFETY_FACTOR as u64) * batch_gas_limit) == TX_GAS_LIMIT_CAP);
  /*
    Confirm the gas limit for a batch exceeds the limit for an individual destination.

    Note this isn't quite comprehensive due to the overhead of performing such a transfer, and as
    it assumes `ADDRESS_GAS_LIMIT` is greater than constants such as the one used for ERC20
    transfers. We trust `BATCH_GAS_SAFETY_FACTOR` to cover the overhead and assume
    `ADDRESS_GAS_LIMIT` is the largest such constant.
  */
  assert!(batch_gas_limit > ((BATCH_GAS_SAFETY_FACTOR as u64) * (ADDRESS_GAS_LIMIT as u64)));
  batch_gas_limit
};

fn coin_to_ethereum_coin(coin: ExternalCoin) -> EthereumCoin {
  assert_eq!(coin.network(), ExternalNetworkId::Ethereum);
  match coin {
    ExternalCoin::Ether => EthereumCoin::Ether,
    ExternalCoin::Dai => EthereumCoin::Erc20(DAI),
    ExternalCoin::Bitcoin | ExternalCoin::Monero => unreachable!(),
  }
}

fn balance_to_ethereum_amount(balance: ExternalBalance) -> U256 {
  assert_eq!(balance.coin.network(), ExternalNetworkId::Ethereum);
  assert_eq!(balance.coin.decimals(), 8);
  // Restore 10 decimals so we go from 8 decimals to 18 decimals
  // TODO: Document the expectation all integrated coins have 18 decimals
  let factor = U256::from(10_000_000_000u64);
  U256::from(balance.amount.0) * factor
}

#[derive(Clone)]
pub(crate) struct SmartContract {
  pub(crate) chain_id: U256,
  pub(crate) router: Arc<OnceLock<Router>>,
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
      router_address: self
        .router
        .get()
        .expect("scheduler rotating before router was identified")
        .address(),
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
    let router = self.router.get().expect("scheduler fulfilling before router was identified");

    // Sort by coin
    let mut payments_by_coin = HashMap::<_, _>::new();
    for payment in payments {
      let coin = payment.balance().coin;
      payments_by_coin
        .entry(coin)
        .or_insert_with(|| Vec::with_capacity(1))
        .push((payment.address().clone(), balance_to_ethereum_amount(payment.balance())));
    }

    let mut res = vec![];
    for coin in ExternalNetworkId::Ethereum.coins() {
      let Some(mut payments) = payments_by_coin.remove(&coin) else { continue };
      assert!(!payments.is_empty(), "entry in map only populated if there was a payment");

      let maximum_amount_out = {
        let mut maximum_amount_out = U256::ZERO;
        for (_dest, amount) in &payments {
          maximum_amount_out = maximum_amount_out.checked_add(*amount).unwrap();
        }
        maximum_amount_out
      };

      // TODO
      let fee_per_gas = match coin {
        // 10 gwei
        ExternalCoin::Ether => {
          U256::try_from(10u64).unwrap() * alloy_core::primitives::utils::Unit::GWEI.wei()
        }
        // 0.0003 DAI
        ExternalCoin::Dai => {
          U256::try_from(30u64).unwrap() * alloy_core::primitives::utils::Unit::TWEI.wei()
        }
        ExternalCoin::Bitcoin | ExternalCoin::Monero => unreachable!(),
      };

      let mut batch = vec![];
      while !(payments.is_empty() && batch.is_empty()) {
        // If we can append any payments to this batch, do so
        {
          let mut i = 0;
          while i < payments.len() {
            let (gas, _fee) = router.execute_gas_and_fee(
              coin_to_ethereum_coin(coin),
              fee_per_gas,
              &OutInstructions::from(batch.as_slice()),
            );
            if gas <= BATCH_GAS_LIMIT {
              batch.push(payments.remove(i));
            } else {
              // There should be no payment which cannot be pushed onto an empty batch
              assert!(!batch.is_empty());
              i += 1;
            }
          }
        }

        // Now that the batch is full, prune any payments which can't cover their own fee
        // We wait until now as the fullest batch will have the least impact to each individual
        assert!(
          !batch.is_empty(),
          "loop was entered but no items in batch nor payments added to batch"
        );

        let gas_per_payment = batch
          .iter()
          .map(|payment| {
            router.execute_out_instruction_gas_estimate(coin_to_ethereum_coin(coin), payment.into())
          })
          .collect::<Vec<_>>();
        let base_gas = {
          let (batch_gas, _fee) = router.execute_gas_and_fee(
            coin_to_ethereum_coin(coin),
            fee_per_gas,
            &OutInstructions::from(batch.as_slice()),
          );
          batch_gas - gas_per_payment.iter().copied().sum::<u64>()
        };
        let base_gas_per_payment = base_gas.div_ceil(u64::try_from(batch.len()).unwrap());
        let fee_per_payment = gas_per_payment
          .into_iter()
          .map(|gas_per_payment| {
            fee_per_gas.checked_mul(U256::from(base_gas_per_payment + gas_per_payment)).unwrap()
          })
          .collect::<Vec<_>>();

        let original_len = batch.len();
        batch = batch
          .into_iter()
          .zip(fee_per_payment.iter().copied())
          .filter_map(|(payment, fee_per_payment)| {
            (payment.1 >= fee_per_payment).then_some(payment)
          })
          .collect::<Vec<_>>();
        // If this dropped any payments, move to the next iteration of the loop
        if original_len != batch.len() {
          continue;
        }

        // Since this batch is packed and all payments can be amortized, actually amortize it
        let mut total_fee = U256::ZERO;
        for (payment, fee) in batch.iter_mut().zip(fee_per_payment) {
          total_fee = total_fee.checked_add(fee).unwrap();
          payment.1 = payment.1.checked_sub(fee).expect("payment's amount exceeds fee");
        }

        res.push(Action::Batch {
          chain_id: self.chain_id,
          router_address: router.address(),
          nonce,
          coin: coin_to_ethereum_coin(coin),
          fee: total_fee,
          outs: batch,
        });
        nonce += 1;
        batch = vec![];
      }
      assert!(payments.is_empty(), "executed loop before assigning all payments to a batch");
      assert!(batch.is_empty(), "executed loop before finishing a batch");

      assert!(
        maximum_amount_out >= {
          let mut amount_out = U256::ZERO;
          for amount in res.iter().flat_map(|batch| match batch {
            Action::Batch { coin: eth_coin, fee, outs, .. } => {
              if *eth_coin == coin_to_ethereum_coin(coin) {
                core::iter::once(fee).chain(outs.iter().map(|(_dest, amount)| amount)).collect()
              } else {
                vec![]
              }
            }
            Action::SetKey { .. } => unreachable!(),
          }) {
            amount_out = amount_out.checked_add(*amount).unwrap();
          }
          amount_out
        }
      );
    }
    assert!(payments_by_coin.is_empty());

    res.into_iter().map(|action| (action.clone(), action.eventuality())).collect()
  }
}

pub(crate) type Scheduler<D> = smart_contract_scheduler::Scheduler<Rpc<D>, SmartContract>;
