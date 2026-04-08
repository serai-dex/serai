use std::collections::HashMap;

use alloy_core::primitives::U256;

use serai_primitives::{network_id::ExternalNetworkId, coin::ExternalCoin, balance::ExternalBalance};
use serai_client_ethereum::{ADDRESS_GAS_LIMIT, Address};

use serai_db::Db;

use primitives::Payment;
use scanner::{KeyFor, AddressFor, EventualityFor};

use ethereum_schnorr::PublicKey;
use ethereum_router::Coin as EthereumCoin;

use crate::{DAI, transaction::Action, rpc::Rpc};

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
      router_address: if true { todo!("TODO") } else { Default::default() },
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

      // TODO: All of this gas code needs to be rewritten around
      // `Router::{execute_gas_and_fee, execute_out_instruction_gas_estimate}`

      // The gas required to perform any interaction with the Router.
      const BASE_GAS: u32 = 0; // TODO

      // The gas required to handle an additional payment to an address, in the worst case.
      const ADDRESS_PAYMENT_GAS: u32 = 0; // TODO

      // The gas required to handle an additional payment to an smart contract, in the worst case.
      // This does not include the explicit gas budget defined within the address specification.
      const CONTRACT_PAYMENT_GAS: u32 = 0; // TODO

      // The maximum amount of gas for a batch.
      const BATCH_GAS_LIMIT: u32 = 10_000_000;

      let mut batch = vec![];
      while !(payments.is_empty() && batch.is_empty()) {
        let dest_gas = |dest: &Address| {
          let gas = match dest {
            Address::Address(_) => ADDRESS_PAYMENT_GAS,
            Address::Contract(deployment) => {
              assert!(deployment.gas_limit() < ADDRESS_GAS_LIMIT);
              CONTRACT_PAYMENT_GAS + deployment.gas_limit()
            }
          };

          // Perform `const` assertions which justify this following runtime assertion
          const {
            assert!(ADDRESS_PAYMENT_GAS < BATCH_GAS_LIMIT);
            assert!((CONTRACT_PAYMENT_GAS + ADDRESS_GAS_LIMIT) < BATCH_GAS_LIMIT);
          }
          assert!(gas < BATCH_GAS_LIMIT);

          gas
        };

        // If we can append any payments to this batch, do so
        {
          let mut i = 0;
          while i < payments.len() {
            /*
              This is a `u32` so it would panic on overflow, but it won't so long as
              `(dest_gas(_) < BATCH_GAS_LIMIT) && (BATCH_GAS_LIMIT <= (u32::MAX / 2))`.
              The first clause is checked within the `dest_gas` function.
            */
            const {
              assert!(BATCH_GAS_LIMIT < (u32::MAX / 2));
            }

            if (BASE_GAS +
              batch.iter().map(|(dest, _)| dest_gas(dest)).sum::<u32>() +
              dest_gas(&payments[i].0)) <=
              BATCH_GAS_LIMIT
            {
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
        let base_gas_per_payment = BASE_GAS.div_ceil(u32::try_from(batch.len()).unwrap());
        let amortized_gas_per_payment = |(dest, _): &(_, _)| base_gas_per_payment + dest_gas(dest);
        let fee_per_payment = |payment: &(_, _)| {
          U256::from(amortized_gas_per_payment(payment)).checked_mul(fee_per_gas).unwrap()
        };
        let original_len = batch.len();
        batch = batch
          .into_iter()
          .filter(|payment| payment.1 >= fee_per_payment(payment))
          .collect::<Vec<_>>();
        // If this dropped any payments, move to the next iteration of the loop
        if original_len != batch.len() {
          continue;
        }

        // Since this batch is packed and all payments can be amortized, actually amortize it
        let mut total_fee = U256::ZERO;
        for payment in &mut batch {
          let fee = fee_per_payment(payment);
          total_fee = total_fee.checked_add(fee).unwrap();
          payment.1 = payment.1.checked_sub(fee).expect("payment's amount exceeds fee");
        }

        res.push(Action::Batch {
          chain_id: self.chain_id,
          router_address: if true { todo!("TODO") } else { Default::default() },
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
