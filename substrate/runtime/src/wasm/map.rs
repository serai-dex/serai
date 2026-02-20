use serai_abi::validator_sets::Slashes;

use super::*;

impl From<serai_abi::Call> for RuntimeCall {
  fn from(call: serai_abi::Call) -> Self {
    match call {
      serai_abi::Call::Coins(call) => {
        use serai_abi::coins::Call;
        use serai_coins_pallet::Call as Scall;
        RuntimeCall::Coins(match call {
          Call::transfer { to, coins } => Scall::transfer { to, coins },
          Call::burn { coins } => Scall::burn { coins },
          Call::burn_with_instruction { instruction } => {
            Scall::burn_with_instruction { instruction }
          }
        })
      }
      serai_abi::Call::ValidatorSets(call) => {
        use serai_abi::validator_sets::Call;
        use serai_validator_sets_pallet::Call as Scall;
        RuntimeCall::ValidatorSets(match call {
          Call::set_keys { network, key_pair, signature_participants, signature } => {
            Scall::set_keys { network, key_pair, signature_participants, signature }
          }
          Call::report_slashes(Slashes::Serai { session, validator, reason: _ }) => {
            Scall::slash_serai_validator { session, validator }
          }
          Call::report_slashes(Slashes::ExternalNetwork { set, slashes, signature }) => {
            Scall::report_slashes { set, slashes, signature }
          }
          Call::set_embedded_elliptic_curve_keys { keys } => Scall::set_auxiliary_keys { keys },
          Call::allocate { network, amount } => Scall::allocate { network, amount },
          Call::deallocate { network, amount } => Scall::deallocate { network, amount },
          Call::claim_deallocation { deallocation } => Scall::claim_deallocation {
            network: deallocation.network,
            session: deallocation.session,
          },
        })
      }
      serai_abi::Call::Signals(call) => {
        use serai_abi::signals::Call;
        use serai_signals_pallet::Call as Scall;
        RuntimeCall::Signals(match call {
          Call::register_retirement_signal { in_favor_of } => {
            Scall::register_retirement_signal { in_favor_of }
          }
          Call::revoke_retirement_signal { was_in_favor_of } => {
            Scall::revoke_retirement_signal { retirement_signal: was_in_favor_of }
          }
          Call::favor { signal, with_network } => Scall::favor { signal, with_network },
          Call::revoke_favor { signal, with_network } => {
            Scall::revoke_favor { signal, with_network }
          }
          Call::stand_against { signal, with_network } => {
            Scall::stand_against { signal, with_network }
          }
        })
      }
      serai_abi::Call::Dex(call) => {
        use serai_abi::dex::Call;
        RuntimeCall::Dex(match call {
          Call::add_liquidity {
            external_coin,
            sri_intended,
            external_coin_intended,
            sri_minimum,
            external_coin_minimum,
          } => serai_dex_pallet::Call::add_liquidity {
            external_coin,
            sri_intended,
            external_coin_intended,
            sri_minimum,
            external_coin_minimum,
          },
          Call::transfer_liquidity { to, liquidity_tokens } => {
            serai_dex_pallet::Call::transfer_liquidity { to, liquidity_tokens }
          }
          Call::remove_liquidity { liquidity_tokens, sri_minimum, external_coin_minimum } => {
            serai_dex_pallet::Call::remove_liquidity {
              liquidity_tokens,
              sri_minimum,
              external_coin_minimum,
            }
          }
          Call::swap { coins_to_swap, minimum_to_receive } => {
            serai_dex_pallet::Call::swap { coins_to_swap, minimum_to_receive }
          }
          Call::swap_for { coins_to_receive, maximum_to_swap } => {
            serai_dex_pallet::Call::swap_for { coins_to_receive, maximum_to_swap }
          }
        })
      }
      serai_abi::Call::GenesisLiquidity(call) => {
        use serai_abi::genesis_liquidity::Call;
        RuntimeCall::GenesisLiquidity(match call {
          Call::oraclize_values { values, signature_participants, signature } => {
            serai_genesis_liquidity_pallet::Call::oraclize_values {
              values,
              signature_participants,
              signature,
            }
          }
          Call::transfer_genesis_liquidity { to, genesis_liquidity } => {
            serai_genesis_liquidity_pallet::Call::transfer_genesis_liquidity {
              to,
              genesis_liquidity,
            }
          }
          Call::remove_genesis_liquidity {
            genesis_liquidity,
            sri_minimum,
            external_coin_minimum,
          } => serai_genesis_liquidity_pallet::Call::remove_genesis_liquidity {
            genesis_liquidity,
            sri_minimum,
            external_coin_minimum,
          },
        })
      }
      serai_abi::Call::InInstructions(call) => {
        use serai_abi::in_instructions::Call;
        RuntimeCall::InInstructions(match call {
          Call::execute_batch { batch } => {
            serai_in_instructions_pallet::Call::execute_batch { batch }
          }
        })
      }
    }
  }
}
