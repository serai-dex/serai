use core::marker::PhantomData;

use scale::{Encode, Decode};

use serai_abi::Call;

use crate::{
  Vec,
  primitives::{PublicKey, SeraiAddress},
  timestamp, coins, dex,
  validator_sets::{self, MembershipProof},
  in_instructions, signals, babe, grandpa, RuntimeCall,
};

impl From<Call> for RuntimeCall {
  fn from(call: Call) -> RuntimeCall {
    match call {
      Call::Timestamp(serai_abi::timestamp::Call::set { now }) => {
        RuntimeCall::Timestamp(timestamp::Call::set { now })
      }
      Call::Coins(coins) => match coins {
        serai_abi::coins::Call::transfer { to, balance } => {
          RuntimeCall::Coins(coins::Call::transfer { to: to.into(), balance })
        }
        serai_abi::coins::Call::burn { balance } => {
          RuntimeCall::Coins(coins::Call::burn { balance })
        }
        serai_abi::coins::Call::burn_with_instruction { instruction } => {
          RuntimeCall::Coins(coins::Call::burn_with_instruction { instruction })
        }
      },
      Call::LiquidityTokens(lt) => match lt {
        serai_abi::coins::LiquidityTokensCall::transfer { to, balance } => {
          RuntimeCall::LiquidityTokens(coins::Call::transfer { to: to.into(), balance })
        }
        serai_abi::coins::LiquidityTokensCall::burn { balance } => {
          RuntimeCall::LiquidityTokens(coins::Call::burn { balance })
        }
      },
      Call::Dex(dex) => match dex {
        serai_abi::dex::Call::add_liquidity {
          coin,
          coin_desired,
          sri_desired,
          coin_min,
          sri_min,
          mint_to,
        } => RuntimeCall::Dex(dex::Call::add_liquidity {
          coin,
          coin_desired,
          sri_desired,
          coin_min,
          sri_min,
          mint_to: mint_to.into(),
        }),
        serai_abi::dex::Call::remove_liquidity {
          coin,
          lp_token_burn,
          coin_min_receive,
          sri_min_receive,
          withdraw_to,
        } => RuntimeCall::Dex(dex::Call::remove_liquidity {
          coin,
          lp_token_burn,
          coin_min_receive,
          sri_min_receive,
          withdraw_to: withdraw_to.into(),
        }),
        serai_abi::dex::Call::swap_exact_tokens_for_tokens {
          path,
          amount_in,
          amount_out_min,
          send_to,
        } => RuntimeCall::Dex(dex::Call::swap_exact_tokens_for_tokens {
          path,
          amount_in,
          amount_out_min,
          send_to: send_to.into(),
        }),
        serai_abi::dex::Call::swap_tokens_for_exact_tokens {
          path,
          amount_out,
          amount_in_max,
          send_to,
        } => RuntimeCall::Dex(dex::Call::swap_tokens_for_exact_tokens {
          path,
          amount_out,
          amount_in_max,
          send_to: send_to.into(),
        }),
      },
      Call::ValidatorSets(vs) => match vs {
        serai_abi::validator_sets::Call::set_keys {
          network,
          removed_participants,
          key_pair,
          signature,
        } => RuntimeCall::ValidatorSets(validator_sets::Call::set_keys {
          network,
          removed_participants: <_>::try_from(
            removed_participants.into_iter().map(PublicKey::from).collect::<Vec<_>>(),
          )
          .unwrap(),
          key_pair,
          signature,
        }),
        serai_abi::validator_sets::Call::report_slashes { network, slashes, signature } => {
          RuntimeCall::ValidatorSets(validator_sets::Call::report_slashes {
            network,
            slashes: <_>::try_from(
              slashes
                .into_iter()
                .map(|(addr, slash)| (PublicKey::from(addr), slash))
                .collect::<Vec<_>>(),
            )
            .unwrap(),
            signature,
          })
        }
        serai_abi::validator_sets::Call::allocate { network, amount } => {
          RuntimeCall::ValidatorSets(validator_sets::Call::allocate { network, amount })
        }
        serai_abi::validator_sets::Call::deallocate { network, amount } => {
          RuntimeCall::ValidatorSets(validator_sets::Call::deallocate { network, amount })
        }
        serai_abi::validator_sets::Call::claim_deallocation { network, session } => {
          RuntimeCall::ValidatorSets(validator_sets::Call::claim_deallocation { network, session })
        }
      },
      Call::InInstructions(ii) => match ii {
        serai_abi::in_instructions::Call::execute_batch { batch } => {
          RuntimeCall::InInstructions(in_instructions::Call::execute_batch { batch })
        }
      },
      Call::Signals(signals) => match signals {
        serai_abi::signals::Call::register_retirement_signal { in_favor_of } => {
          RuntimeCall::Signals(signals::Call::register_retirement_signal { in_favor_of })
        }
        serai_abi::signals::Call::revoke_retirement_signal { retirement_signal_id } => {
          RuntimeCall::Signals(signals::Call::revoke_retirement_signal { retirement_signal_id })
        }
        serai_abi::signals::Call::favor { signal_id, for_network } => {
          RuntimeCall::Signals(signals::Call::favor { signal_id, for_network })
        }
        serai_abi::signals::Call::revoke_favor { signal_id, for_network } => {
          RuntimeCall::Signals(signals::Call::revoke_favor { signal_id, for_network })
        }
        serai_abi::signals::Call::stand_against { signal_id, for_network } => {
          RuntimeCall::Signals(signals::Call::stand_against { signal_id, for_network })
        }
      },
      Call::Babe(babe) => match babe {
        serai_abi::babe::Call::report_equivocation(report) => {
          RuntimeCall::Babe(babe::Call::report_equivocation {
            // TODO: Find a better way to go from Proof<[u8; 32]> to Proof<H256>
            equivocation_proof: <_>::decode(&mut report.equivocation_proof.encode().as_slice())
              .unwrap(),
            key_owner_proof: MembershipProof(report.key_owner_proof.into(), PhantomData),
          })
        }
        serai_abi::babe::Call::report_equivocation_unsigned(report) => {
          RuntimeCall::Babe(babe::Call::report_equivocation_unsigned {
            // TODO: Find a better way to go from Proof<[u8; 32]> to Proof<H256>
            equivocation_proof: <_>::decode(&mut report.equivocation_proof.encode().as_slice())
              .unwrap(),
            key_owner_proof: MembershipProof(report.key_owner_proof.into(), PhantomData),
          })
        }
      },
      Call::Grandpa(grandpa) => match grandpa {
        serai_abi::grandpa::Call::report_equivocation(report) => {
          RuntimeCall::Grandpa(grandpa::Call::report_equivocation {
            // TODO: Find a better way to go from Proof<[u8; 32]> to Proof<H256>
            equivocation_proof: <_>::decode(&mut report.equivocation_proof.encode().as_slice())
              .unwrap(),
            key_owner_proof: MembershipProof(report.key_owner_proof.into(), PhantomData),
          })
        }
        serai_abi::grandpa::Call::report_equivocation_unsigned(report) => {
          RuntimeCall::Grandpa(grandpa::Call::report_equivocation_unsigned {
            // TODO: Find a better way to go from Proof<[u8; 32]> to Proof<H256>
            equivocation_proof: <_>::decode(&mut report.equivocation_proof.encode().as_slice())
              .unwrap(),
            key_owner_proof: MembershipProof(report.key_owner_proof.into(), PhantomData),
          })
        }
      },
    }
  }
}

impl TryInto<Call> for RuntimeCall {
  type Error = ();

  fn try_into(self) -> Result<Call, ()> {
    Ok(match self {
      RuntimeCall::Timestamp(timestamp::Call::set { now }) => {
        Call::Timestamp(serai_abi::timestamp::Call::set { now })
      }
      RuntimeCall::Coins(call) => Call::Coins(match call {
        coins::Call::transfer { to, balance } => {
          serai_abi::coins::Call::transfer { to: to.into(), balance }
        }
        coins::Call::burn { balance } => serai_abi::coins::Call::burn { balance },
        coins::Call::burn_with_instruction { instruction } => {
          serai_abi::coins::Call::burn_with_instruction { instruction }
        }
        _ => Err(())?,
      }),
      RuntimeCall::LiquidityTokens(call) => Call::LiquidityTokens(match call {
        coins::Call::transfer { to, balance } => {
          serai_abi::coins::LiquidityTokensCall::transfer { to: to.into(), balance }
        }
        coins::Call::burn { balance } => serai_abi::coins::LiquidityTokensCall::burn { balance },
        _ => Err(())?,
      }),
      RuntimeCall::Dex(call) => Call::Dex(match call {
        dex::Call::add_liquidity {
          coin,
          coin_desired,
          sri_desired,
          coin_min,
          sri_min,
          mint_to,
        } => serai_abi::dex::Call::add_liquidity {
          coin,
          coin_desired,
          sri_desired,
          coin_min,
          sri_min,
          mint_to: mint_to.into(),
        },
        dex::Call::remove_liquidity {
          coin,
          lp_token_burn,
          coin_min_receive,
          sri_min_receive,
          withdraw_to,
        } => serai_abi::dex::Call::remove_liquidity {
          coin,
          lp_token_burn,
          coin_min_receive,
          sri_min_receive,
          withdraw_to: withdraw_to.into(),
        },
        dex::Call::swap_exact_tokens_for_tokens { path, amount_in, amount_out_min, send_to } => {
          serai_abi::dex::Call::swap_exact_tokens_for_tokens {
            path,
            amount_in,
            amount_out_min,
            send_to: send_to.into(),
          }
        }
        dex::Call::swap_tokens_for_exact_tokens { path, amount_out, amount_in_max, send_to } => {
          serai_abi::dex::Call::swap_tokens_for_exact_tokens {
            path,
            amount_out,
            amount_in_max,
            send_to: send_to.into(),
          }
        }
        _ => Err(())?,
      }),
      RuntimeCall::ValidatorSets(call) => Call::ValidatorSets(match call {
        validator_sets::Call::set_keys { network, removed_participants, key_pair, signature } => {
          serai_abi::validator_sets::Call::set_keys {
            network,
            removed_participants: <_>::try_from(
              removed_participants.into_iter().map(SeraiAddress::from).collect::<Vec<_>>(),
            )
            .unwrap(),
            key_pair,
            signature,
          }
        }
        validator_sets::Call::report_slashes { network, slashes, signature } => {
          serai_abi::validator_sets::Call::report_slashes {
            network,
            slashes: <_>::try_from(
              slashes
                .into_iter()
                .map(|(addr, slash)| (SeraiAddress::from(addr), slash))
                .collect::<Vec<_>>(),
            )
            .unwrap(),
            signature,
          }
        }
        validator_sets::Call::allocate { network, amount } => {
          serai_abi::validator_sets::Call::allocate { network, amount }
        }
        validator_sets::Call::deallocate { network, amount } => {
          serai_abi::validator_sets::Call::deallocate { network, amount }
        }
        validator_sets::Call::claim_deallocation { network, session } => {
          serai_abi::validator_sets::Call::claim_deallocation { network, session }
        }
        _ => Err(())?,
      }),
      RuntimeCall::InInstructions(call) => Call::InInstructions(match call {
        in_instructions::Call::execute_batch { batch } => {
          serai_abi::in_instructions::Call::execute_batch { batch }
        }
        _ => Err(())?,
      }),
      RuntimeCall::Signals(call) => Call::Signals(match call {
        signals::Call::register_retirement_signal { in_favor_of } => {
          serai_abi::signals::Call::register_retirement_signal { in_favor_of }
        }
        signals::Call::revoke_retirement_signal { retirement_signal_id } => {
          serai_abi::signals::Call::revoke_retirement_signal { retirement_signal_id }
        }
        signals::Call::favor { signal_id, for_network } => {
          serai_abi::signals::Call::favor { signal_id, for_network }
        }
        signals::Call::revoke_favor { signal_id, for_network } => {
          serai_abi::signals::Call::revoke_favor { signal_id, for_network }
        }
        signals::Call::stand_against { signal_id, for_network } => {
          serai_abi::signals::Call::stand_against { signal_id, for_network }
        }
        _ => Err(())?,
      }),
      RuntimeCall::Babe(call) => Call::Babe(match call {
        babe::Call::report_equivocation { equivocation_proof, key_owner_proof } => {
          serai_abi::babe::Call::report_equivocation(serai_abi::babe::ReportEquivocation {
            // TODO: Find a better way to go from Proof<H256> to Proof<[u8; 32]>
            equivocation_proof: <_>::decode(&mut equivocation_proof.encode().as_slice()).unwrap(),
            key_owner_proof: key_owner_proof.0.into(),
          })
        }
        babe::Call::report_equivocation_unsigned { equivocation_proof, key_owner_proof } => {
          serai_abi::babe::Call::report_equivocation_unsigned(serai_abi::babe::ReportEquivocation {
            // TODO: Find a better way to go from Proof<H256> to Proof<[u8; 32]>
            equivocation_proof: <_>::decode(&mut equivocation_proof.encode().as_slice()).unwrap(),
            key_owner_proof: key_owner_proof.0.into(),
          })
        }
        _ => Err(())?,
      }),
      RuntimeCall::Grandpa(call) => Call::Grandpa(match call {
        grandpa::Call::report_equivocation { equivocation_proof, key_owner_proof } => {
          serai_abi::grandpa::Call::report_equivocation(serai_abi::grandpa::ReportEquivocation {
            // TODO: Find a better way to go from Proof<H256> to Proof<[u8; 32]>
            equivocation_proof: <_>::decode(&mut equivocation_proof.encode().as_slice()).unwrap(),
            key_owner_proof: key_owner_proof.0.into(),
          })
        }
        grandpa::Call::report_equivocation_unsigned { equivocation_proof, key_owner_proof } => {
          serai_abi::grandpa::Call::report_equivocation_unsigned(
            serai_abi::grandpa::ReportEquivocation {
              // TODO: Find a better way to go from Proof<H256> to Proof<[u8; 32]>
              equivocation_proof: <_>::decode(&mut equivocation_proof.encode().as_slice()).unwrap(),
              key_owner_proof: key_owner_proof.0.into(),
            },
          )
        }
        _ => Err(())?,
      }),
      _ => Err(())?,
    })
  }
}
