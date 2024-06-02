use sp_runtime::BoundedVec;

use serai_primitives::*;

type PoolId = Coin;
type MaxSwapPathLength = sp_core::ConstU32<3>;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Call {
  add_liquidity {
    coin: Coin,
    coin_desired: SubstrateAmount,
    sri_desired: SubstrateAmount,
    coin_min: SubstrateAmount,
    sri_min: SubstrateAmount,
    mint_to: SeraiAddress,
  },
  remove_liquidity {
    coin: Coin,
    lp_token_burn: SubstrateAmount,
    coin_min_receive: SubstrateAmount,
    sri_min_receive: SubstrateAmount,
    withdraw_to: SeraiAddress,
  },
  swap_exact_tokens_for_tokens {
    path: BoundedVec<Coin, MaxSwapPathLength>,
    amount_in: SubstrateAmount,
    amount_out_min: SubstrateAmount,
    send_to: SeraiAddress,
  },
  swap_tokens_for_exact_tokens {
    path: BoundedVec<Coin, MaxSwapPathLength>,
    amount_out: SubstrateAmount,
    amount_in_max: SubstrateAmount,
    send_to: SeraiAddress,
  },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  PoolCreated {
    pool_id: PoolId,
    pool_account: SeraiAddress,
  },

  LiquidityAdded {
    who: SeraiAddress,
    mint_to: SeraiAddress,
    pool_id: PoolId,
    coin_amount: SubstrateAmount,
    sri_amount: SubstrateAmount,
    lp_token_minted: SubstrateAmount,
  },

  LiquidityRemoved {
    who: SeraiAddress,
    withdraw_to: SeraiAddress,
    pool_id: PoolId,
    coin_amount: SubstrateAmount,
    sri_amount: SubstrateAmount,
    lp_token_burned: SubstrateAmount,
  },

  SwapExecuted {
    who: SeraiAddress,
    send_to: SeraiAddress,
    path: BoundedVec<Coin, MaxSwapPathLength>,
    amount_in: SubstrateAmount,
    amount_out: SubstrateAmount,
  },
}
