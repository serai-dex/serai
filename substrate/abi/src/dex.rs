use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  address::SeraiAddress,
  coin::ExternalCoin,
  balance::{Amount, ExternalBalance, Balance},
};

/// A call to the DEX.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Add liquidity.
  add_liquidity {
    /// The coin to add liquidity for.
    coin: ExternalCoin,
    /// The intended amount of SRI to add as liquidity.
    sri_intended: Amount,
    /// The intended amount of the coin to add as liquidity.
    coin_intended: Amount,
    /// The minimum amount of SRI to add as liquidity.
    sri_minimum: Amount,
    /// The minimum amount of the coin to add as liquidity.
    coin_minimum: Amount,
  },
  /// Transfer these liquidity tokens to the specified address.
  transfer_liquidity {
    /// The address to transfer to.
    to: SeraiAddress,
    /// The liquidity tokens to transfer.
    liquidity_tokens: ExternalBalance,
  },
  /// Remove liquidity.
  remove_liquidity {
    /// The liquidity tokens to burn, removing the underlying liquidity from the pool.
    ///
    /// The `coin` within the balance is the coin to remove liquidity for.
    liquidity_tokens: ExternalBalance,
    /// The minimum amount of SRI to receive.
    sri_minimum: Amount,
    /// The minimum amount of the coin to receive.
    coin_minimum: Amount,
  },
  /// Swap an exact amount of coins.
  swap_exact {
    /// The coins to swap.
    coins_to_swap: Balance,
    /// The minimum balance to receive.
    minimum_to_receive: Balance,
  },
  /// Swap for an exact amount of coins.
  swap_for_exact {
    /// The coins to receive.
    coins_to_receive: Balance,
    /// The maximum amount to swap.
    maximum_to_swap: Balance,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::add_liquidity { .. } |
      Call::transfer_liquidity { .. } |
      Call::remove_liquidity { .. } |
      Call::swap_exact { .. } |
      Call::swap_for_exact { .. } => true,
    }
  }
}

/// An event from the DEX.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// Liquidity was added to a pool.
  LiquidityAdded {
    /// The account which added the liquidity.
    origin: SeraiAddress,
    /// The account which received the liquidity tokens.
    recipient: SeraiAddress,
    /// The pool liquidity was added to.
    pool: ExternalCoin,
    /// The amount of liquidity tokens which were minted.
    liquidity_tokens_minted: Amount,
    /// The amount of the coin which was added to the pool's liquidity.
    coin_amount: Amount,
    /// The amount of SRI which was added to the pool's liquidity.
    sri_amount: Amount,
  },

  /// Liquidity was removed from a pool.
  LiquidityRemoved {
    /// The account which removed the liquidity.
    origin: SeraiAddress,
    /// The pool liquidity was removed from.
    pool: ExternalCoin,
    /// The mount of liquidity tokens which were burnt.
    liquidity_tokens_burnt: Amount,
    /// The amount of the coin which was removed from the pool's liquidity.
    coin_amount: Amount,
    /// The amount of SRI which was removed from the pool's liquidity.
    sri_amount: Amount,
  },

  /// A swap through the liquidity pools occurred.
  Swap {
    /// The account which made the swap.
    origin: SeraiAddress,
    /// The recipient for the output of the swap.
    recipient: SeraiAddress,
    /// The deltas incurred by the pools.
    ///
    /// For a swap of sriABC to sriDEF, this would be
    /// `[Balance { sriABC, 1 }, Balance { SRI, 2 }, Balance { sriDEF, 3 }]`, where
    /// `Balance { sriABC, 1 }` was added to the `sriABC-SRI` pool, `Balance { SRI, 2 }` was
    /// removed from the `sriABC-SRI` pool and added to the `sriDEF-SRI` pool, and
    /// `Balance { sriDEF, 3 }` was removed from the `sriDEF-SRI` pool.
    deltas: Vec<Balance>,
  },
}
