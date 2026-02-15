use super::*;

impl<T: Config> Pallet<T> {
  pub(crate) fn include_genesis_validators(network: impl Into<NetworkId>) -> bool {
    match network.into() {
      // For Serai, we include the genesis validators as long as any other set would
      NetworkId::Serai => ExternalNetworkId::all().any(Self::include_genesis_validators),
      // For external networks, we include the genesis validators if pre-economic security
      NetworkId::External(network) => !T::EconomicSecurity::achieved_economic_security(network),
    }
  }

  /// The required amount of SRI which must be allocated as stake for a network to be considered
  /// economically secure regarding the total amount of coins.
  ///
  /// This evaluates the stake required to secure the amount of coins with the valuation from the
  /// economic security oracle, without any buffer.
  ///
  /// This accepts a `proposed_additional_balance` which, if present, will be added to the relevant
  /// supply when performing the calculation. The balance's coin's network MUST be `network` for
  /// this to be sound. This has undefined behavior if it isn't.
  ///
  /// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
  /// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
  pub fn coins_stake_requirement(
    network: ExternalNetworkId,
    proposed_additional_balance: Option<Balance>,
  ) -> Amount {
    let mut requirement = Amount(0).0;
    for coin in network.coins() {
      let mut coin_supply = Coins::<T>::supply(Coin::from(coin));
      if let Some(proposed_additional_balance) = proposed_additional_balance {
        if proposed_additional_balance.coin == Coin::External(coin) {
          coin_supply.0 = coin_supply.0.saturating_add(proposed_additional_balance.amount.0);
        }
      }

      let stake_for_balance = {
        let value = T::EconomicSecurity::sri_value(ExternalBalance { coin, amount: coin_supply });
        // As 67% can execute signing protocols, 67% of stake must be sufficient to secure this
        let requirement = (u128::from(value.0) * 3).div_ceil(2);
        Amount(u64::try_from(requirement).unwrap_or(u64::MAX))
      };

      requirement = requirement.saturating_add(stake_for_balance.0);
    }
    Amount(requirement)
  }

  /// The required amount of SRI which must be allocated as stake for a network to be considered
  /// economically secure regarding the coins in the liquidity pool.
  ///
  /// This evaluates the stake required to secure the amount of coins within the liquidity pool
  /// with the valuation from the economic security oracle, with an additional buffer for safety.
  ///
  /// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
  /// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
  pub fn liquidity_tokens_stake_requirement(network: ExternalNetworkId) -> Amount {
    let mut requirement = Amount(0).0;
    for coin in network.coins() {
      let liquidity_pool_balance =
        Coins::<T>::balance(serai_abi::dex::address(coin), Coin::from(coin));

      let stake_for_balance = {
        let value =
          T::EconomicSecurity::sri_value(ExternalBalance { coin, amount: liquidity_pool_balance });
        // As 67% can execute signing protocols, 67% of stake must be sufficient to secure this
        let requirement = (u128::from(value.0) * 3).div_ceil(2);
        // We require an additional margin of 20%
        let margin = requirement.div_ceil(5);
        Amount(u64::try_from(requirement.saturating_add(margin)).unwrap_or(u64::MAX))
      };

      requirement = requirement.saturating_add(stake_for_balance.0);
    }
    Amount(requirement)
  }

  /// The required amount of SRI which must be allocated as stake for a network to be considered
  /// economically secure.
  ///
  /// This may return `Amount(u64::MAX)` to represent an overflow. As `u64::MAX` can be assumed to
  /// exceed the SRI supply, this will represent a requirement which can never be fulfilled.
  pub fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
    Self::coins_stake_requirement(network, None)
      .max(Self::liquidity_tokens_stake_requirement(network))
  }
}
