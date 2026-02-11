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

  /// The required amount of allocated stake (denominated in SRI) to consider a balance secure.
  fn stake_for_balance(balance: ExternalBalance) -> Amount {
    let value = T::EconomicSecurity::sri_value(balance).0;
    // As 67% can execute signing protocols, 67% of stake must be sufficient to secure this
    let requirement = value.saturating_mul(3).div_ceil(2);
    // We require an additional margin of 20%
    let margin = requirement.div_ceil(5);
    Amount(requirement.saturating_add(margin))
  }

  /// The required amount of SRI which must be allocated as stake for a network to be considered
  /// economically secure.
  ///
  /// This evaluates the stake required to secure the amount of coins within the liquidity pool,
  /// with the valuation from the economic security oracle.
  pub fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
    let mut requirement = Amount(0).0;
    for coin in network.coins() {
      let liquidity_pool_balance =
        Coins::<T>::balance(serai_abi::dex::address(coin), Coin::from(coin));
      requirement = requirement.saturating_add(
        Self::stake_for_balance(ExternalBalance { coin, amount: liquidity_pool_balance }).0,
      );
    }
    Amount(requirement)
  }
}
