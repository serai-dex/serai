use super::*;

#[test]
fn mint() {
  let mut ext = new_test_ext(vec![]);
  let state_version = ext.state_version;
  ext.execute_with(|| {
    Core::start_transaction(0);

    let root_at_start = sp_io::storage::root(state_version);

    let mut state = State::new();

    let coin = Coin::Serai;
    let to = SeraiAddress::from(Pair::generate().0.public());

    assert_eq!(Coins::supply(coin), Amount(0));
    assert_eq!(Coins::balance(to, coin), Amount(0));

    // Minting `u64::MAX` should work
    let balance = Balance { coin, amount: Amount(u64::MAX) };

    Coins::mint(to, balance).unwrap();
    state.mint::<CoinsInstance>(to, balance);
    assert_eq!(Coins::supply(balance.coin), balance.amount);
    assert_eq!(Coins::balance(to, balance.coin), balance.amount);

    // Minting more should fail, with no changes to the state
    {
      let root = sp_io::storage::root(state_version);
      // Check `sp_io::TestExternalities` doesn't stub this and it does update upon change
      assert_ne!(root_at_start, root);
      assert!(Coins::mint(to, Balance { coin, amount: Amount(1) }).is_err());
      assert_eq!(sp_io::storage::root(state_version), root);
    }

    // Minting for another instance should behave the same, but without an event associated
    let events = Core::events();
    let balance = Balance { coin: ExternalCoin::Bitcoin.into(), amount: Amount(1) };
    LiquidityTokens::mint(to, balance).unwrap();
    state.mint::<LiquidityTokensInstance>(to, balance);
    // Check the events haven't changed, meaning no event was emitted
    assert_eq!(events, Core::events());
  });
}

#[test]
fn genesis() {
  use rand_core::{RngCore as _, OsRng};

  let alice = SeraiAddress::from(Pair::generate().0.public());
  let alice_balance = Balance { coin: Coin::Serai, amount: Amount(OsRng.next_u64()) };
  let bob = SeraiAddress::from(Pair::generate().0.public());
  let bob_balance = Balance { coin: ExternalCoin::Ether.into(), amount: Amount(OsRng.next_u64()) };
  let coins = vec![(alice, alice_balance), (bob, bob_balance)];

  let mut ext = new_test_ext(coins.clone());
  ext.execute_with(|| {
    for (account, balance) in coins.clone() {
      assert_eq!(Coins::balance(account, balance.coin), balance.amount);
    }
    for coin in Coin::all() {
      let supply = Amount(
        coins
          .iter()
          .filter_map(|(_account, balance)| (balance.coin == coin).then_some(balance.amount.0))
          .sum::<u64>(),
      );
      assert_eq!(Coins::supply(coin), supply);
    }
  });
}

#[test]
fn allow_mint() {
  let mut ext = new_test_ext(vec![]);
  let state_version = ext.state_version;
  ext.execute_with(|| {
    let mut state = State::new();

    let to = SeraiAddress::from(Pair::generate().0.public());
    let balance = Balance { coin: Coin::Serai, amount: Amount(1) };
    GenesisLiquidityTokens::mint(to, balance).unwrap();
    state.mint::<GenesisLiquidityTokensInstance>(to, balance);

    {
      let mut allow_mint_lock = ALLOW_MINT.lock().unwrap();
      assert!(*allow_mint_lock);
      *allow_mint_lock = false;
    }

    // Mints should now error without effecting any state changes
    let root = sp_io::storage::root(state_version);
    assert!(matches!(
      GenesisLiquidityTokens::mint(to, balance).unwrap_err(),
      crate::Error::<Test, GenesisLiquidityTokensInstance>::MintNotAllowed
    ));
    assert_eq!(root, sp_io::storage::root(state_version));
  });
}
