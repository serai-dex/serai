use std::str::FromStr;

use scale::Decode;
use zeroize::Zeroizing;

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ed25519, Secp256k1,
};

use sp_core::{
  Pair as PairTrait,
  sr25519::{Public, Pair},
};

use serai_abi::{
  in_instructions::primitives::Shorthand,
  primitives::{
    insecure_pair_from_name, ExternalBalance, ExternalCoin, ExternalNetworkId, QuotePriceParams,
    Amount,
  },
  validator_sets::primitives::{ExternalValidatorSet, KeyPair, Session},
};
use serai_client::{Serai, SeraiAddress};

use rand_core::{RngCore, OsRng};

mod common;
use common::{validator_sets::set_keys, in_instructions::mint_coin, dex::add_liquidity};

serai_test!(
  external_address: (|serai: Serai| async move {
      test_external_address(serai).await;
  })

  encoded_shorthand: (|serai: Serai| async move {
    test_encoded_shorthand(serai).await;
  })

  dex_quote_price: (|serai: Serai| async move {
    test_dex_quote_price(serai).await;
  })
);

async fn set_network_keys<C: Ciphersuite>(
  serai: &Serai,
  set: ExternalValidatorSet,
  pairs: &[Pair],
) {
  // Ristretto key
  let mut ristretto_key = [0; 32];
  OsRng.fill_bytes(&mut ristretto_key);

  // network key
  let network_priv_key = Zeroizing::new(C::F::random(&mut OsRng));
  let network_key = (C::generator() * *network_priv_key).to_bytes().as_ref().to_vec();

  let key_pair = KeyPair(Public(ristretto_key), network_key.try_into().unwrap());
  let _ = set_keys(serai, set, key_pair, pairs).await;
}

async fn test_external_address(serai: Serai) {
  let pair = insecure_pair_from_name("Alice");

  // set btc keys
  let network = ExternalNetworkId::Bitcoin;
  set_network_keys::<Secp256k1>(
    &serai,
    ExternalValidatorSet { session: Session(0), network },
    &[pair.clone()],
  )
  .await;

  // get the address from the node
  let btc_address: String = serai.external_network_address(network).await.unwrap();

  // make sure it is a valid address
  let _ = bitcoin::Address::from_str(&btc_address)
    .unwrap()
    .require_network(bitcoin::Network::Bitcoin)
    .unwrap();

  // set monero keys
  let network = ExternalNetworkId::Monero;
  set_network_keys::<Ed25519>(
    &serai,
    ExternalValidatorSet { session: Session(0), network },
    &[pair],
  )
  .await;

  // get the address from the node
  let xmr_address: String = serai.external_network_address(network).await.unwrap();

  // make sure it is a valid address
  let _ = monero_address::MoneroAddress::from_str(monero_address::Network::Mainnet, &xmr_address)
    .unwrap();
}

async fn test_encoded_shorthand(serai: Serai) {
  let shorthand = Shorthand::transfer(None, SeraiAddress::new([0u8; 32]));
  let encoded = serai.encoded_shorthand(shorthand.clone()).await.unwrap();

  assert_eq!(Shorthand::decode::<&[u8]>(&mut encoded.as_slice()).unwrap(), shorthand);
}

async fn test_dex_quote_price(serai: Serai) {
  // make a liquid pool to get the quote on
  let coin1 = ExternalCoin::Bitcoin;
  let coin2 = ExternalCoin::Monero;
  let amount1 = Amount(10u64.pow(coin1.decimals()));
  let amount2 = Amount(10u64.pow(coin2.decimals()));
  let pair = insecure_pair_from_name("Ferdie");

  // mint sriBTC in the account so that we can add liq.
  // Ferdie account is already pre-funded with SRI.
  mint_coin(
    &serai,
    ExternalBalance { coin: coin1, amount: amount1 },
    0,
    pair.clone().public().into(),
  )
  .await;

  // add liquidity
  let coin_amount = Amount(amount1.0 / 2);
  let sri_amount = Amount(amount1.0 / 2);
  let _ = add_liquidity(&serai, coin1, coin_amount, sri_amount, 0, pair.clone()).await;

  // same for xmr
  mint_coin(
    &serai,
    ExternalBalance { coin: coin2, amount: amount2 },
    0,
    pair.clone().public().into(),
  )
  .await;

  // add liquidity
  let coin_amount = Amount(amount2.0 / 2);
  let sri_amount = Amount(amount2.0 / 2);
  let _ = add_liquidity(&serai, coin2, coin_amount, sri_amount, 1, pair.clone()).await;

  // price for BTC -> SRI -> XMR path
  let params = QuotePriceParams {
    coin1: coin1.into(),
    coin2: coin2.into(),
    amount: coin_amount.0 / 2,
    include_fee: true,
    exact_in: true,
  };

  let res = serai.quote_price(params).await.unwrap();
  assert!(res > 0);
}
