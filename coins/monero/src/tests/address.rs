use hex_literal::hex;

use rand_core::{RngCore, OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY};

use crate::{
  random_scalar,
  wallet::address::{Network, AddressType, AddressMeta, MoneroAddress},
};

const SPEND: [u8; 32] = hex!("f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7");
const VIEW: [u8; 32] = hex!("4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce");

const STANDARD: &str =
  "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";

const PAYMENT_ID: [u8; 8] = hex!("b8963a57855cf73f");
const INTEGRATED: &str =
  "4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6Mn\
  pXSn88oBX35";

const SUB_SPEND: [u8; 32] =
  hex!("fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b");
const SUB_VIEW: [u8; 32] = hex!("9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470");
const SUBADDRESS: &str =
  "8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB";

const FEATURED_JSON: &str = include_str!("vectors/featured_addresses.json");

#[test]
fn standard_address() {
  let addr = MoneroAddress::from_str(Network::Mainnet, STANDARD).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Standard);
  assert!(!addr.meta.kind.is_subaddress());
  assert_eq!(addr.meta.kind.payment_id(), None);
  assert!(!addr.meta.kind.is_guaranteed());
  assert_eq!(addr.spend.compress().to_bytes(), SPEND);
  assert_eq!(addr.view.compress().to_bytes(), VIEW);
  assert_eq!(addr.to_string(), STANDARD);
}

#[test]
fn integrated_address() {
  let addr = MoneroAddress::from_str(Network::Mainnet, INTEGRATED).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Integrated(PAYMENT_ID));
  assert!(!addr.meta.kind.is_subaddress());
  assert_eq!(addr.meta.kind.payment_id(), Some(PAYMENT_ID));
  assert!(!addr.meta.kind.is_guaranteed());
  assert_eq!(addr.spend.compress().to_bytes(), SPEND);
  assert_eq!(addr.view.compress().to_bytes(), VIEW);
  assert_eq!(addr.to_string(), INTEGRATED);
}

#[test]
fn subaddress() {
  let addr = MoneroAddress::from_str(Network::Mainnet, SUBADDRESS).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Subaddress);
  assert!(addr.meta.kind.is_subaddress());
  assert_eq!(addr.meta.kind.payment_id(), None);
  assert!(!addr.meta.kind.is_guaranteed());
  assert_eq!(addr.spend.compress().to_bytes(), SUB_SPEND);
  assert_eq!(addr.view.compress().to_bytes(), SUB_VIEW);
  assert_eq!(addr.to_string(), SUBADDRESS);
}

#[test]
fn featured() {
  for (network, first) in
    [(Network::Mainnet, 'C'), (Network::Testnet, 'K'), (Network::Stagenet, 'F')]
  {
    for _ in 0 .. 100 {
      let spend = &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE;
      let view = &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE;

      for features in 0 .. (1 << 3) {
        const SUBADDRESS_FEATURE_BIT: u8 = 1;
        const INTEGRATED_FEATURE_BIT: u8 = 1 << 1;
        const GUARANTEED_FEATURE_BIT: u8 = 1 << 2;

        let subaddress = (features & SUBADDRESS_FEATURE_BIT) == SUBADDRESS_FEATURE_BIT;

        let mut payment_id = [0; 8];
        OsRng.fill_bytes(&mut payment_id);
        let payment_id = Some(payment_id)
          .filter(|_| (features & INTEGRATED_FEATURE_BIT) == INTEGRATED_FEATURE_BIT);

        let guaranteed = (features & GUARANTEED_FEATURE_BIT) == GUARANTEED_FEATURE_BIT;

        let kind = AddressType::Featured { subaddress, payment_id, guaranteed };
        let meta = AddressMeta::new(network, kind);
        let addr = MoneroAddress::new(meta, spend, view);

        assert_eq!(addr.to_string().chars().next().unwrap(), first);
        assert_eq!(MoneroAddress::from_str(network, &addr.to_string()).unwrap(), addr);

        assert_eq!(addr.spend, spend);
        assert_eq!(addr.view, view);

        assert_eq!(addr.is_subaddress(), subaddress);
        assert_eq!(addr.payment_id(), payment_id);
        assert_eq!(addr.is_guaranteed(), guaranteed);
      }
    }
  }
}

#[test]
fn featured_vectors() {
  #[derive(serde::Deserialize)]
  struct Vector {
    address: String,

    network: String,
    spend: String,
    view: String,

    subaddress: bool,
    integrated: bool,
    payment_id: Option<[u8; 8]>,
    guaranteed: bool,
  }

  let vectors = serde_json::from_str::<Vec<Vector>>(FEATURED_JSON).unwrap();
  for vector in vectors {
    let first = vector.address.chars().next().unwrap();
    let network = match vector.network.as_str() {
      "Mainnet" => {
        assert_eq!(first, 'C');
        Network::Mainnet
      }
      "Testnet" => {
        assert_eq!(first, 'K');
        Network::Testnet
      }
      "Stagenet" => {
        assert_eq!(first, 'F');
        Network::Stagenet
      }
      _ => panic!("Unknown network"),
    };
    let spend =
      CompressedEdwardsY::from_slice(&hex::decode(vector.spend).unwrap()).decompress().unwrap();
    let view =
      CompressedEdwardsY::from_slice(&hex::decode(vector.view).unwrap()).decompress().unwrap();

    let addr = MoneroAddress::from_str(network, &vector.address).unwrap();
    assert_eq!(addr.spend, spend);
    assert_eq!(addr.view, view);

    assert_eq!(addr.is_subaddress(), vector.subaddress);
    assert_eq!(vector.integrated, vector.payment_id.is_some());
    assert_eq!(addr.payment_id(), vector.payment_id);
    assert_eq!(addr.is_guaranteed(), vector.guaranteed);

    assert_eq!(
      MoneroAddress::new(
        AddressMeta::new(
          network,
          AddressType::Featured {
            subaddress: vector.subaddress,
            payment_id: vector.payment_id,
            guaranteed: vector.guaranteed
          }
        ),
        spend,
        view
      )
      .to_string(),
      vector.address
    );
  }
}
