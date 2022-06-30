use hex_literal::hex;

use crate::wallet::address::{Network, AddressType, Address};

const SPEND: [u8; 32] = hex!("f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7");
const VIEW: [u8; 32] = hex!("4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce");

const STANDARD: &'static str = "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";

const PAYMENT_ID: [u8; 8] = hex!("b8963a57855cf73f");
const INTEGRATED: &'static str = "4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35";

const SUB_SPEND: [u8; 32] = hex!("fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b");
const SUB_VIEW: [u8; 32] = hex!("9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470");
const SUBADDRESS: &'static str = "8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB";

#[test]
fn standard_address() {
  let addr = Address::from_str(STANDARD, Network::Mainnet).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Standard);
  assert_eq!(addr.meta.guaranteed, false);
  assert_eq!(addr.spend.compress().to_bytes(), SPEND);
  assert_eq!(addr.view.compress().to_bytes(), VIEW);
}

#[test]
fn integrated_address() {
  let addr = Address::from_str(INTEGRATED, Network::Mainnet).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Integrated(PAYMENT_ID));
  assert_eq!(addr.meta.guaranteed, false);
  assert_eq!(addr.spend.compress().to_bytes(), SPEND);
  assert_eq!(addr.view.compress().to_bytes(), VIEW);
}

#[test]
fn subaddress() {
  let addr = Address::from_str(SUBADDRESS, Network::Mainnet).unwrap();
  assert_eq!(addr.meta.network, Network::Mainnet);
  assert_eq!(addr.meta.kind, AddressType::Subaddress);
  assert_eq!(addr.meta.guaranteed, false);
  assert_eq!(addr.spend.compress().to_bytes(), SUB_SPEND);
  assert_eq!(addr.view.compress().to_bytes(), SUB_VIEW);
}
