use std::collections::HashSet;
use hex_literal::hex;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand_core::OsRng;
use zeroize::Zeroizing;

use monero_serai::{
  wallet::{
    address::{Network, MoneroAddress},
    ViewPair, SignableTransaction, Scanner,
  },
};

mod runner;

const ADDR_SPEND: [u8; 32] =
  hex!("bf02a79d9e30ea76872e565722517924151793c535832e4353e54dc0be698001");
const ADDR_VIEW: [u8; 32] =
  hex!("c300b798c000f3c5da4ebc5a288418fe9060d623c9830b7abc3d9e7a3152eb08");

pub struct AddressInfo {
  address: String,
  payment_id: Option<[u8; 8]>,
}

pub async fn scan_incomings(addr_scanner: &mut Scanner, addresses: &Vec<AddressInfo>) {
  // get an output to spend
  let (miner_spend, miner_view, miner_addr) = runner::random_address();
  let mut miner_scanner =
    Scanner::from_view(miner_view.clone(), Network::Mainnet, Some(HashSet::new()));
  let rpc = runner::rpc().await;
  let mut input = runner::get_miner_tx_output(&rpc, &miner_view).await;

  // chain params
  let fee = rpc.get_fee().await.unwrap();
  let start = rpc.get_height().await.unwrap() - 59; // -60 input is already grabbed above
  let protocol = rpc.get_protocol().await.unwrap();
  let amount = 1000000;

  for (i, addr) in addresses.iter().enumerate() {
    let mut tx = SignableTransaction::new(
      protocol,
      vec![input],
      vec![(MoneroAddress::from_str(Network::Mainnet, &addr.address).unwrap(), amount)],
      Some(miner_addr),
      vec![],
      fee,
    )
    .unwrap()
    .sign(&mut OsRng, &rpc, &Zeroizing::new(miner_spend))
    .await
    .unwrap();

    // submit and unlock tx
    rpc.publish_transaction(&tx).await.unwrap();
    runner::mine_until_unlocked(&rpc, &miner_addr.to_string(), tx.hash()).await;

    // get the tx and confirm receipt
    tx = rpc.get_transaction(tx.hash()).await.unwrap();
    let output = addr_scanner.scan_transaction(&tx).not_locked().swap_remove(0);
    assert_eq!(output.commitment().amount, amount);
    if addr.payment_id.is_some() {
      assert_eq!(output.metadata.payment_id, addr.payment_id.unwrap());
    }

    // pick another input to spend for the  next address
    let block = rpc.get_block(start + i).await.unwrap();
    input = miner_scanner
      .scan(&rpc, &block)
      .await
      .unwrap()
      .swap_remove(0)
      .ignore_timelock()
      .swap_remove(0);
  }
}

async_sequential!(
  async fn scan_all_standard_addresses() {
    // scanner
    let spend_pub = &Scalar::from_bits(ADDR_SPEND) * &ED25519_BASEPOINT_TABLE;
    let mut scanner = Scanner::from_view(
      ViewPair::new(spend_pub, Zeroizing::new(Scalar::from_bits(ADDR_VIEW))),
      Network::Mainnet,
      Some(HashSet::new()),
    );

    // generate all types of addresses
    let payment_ids = vec![
      [46, 48, 134, 34, 245, 148, 243, 195],
      [153, 176, 98, 204, 151, 27, 197, 168],
      [88, 37, 149, 111, 171, 108, 120, 181],
    ];
    let mut addresses = vec![];
    // standard versions
    addresses.push(AddressInfo { address: scanner.address().to_string(), payment_id: None });
    addresses
      .push(AddressInfo { address: scanner.subaddress((0, 1)).to_string(), payment_id: None });
    addresses.push(AddressInfo {
      address: scanner.integrated_address(payment_ids[0]).to_string(),
      payment_id: Some(payment_ids[0]),
    });
    // featured versions
    addresses.push(AddressInfo {
      address: scanner.featured_address(Some((0, 2)), Some(payment_ids[1]), false).to_string(),
      payment_id: Some(payment_ids[1]),
    });
    addresses.push(AddressInfo {
      address: scanner.featured_address(None, None, false).to_string(),
      payment_id: None,
    });
    addresses.push(AddressInfo {
      address: scanner.featured_address(Some((0, 3)), None, false).to_string(),
      payment_id: None,
    });
    addresses.push(AddressInfo {
      address: scanner.featured_address(None, Some(payment_ids[2]), false).to_string(),
      payment_id: Some(payment_ids[2]),
    });

    // send to &  test receive from addresses
    scan_incomings(&mut scanner, &addresses).await;
  }
);

async_sequential!(
  async fn scan_all_guaranteed_addresses() {
    // scanner
    let spend_pub = &Scalar::from_bits(ADDR_SPEND) * &ED25519_BASEPOINT_TABLE;
    let mut scanner = Scanner::from_view(
      ViewPair::new(spend_pub, Zeroizing::new(Scalar::from_bits(ADDR_VIEW))),
      Network::Mainnet,
      None,
    );

    // generate all types of addresses
    let payment_ids =
      vec![[88, 37, 149, 111, 171, 108, 120, 181], [125, 69, 155, 152, 140, 160, 157, 186]];
    let mut addresses = vec![];
    // featured (false, none, true)
    addresses.push(AddressInfo { address: scanner.address().to_string(), payment_id: None });
    // featured (false, some, true)
    addresses.push(AddressInfo {
      address: scanner.integrated_address(payment_ids[0]).to_string(),
      payment_id: Some(payment_ids[0]),
    });
    // featured (true, none, true)
    addresses
      .push(AddressInfo { address: scanner.subaddress((0, 1)).to_string(), payment_id: None });
    // featured (true, some, true)
    addresses.push(AddressInfo {
      address: scanner.featured_address(Some((0, 2)), Some(payment_ids[1]), true).to_string(),
      payment_id: Some(payment_ids[1]),
    });

    // send to &  test receive from addresses
    scan_incomings(&mut scanner, &addresses).await;
  }
);
