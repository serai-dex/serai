use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

use monero_serai::transaction::Transaction;
use monero_wallet::{
  rpc::Rpc,
  address::{AddressType, MoneroAddress},
};

mod runner;

test!(
  eventuality,
  (
    |_, mut builder: Builder, _| async move {
      // Add a standard address, a payment ID address, a subaddress, and a guaranteed address
      // Each have their own slight implications to eventualities
      builder.add_payment(
        MoneroAddress::new(
          Network::Mainnet,
          AddressType::Legacy,
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        1,
      );
      builder.add_payment(
        MoneroAddress::new(
          Network::Mainnet,
          AddressType::LegacyIntegrated([0xaa; 8]),
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        2,
      );
      builder.add_payment(
        MoneroAddress::new(
          Network::Mainnet,
          AddressType::Subaddress,
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        3,
      );
      builder.add_payment(
        MoneroAddress::new(
          Network::Mainnet,
          AddressType::Featured { subaddress: false, payment_id: None, guaranteed: true },
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        4,
      );
      let tx = builder.build().unwrap();
      let eventuality = Eventuality::from(tx.clone());
      assert_eq!(
        eventuality,
        Eventuality::read::<&[u8]>(&mut eventuality.serialize().as_ref()).unwrap()
      );
      (tx, eventuality)
    },
    |_, _, mut tx: Transaction, _, eventuality: Eventuality| async move {
      // 4 explicitly outputs added and one change output
      assert_eq!(tx.prefix().outputs.len(), 5);

      // The eventuality's available extra should be the actual TX's
      assert_eq!(tx.prefix().extra, eventuality.extra());

      // The TX should match
      assert!(eventuality.matches(&tx.clone().into()));

      // Mutate the TX
      let Transaction::V2 { proofs: Some(ref mut proofs), .. } = tx else {
        panic!("TX wasn't RingCT")
      };
      proofs.base.commitments[0] += ED25519_BASEPOINT_POINT;
      // Verify it no longer matches
      assert!(!eventuality.matches(&tx.clone().into()));
    },
  ),
);
