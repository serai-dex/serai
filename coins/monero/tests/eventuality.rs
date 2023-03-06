use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

use monero_serai::{
  transaction::Transaction,
  wallet::{
    Eventuality,
    address::{AddressType, AddressMeta, MoneroAddress},
  },
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
          AddressMeta::new(Network::Mainnet, AddressType::Standard),
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        1,
      );
      builder.add_payment(
        MoneroAddress::new(
          AddressMeta::new(Network::Mainnet, AddressType::Integrated([0xaa; 8])),
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        2,
      );
      builder.add_payment(
        MoneroAddress::new(
          AddressMeta::new(Network::Mainnet, AddressType::Subaddress),
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        3,
      );
      builder.add_payment(
        MoneroAddress::new(
          AddressMeta::new(
            Network::Mainnet,
            AddressType::Featured { subaddress: false, payment_id: None, guaranteed: true },
          ),
          ED25519_BASEPOINT_POINT,
          ED25519_BASEPOINT_POINT,
        ),
        4,
      );
      builder.set_r_seed(Zeroizing::new([0xbb; 32]));
      let tx = builder.build().unwrap();
      let eventuality = tx.eventuality().unwrap();
      assert_eq!(
        eventuality,
        Eventuality::read::<&[u8]>(&mut eventuality.serialize().as_ref()).unwrap()
      );
      (tx, eventuality)
    },
    |_, mut tx: Transaction, _, eventuality: Eventuality| async move {
      // 4 explicitly outputs added and one change output
      assert_eq!(tx.prefix.outputs.len(), 5);

      // The eventuality's available extra should be the actual TX's
      assert_eq!(tx.prefix.extra, eventuality.extra());

      // The TX should match
      assert!(eventuality.matches(&tx));

      // Mutate the TX
      tx.rct_signatures.base.commitments[0] += ED25519_BASEPOINT_POINT;
      // Verify it no longer matches
      assert!(!eventuality.matches(&tx));
    },
  ),
);
