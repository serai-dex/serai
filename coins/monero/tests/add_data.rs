use monero_serai::{
  transaction::Transaction,
  wallet::{TransactionError, extra::MAX_ARBITRARY_DATA_SIZE},
};

mod runner;

test!(
  add_single_data_less_than_max,
  (
    |_, mut builder: Builder, addr| async move {
      let arbitrary_data = vec![b'\0'; MAX_ARBITRARY_DATA_SIZE - 1];

      // make sure we can add to tx
      let result = builder.add_data(arbitrary_data.clone());
      assert!(result.is_ok());

      builder.add_payment(addr, 5);
      (builder.build().unwrap(), (arbitrary_data,))
    },
    |_, tx: Transaction, mut scanner: Scanner, data: (Vec<u8>,)| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.arbitrary_data()[0], data.0);
    },
  ),
);

test!(
  add_multiple_data_less_than_max,
  (
    |_, mut builder: Builder, addr| async move {
      let data = vec![b'\0'; MAX_ARBITRARY_DATA_SIZE - 1];

      // Add tx multiple times
      for _ in 0 .. 5 {
        let result = builder.add_data(data.clone());
        assert!(result.is_ok());
      }

      builder.add_payment(addr, 5);
      (builder.build().unwrap(), data)
    },
    |_, tx: Transaction, mut scanner: Scanner, data: Vec<u8>| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.arbitrary_data(), vec![data; 5]);
    },
  ),
);

test!(
  add_single_data_more_than_max,
  (
    |_, mut builder: Builder, addr| async move {
      // Make a data that is bigger than the maximum
      let mut data = vec![b'a'; MAX_ARBITRARY_DATA_SIZE + 1];

      // Make sure we get an error if we try to add it to the TX
      assert_eq!(builder.add_data(data.clone()), Err(TransactionError::TooMuchData));

      // Reduce data size and retry. The data will now be 255 bytes long (including the added
      // marker), exactly
      data.pop();
      assert!(builder.add_data(data.clone()).is_ok());

      builder.add_payment(addr, 5);
      (builder.build().unwrap(), data)
    },
    |_, tx: Transaction, mut scanner: Scanner, data: Vec<u8>| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.arbitrary_data(), vec![data]);
    },
  ),
);
