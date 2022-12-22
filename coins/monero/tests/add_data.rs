use monero_serai::{wallet::TransactionError, transaction::Transaction};

mod runner;

test!(
  add_single_data_less_than_255,
  (
    |_, mut builder: Builder, addr| async move {
      // make a data that is less than 255 bytes
      let arbitrary_data = Vec::from("this is an arbitrary data less than 255 bytes");

      // make sure we can add to tx
      let result = builder.add_data(arbitrary_data.clone());
      assert!(result.is_ok());

      builder.add_payment(addr, 5);
      (builder.build().unwrap(), (arbitrary_data,))
    },
    |_, tx: Transaction, mut scanner: Scanner, state: (Vec<u8>,)| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      assert_eq!(output.arbitrary_data()[0], state.0);
    },
  ),
);

test!(
  add_multiple_data_less_than_255,
  (
    |_, mut builder: Builder, addr| async move {
      // make a data that is less than 255 bytes
      let arbitrary_data = Vec::from("this is an arbitrary data less than 255 bytes");

      // add tx multiple times
      for _ in 0 .. 5 {
        let result = builder.add_data(arbitrary_data.clone());
        assert!(result.is_ok());
      }

      builder.add_payment(addr, 5);
      (builder.build().unwrap(), (arbitrary_data,))
    },
    |_, tx: Transaction, mut scanner: Scanner, state: (Vec<u8>,)| async move {
      let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);
      assert_eq!(output.commitment().amount, 5);
      let data = output.arbitrary_data();
      for i in 0 .. 5 {
        assert_eq!(data[i], state.0);
      }
    },
  ),
);

test!(
  add_single_data_more_than_255,
  (
    |_, mut builder: Builder, addr| async move {
      // make a data that is bigger than 255 bytes
      let mut arbitrary_data = vec![];
      for _ in 0 .. 256 {
        arbitrary_data.push(b'a');
      }

      // make sure we get an error if we try to add it to tx
      let mut result = builder.add_payment(addr, 5).add_data(arbitrary_data.clone());
      assert_eq!(result, Err(TransactionError::TooMuchData));

      // reduce data size and re-try
      arbitrary_data.swap_remove(0);
      result = builder.add_data(arbitrary_data);

      assert!(result.is_ok());
      (builder.build().unwrap(), ())
    },
    |_, _, _, _| async move {},
  ),
);
