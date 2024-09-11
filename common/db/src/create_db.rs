#[doc(hidden)]
pub fn serai_db_key(
  db_dst: &'static [u8],
  item_dst: &'static [u8],
  key: impl AsRef<[u8]>,
) -> Vec<u8> {
  let db_len = u8::try_from(db_dst.len()).unwrap();
  let dst_len = u8::try_from(item_dst.len()).unwrap();
  [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat()
}

/// Creates a series of structs which provide namespacing for keys
///
/// # Description
///
/// Creates a unit struct and a default implementation for the `key`, `get`, and `set`. The macro
/// uses a syntax similar to defining a function. Parameters are concatenated to produce a key,
/// they must be `scale` encodable. The return type is used to auto encode and decode the database
/// value bytes using `borsh`.
///
/// # Arguments
///
/// * `db_name` - A database name
/// * `field_name` - An item name
/// * `args` - Comma separated list of key arguments
/// * `field_type` - The return type
///
/// # Example
///
/// ```ignore
/// create_db!(
///   TributariesDb {
///     AttemptsDb: (key_bytes: &[u8], attempt_id: u32) -> u64,
///     ExpiredDb: (genesis: [u8; 32]) -> Vec<u8>
///   }
/// )
/// ```
#[macro_export]
macro_rules! create_db {
  ($db_name: ident {
    $(
      $field_name: ident:
        $(<$($generic_name: tt: $generic_type: tt),+>)?(
          $($arg: ident: $arg_type: ty),*
        ) -> $field_type: ty$(,)?
    )*
  }) => {
    $(
      #[derive(Clone, Debug)]
      pub(crate) struct $field_name$(
        <$($generic_name: $generic_type),+>
      )?$(
        (core::marker::PhantomData<($($generic_name),+)>)
      )?;
      impl$(<$($generic_name: $generic_type),+>)? $field_name$(<$($generic_name),+>)? {
        pub(crate) fn key($($arg: $arg_type),*) -> Vec<u8> {
          use scale::Encode;
          $crate::serai_db_key(
            stringify!($db_name).as_bytes(),
            stringify!($field_name).as_bytes(),
            ($($arg),*).encode()
          )
        }
        pub(crate) fn set(
          txn: &mut impl DbTxn
          $(, $arg: $arg_type)*,
          data: &$field_type
        ) {
          let key = Self::key($($arg),*);
          txn.put(&key, borsh::to_vec(data).unwrap());
        }
        pub(crate) fn get(
          getter: &impl Get,
          $($arg: $arg_type),*
        ) -> Option<$field_type> {
          getter.get(Self::key($($arg),*)).map(|data| {
            borsh::from_slice(data.as_ref()).unwrap()
          })
        }
        // Returns a PhantomData of all generic types so if the generic was only used in the value,
        // not the keys, this doesn't have unused generic types
        #[allow(dead_code)]
        pub(crate) fn del(
          txn: &mut impl DbTxn
          $(, $arg: $arg_type)*
        ) -> core::marker::PhantomData<($($($generic_name),+)?)> {
          txn.del(&Self::key($($arg),*));
          core::marker::PhantomData
        }

        pub(crate) fn take(
          txn: &mut impl DbTxn
          $(, $arg: $arg_type)*
        ) -> Option<$field_type> {
          let key = Self::key($($arg),*);
          let res = txn.get(&key).map(|data| borsh::from_slice(data.as_ref()).unwrap());
          if res.is_some() {
            txn.del(key);
          }
          res
        }
      }
    )*
  };
}

#[macro_export]
macro_rules! db_channel {
  ($db_name: ident {
    $($field_name: ident:
      $(<$($generic_name: tt: $generic_type: tt),+>)?(
        $($arg: ident: $arg_type: ty),*
      ) -> $field_type: ty$(,)?
    )*
  }) => {
    $(
      create_db! {
        $db_name {
          $field_name: $(<$($generic_name: $generic_type),+>)?(
            $($arg: $arg_type,)*
            index: u32
          ) -> $field_type
        }
      }

      impl$(<$($generic_name: $generic_type),+>)? $field_name$(<$($generic_name),+>)? {
        pub(crate) fn send(
          txn: &mut impl DbTxn
          $(, $arg: $arg_type)*
          , value: &$field_type
        ) {
          // Use index 0 to store the amount of messages
          let messages_sent_key = Self::key($($arg,)* 0);
          let messages_sent = txn.get(&messages_sent_key).map(|counter| {
            u32::from_le_bytes(counter.try_into().unwrap())
          }).unwrap_or(0);
          txn.put(&messages_sent_key, (messages_sent + 1).to_le_bytes());

          // + 2 as index 1 is used for the amount of messages read
          // Using distinct counters enables send to be called without mutating anything recv may
          // at the same time
          let index_to_use = messages_sent + 2;

          Self::set(txn, $($arg,)* index_to_use, value);
        }
        pub(crate) fn try_recv(
          txn: &mut impl DbTxn
          $(, $arg: $arg_type)*
        ) -> Option<$field_type> {
          let messages_recvd_key = Self::key($($arg,)* 1);
          let messages_recvd = txn.get(&messages_recvd_key).map(|counter| {
            u32::from_le_bytes(counter.try_into().unwrap())
          }).unwrap_or(0);

          let index_to_read = messages_recvd + 2;

          let res = Self::get(txn, $($arg,)* index_to_read);
          if res.is_some() {
            Self::del(txn, $($arg,)* index_to_read);
            txn.put(&messages_recvd_key, (messages_recvd + 1).to_le_bytes());
          }
          res
        }
      }
    )*
  };
}
