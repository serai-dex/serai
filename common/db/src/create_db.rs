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
/// * `args` - Comma seperated list of key arguments
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
    $($field_name: ident: ($($arg: ident: $arg_type: ty),*) -> $field_type: ty$(,)?)*
  }) => {
    $(
      #[derive(Clone, Debug)]
      pub struct $field_name;
      impl $field_name {
        pub fn key($($arg: $arg_type),*) -> Vec<u8> {
          $crate::serai_db_key(
            stringify!($db_name).as_bytes(),
            stringify!($field_name).as_bytes(),
            ($($arg),*).encode()
          )
        }
        pub fn set(txn: &mut impl DbTxn $(, $arg: $arg_type)*, data: &$field_type) {
          let key = $field_name::key($($arg),*);
          txn.put(&key, borsh::to_vec(data).unwrap());
        }
        pub fn get(getter: &impl Get, $($arg: $arg_type),*) -> Option<$field_type> {
          getter.get($field_name::key($($arg),*)).map(|data| {
            borsh::from_slice(data.as_ref()).unwrap()
          })
        }
        #[allow(dead_code)]
        pub fn del(txn: &mut impl DbTxn $(, $arg: $arg_type)*) {
          txn.del(&$field_name::key($($arg),*))
        }
      }
    )*
  };
}

#[macro_export]
macro_rules! db_channel {
  ($db_name: ident {
    $($field_name: ident: ($($arg: ident: $arg_type: ty),*) -> $field_type: ty$(,)?)*
  }) => {
    $(
      create_db! {
        $db_name {
          $field_name: ($($arg: $arg_type,)* index: u32) -> $field_type,
        }
      }

      impl $field_name {
        pub fn send(txn: &mut impl DbTxn $(, $arg: $arg_type)*, value: &$field_type) {
          // Use index 0 to store the amount of messages
          let messages_sent_key = $field_name::key($($arg),*, 0);
          let messages_sent = txn.get(&messages_sent_key).map(|counter| {
            u32::from_le_bytes(counter.try_into().unwrap())
          }).unwrap_or(0);
          txn.put(&messages_sent_key, (messages_sent + 1).to_le_bytes());

          // + 2 as index 1 is used for the amount of messages read
          // Using distinct counters enables send to be called without mutating anything recv may
          // at the same time
          let index_to_use = messages_sent + 2;

          $field_name::set(txn, $($arg),*, index_to_use, value);
        }
        pub fn try_recv(txn: &mut impl DbTxn $(, $arg: $arg_type)*) -> Option<$field_type> {
          let messages_recvd_key = $field_name::key($($arg),*, 1);
          let messages_recvd = txn.get(&messages_recvd_key).map(|counter| {
            u32::from_le_bytes(counter.try_into().unwrap())
          }).unwrap_or(0);

          let index_to_read = messages_recvd + 2;

          let res = $field_name::get(txn, $($arg),*, index_to_read);
          if res.is_some() {
            $field_name::del(txn, $($arg),*, index_to_read);
            txn.put(&messages_recvd_key, (messages_recvd + 1).to_le_bytes());
          }
          res
        }
      }
    )*
  };
}
