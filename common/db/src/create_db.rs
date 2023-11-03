pub fn db_key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
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
/// value bytes using `bincode`.
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
/// ```no_run
/// create_db!(
///   TrubutariesDb {
///     AttemptsDb: (key_bytes: &[u8], attempt_id: u32) -> u64,
///     ExpiredDb: (genesis: [u8; 32]) -> Vec<u8>
///   }
/// )
/// ```
#[macro_export]
macro_rules! create_db {
  ($db_name: ident
    { $($field_name: ident: ($($arg: ident: $arg_type: ty),*) -> $field_type: ty),*}
  ) => {
    $(
      #[derive(Clone, Debug)]
      pub struct $field_name;
      impl $field_name {
        pub fn key($($arg: $arg_type),*) -> Vec<u8> {
          $crate::db_key(
            stringify!($db_name).as_bytes(),
            stringify!($field_name).as_bytes(),
            (vec![] as Vec<u8>, $($arg),*).encode()
          )
        }
        #[allow(dead_code)]
        pub fn set(txn: &mut impl DbTxn $(, $arg: $arg_type)*,  data: &impl serde::Serialize) {
          let key = $field_name::key($($arg),*);
          txn.put(&key, bincode::serialize(data).unwrap());
        }
        #[allow(dead_code)]
        pub fn get(getter: &impl Get, $($arg: $arg_type),*) -> Option<$field_type> {
          getter.get($field_name::key($($arg),*)).map(|data| {
            bincode::deserialize(data.as_ref()).unwrap()
          })
        }
      }
    )*
  };
}
