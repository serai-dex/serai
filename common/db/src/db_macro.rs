#[macro_export]
macro_rules! create_db {
  ($db_name: ident
    { $($field_name: ident: $field_type: ty),*}
  ) => {
    fn db_key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
      let db_len = u8::try_from(db_dst.len()).unwrap();
      let dst_len = u8::try_from(item_dst.len()).unwrap();
      [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat()
    }

    $(
      #[derive(Clone, Debug)]
      pub struct $field_name;
      impl $field_name {
        pub fn key(key: impl AsRef<[u8]>) -> Vec<u8> {
          db_key(stringify!($db_name).as_bytes(), stringify!($field_name).as_bytes(), key)
        }
        #[allow(dead_code)]
        pub fn set(txn: &mut impl DbTxn, key: impl AsRef<[u8]>, data: &impl serde::Serialize) {
          let key = $field_name::key(key);
          txn.put(&key, bincode::serialize(data).unwrap());
        }
        #[allow(dead_code)]
        pub fn get(getter: &impl Get, key: impl AsRef<[u8]>) -> Option<$field_type> {
          getter.get($field_name::key(key)).map(|data| {
            bincode::deserialize(data.as_ref()).unwrap()
          })
        }
      }
    )*
  };
}
