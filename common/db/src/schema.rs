/// Create a strongly-typed database schema.
///
/// This will define a zero-sized type (ZST) with a statically-defined key structure, helping to
/// effect namespacing for distinct values. The key is not guaranteed to be unique across macro
/// invocations however, it being dependent on the name of the schema and the name of the type.
/// It is guaranteed to be unique within a macro invocation, or across schema definitions with
/// distinct names. Third-party modification of these values within the database has undefined
/// behavior.
///
/// The keys and values are converted to bytes using [`borsh`]. All [`borsh`] serializations are
/// assumed infallible if the underlying writer is, such as when the writer is a [`Vec`], and this
/// library assumes any serialized value may be successfully deserialized. Violations of these
/// conditions MAY incur undefined behavior.
///
/// While the macro supports generic parameters, reading a value written with distinct generic
/// parameters is undefined.
///
/// ### Arguments
///
/// - `Schema`: The name of the schema being defined. This is intended to provide domain-separation
///   with other defined schemas and is limited to being 255 bytes long at most.
/// - `Field`:  A field within the schema. This will be the name of the generated ZST which is
///   usable to read and write to this field  and is limited to being 255 bytes long at most.
/// - `<_>`: Generic type arguments for the arguments and return value. These are not explicitly
///   incorporated into the key and two keys with distinct generic arguments but the same
///   serialization will be considered the same.
/// - `(_)`: Runtime arguments to index the key-space with.
/// - `-> _`: The type of the value stored under this key.
///
/// ### Example
///
/// ```ignore
/// serai_db::schema!(
///   MySchema {
///     Counter: () -> u64,
///     Password: (user: String) -> String,
///     UserData: <PersonalData: BorshSerialize + BorshDeserialize>(user: String) -> PersonalData,
///   }
/// );
/// ```
// TODO: This doesn't support `A + B` generics
#[macro_export]
macro_rules! schema {
  ($Schema: ident {
    $(
      $Field: ident:
        $(<$($generic_name: tt: $generic_type: tt),+>)?(
          $($arg: ident: $arg_type: ty),*
        ) -> $value: ty$(,)?
    )*
  }) => {
    $(
      /// A typed interface for an entry in a database.
      pub(crate) struct $Field$(
        <$($generic_name: $generic_type),+>
      )?$(
        (core::marker::PhantomData<($($generic_name),+)>)
      )?;

      impl$(<$($generic_name: $generic_type),+>)? $Field$(<$($generic_name),+>)? {
        #[doc(hidden)]
        pub(crate) fn key($($arg: $arg_type),*) -> impl AsRef<[u8]> {
          const SCHEMA: &[u8] = stringify!($Schema).as_bytes();
          const FIELD: &[u8] = stringify!($Field).as_bytes();
          const DST: [u8; 1 + SCHEMA.len() + 1 + FIELD.len()] = {
            let mut dst = [0; 1 + SCHEMA.len() + 1 + FIELD.len()];

            assert!(SCHEMA.len() < 255);
            dst[0] = SCHEMA.len() as u8;
            {
              let mut b = 0;
              while b < SCHEMA.len() {
                dst[1 + b] = SCHEMA[b];
                b += 1;
              }
            }

            assert!(FIELD.len() < 255);
            dst[1 + SCHEMA.len()] = FIELD.len() as u8;
            {
              let mut b = 0;
              while b < FIELD.len() {
                dst[(1 + SCHEMA.len() + 1) + b] = FIELD[b];
                b += 1;
              }
            }

            dst
          };

          let mut key = DST.to_vec();
          <($($arg_type),*) as $crate::__private::borsh::BorshSerialize>::serialize(
            &($($arg),*),
            &mut key
          ).expect("`BorshSerialize` errored when writing to an infallible writer (`Vec`)");
          key
        }

        /// Set this entry within the database.
        ///
        /// Please see [`Transaction::set`] for the bounds on this.
        pub(crate) fn set(
          txn: &mut impl $crate::Transaction
          $(, $arg: $arg_type)*,
          value: &$value
        ) {
          let key = Self::key($($arg),*);
          let value = $crate::__private::borsh::to_vec(value)
            .expect("`BorshSerialize` errored when writing to an infallible writer (`Vec`)");
          $crate::Transaction::set(txn, key, value);
        }

        /// Get this value from the database.
        ///
        /// The value MUST have be written with the same generic parameters now being used to read
        /// it.
        pub(crate) fn get(
          getter: &impl $crate::Get,
          $($arg: $arg_type),*
        ) -> Option<$value> {
          $crate::Get::get(getter, Self::key($($arg),*)).map(|value| {
            $crate::__private::borsh::from_slice(value.as_ref())
              .expect("`BorshDeserialize` errored when reading a value it wrote")
          })
        }

        /// Delete this entry from the database.
        ///
        /// Please see [`Transaction::del`] for the bounds on this.
        pub(crate) fn del(
          txn: &mut impl $crate::Transaction
          $(, $arg: $arg_type)*
        ) {
          $crate::Transaction::del(txn, &Self::key($($arg),*));
        }

        /// Take this entry from the database.
        ///
        /// This performs a `get`, followed by a `del`. Please see them for the bounds on this.
        pub(crate) fn take(
          txn: &mut impl $crate::Transaction
          $(, $arg: $arg_type)*
        ) -> Option<$value> {
          let key = Self::key($($arg),*);
          let res = $crate::Get::get(txn, &key).map(|value| {
            $crate::__private::borsh::from_slice(value.as_ref())
              .expect("`BorshDeserialize` errored when reading a value it wrote")
          });
          if res.is_some() {
            $crate::Transaction::del(txn, &key);
          }
          res
        }
      }
    )*
  };
}

/// A database-backed channel.
///
/// This defines a channel such that a producer may send messages a consumer may then read, without
/// risking creating conflicting transactions. The channel is unbounded, but messages are taken
/// upon being received leaving the storage costs soley linear to the amount of _not yet received_
/// messages.
///
/// The API for invoking this matches [`schema`].
#[macro_export]
macro_rules! channel {
  ($Schema: ident {
    $($Field: ident:
      $(<$($generic_name: tt: $generic_type: tt),+>)?(
        $($arg: ident: $arg_type: ty),*
      ) -> $value: ty$(,)?
    )*
  }) => {
    #[doc(hidden)]
    #[allow(non_snake_case)]
    mod $Schema {
      use super::*;

      $crate::schema! {
        $Schema {
          $(
            $Field: $(<$($generic_name: $generic_type),+>)?(
              $($arg: $arg_type,)*
              index: u64
            ) -> $value
          )*
        }
      }
    }

    $(
      /// A typed interface for a database-backed channel.
      pub(crate) struct $Field$(
        <$($generic_name: $generic_type),+>
      )?$(
        (core::marker::PhantomData<($($generic_name),+)>)
      )?;

      impl$(<$($generic_name: $generic_type),+>)? $Field$(<$($generic_name),+>)? {
        /// Send a message down this channel.
        ///
        /// This will never conflict with `try_recv` due to never writing to the same keys.
        ///
        /// Please see [`Transaction::set`] for the bounds on this.
        pub(crate) fn send(
          txn: &mut impl $crate::Transaction
          $(, $arg: $arg_type)*
          , value: &$value
        ) {
          /*
            - `0` is used for the amount of messages sent
            - `1` is used for the amount of messages received
            - messages begin at index `2`
          */

          let messages_sent_key = $Schema::$Field$(::<$($generic_name),+>)?::key($($arg,)* 0);
          // Fetch the amount of messages already sent
          let messages_sent = $crate::Get::get(txn, &messages_sent_key).map(|counter| {
            u64::from_le_bytes(counter.as_ref().try_into().unwrap())
          }).unwrap_or(0);
          // Increment the amount of message sent
          $crate::Transaction::set(txn, &messages_sent_key, (messages_sent + 1).to_le_bytes());

          $Schema::$Field$(::<$($generic_name),+>)?::set(txn, $($arg,)* 2 + messages_sent, value);
        }

        /// Peek at the next message in this channel, without consuming it.
        pub(crate) fn peek(
          getter: &impl $crate::Get
          $(, $arg: $arg_type)*
        ) -> Option<$value> {
          let messages_recvd_key = $Schema::$Field$(::<$($generic_name),+>)?::key($($arg,)* 1);
          let messages_recvd = $crate::Get::get(getter, &messages_recvd_key).map(|counter| {
            u64::from_le_bytes(counter.as_ref().try_into().unwrap())
          }).unwrap_or(0);

          $Schema::$Field$(::<$($generic_name),+>)?::get(getter, $($arg,)* 2 + messages_recvd)
        }

        /// Try to receive a message from this channel.
        ///
        /// This will never conflict with `send` due to never writing to the same keys.
        ///
        /// Please see [`Transaction::set`] for the bounds on this.
        pub(crate) fn try_recv(
          txn: &mut impl $crate::Transaction
          $(, $arg: $arg_type)*
        ) -> Option<$value> {
          let messages_recvd_key = $Schema::$Field$(::<$($generic_name),+>)?::key($($arg,)* 1);
          let messages_recvd = $crate::Get::get(txn, &messages_recvd_key).map(|counter| {
            u64::from_le_bytes(counter.as_ref().try_into().unwrap())
          }).unwrap_or(0);

          let message_index = 2 + messages_recvd;

          let res = $Schema::$Field$(::<$($generic_name),+>)?::get(txn, $($arg,)* message_index);
          // If this message existed, consume it, and update the next message to receive
          if res.is_some() {
            /*
              This `del` call writes to a key set by a transaction already committed, where the
              producer will not write to this key again (meaning the producer couldn't possibly
              have a concurrent transaction).
            */
            $Schema::$Field$(::<$($generic_name),+>)?::del(txn, $($arg,)* message_index);
            $crate::Transaction::set(txn, &messages_recvd_key, (messages_recvd + 1).to_le_bytes());
          }
          res
        }
      }
    )*
  };
}
