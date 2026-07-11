# Serai DB

An inefficient, minimal abstraction around databases.

This was originally written simply to be abstract over the underlying database,
with the minimal abstraction existing to be easy to instantiate from almost any
ACID database. The abstraction has remained minimal due to appreciating its
simplicity, which is almost charming. Discussions and feedback are welcome
however.

### Model

All databases are expected to flush to disk for every operation and _panic_ if
the database operation would fail. The only intended method for handling
database errors is to crash.

Databases, as represented by [`Db`], are primarily considered as _handles_.
They may be cloned while still representing the same underlying database. For
all transactions which simultaneously exist, it is assumed only one will write
to a key, with undefined reconciliation if multiple simultaneous transactions
attempt to write to a single key. Reading from a key which was not modified by
the current transaction, but which was modified by a simultaneous transaction,
is undefined to which value is returned but it will be either the value when
the transaction was opened _or_ the value currently in the database.

Databases MAY assume they have been left intact, without alteration,
substitution, or corruption, with undefined behavior upon any of these events
occurring.

### Serialization

This library includes a macro for generating a typed view of a database schema,
one which premises the serialization of keys and values upon [`borsh`]. All
[`borsh`] serializations are assumed infallible if the underlying writer is,
such as when the writer is a [`Vec`], and this library assumes any serialized
value may be successfully deserialized. Violations of these conditions MAY
incur undefined behavior.

### Bug Bounty

This library is maintained under the
[Serai](https://github.com/serai-dex/serai) repository which has very strict
standards. Specifically, _any undocumented panic reachable from a public API_
is generally considered a security issue covered by
[Serai's Bug Bounty Program](
  https://github.com/serai-dex/serai/tree/next/SECURITY.md
). However, the implementations of traits within this library, which occurs at
time-of-compile _are assumed to be in good faith_. While the traits do
_attempt_ to clearly and explicitly document the expected bounds, intentionally
antagonistic implementations, or implementations which would break
near-immediately and not pass basic testing, will not be considered security
issues. In order to be a security issue, a _good faith_ implementation
(even if naïve) must effect a panic internal to this library, though
antagonistic usage of the API _with correct implementations of the traits_ will
still be recognized as security issues.
