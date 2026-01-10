# Serai DB

A simple database trait and backends for it.

## Overview

This crate provides a generic database interface with support for multiple backend implementations. It defines traits for database operations and includes implementations for RocksDB and Parity DB.

## Features

- **Generic Database Trait**: Abstract interface for database operations
- **Atomic Transactions**: Support for ACID-compliant database transactions
- **Multiple Backends**: RocksDB, Parity DB, and in-memory implementations
- **Type-safe Keys**: Automatic key prefixing with database and item destinations

## Usage

```rust
use serai_db::{Db, Get};

let mut db = serai_db::new_rocksdb("path/to/db");

// Get a value
if let Some(value) = db.get(b"key") {
    println!("Found value");
}

// Atomic transaction
let mut txn = db.txn();
txn.put(b"key1", b"value1");
txn.commit();
```

## License

MIT
