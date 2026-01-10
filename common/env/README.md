# Serai Env

A common library for Serai applications to access environment variables.

## Overview

This crate provides a simple interface for retrieving environment variables across Serai services. It's designed as a centralized way to handle environment configuration and will eventually be extended to support a proper secret store.

## Usage

```rust
use serai_env::var;

// Get an environment variable
if let Some(db_path) = var("DB_PATH") {
    println!("Database path: {}", db_path);
}
```

## Features

- Simple API for environment variable access
- Returns `Option<String>` for safe handling of missing variables
- Designed to be extended for secret store integration

## Future Improvements

This crate is currently a thin wrapper around `std::env::var` but is planned to be extended with:
- Integration with a proper secret store
- Automatic variable cleanup after retrieval
- Enhanced security features for sensitive configuration

## License

AGPL-3.0-only
