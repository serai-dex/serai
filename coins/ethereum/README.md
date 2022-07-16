# Ethereum

This package contains Ethereum-related functionality, specifically deploying and interacting with Serai contracts.

## Requirements

- anvil & solc & geth's abigen (see [here](https://github.com/gakonst/ethers-rs#running-the-tests))

## To test 

To compile contracts:
```
cargo build
```

This places the compiled artifact into `artifacts/`.

To run Rust tests (you must have compiled the contracts first):
```
cargo test
```