# Ethereum

This package contains Ethereum-related functionality, specifically deploying and interacting with Serai contracts.

## Requirements

- npm / node.js (16.0+)
- anvil & solc & geth's abigen (see [here](https://github.com/gakonst/ethers-rs#running-the-tests))

## To test 

To compile and run JS tests:

```
cd schnorr-verify
npx hardhat test
```

To run Rust tests (you must have compiled the contracts first with `npx hardhat compile` or `npx hardhat test`):
```
cd ..
cargo test
```