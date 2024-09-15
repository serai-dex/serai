# Ethereum Smart Contracts Deployer

The deployer for Serai's Ethereum contracts.

## Goals

It should be possible to efficiently locate the Serai Router on an blockchain with the EVM, without
relying on any centralized (or even federated) entities. While deploying and locating an instance of
the Router would be trivial, by using a fixed signature for the deployment transaction, the Router
must be constructed with the correct key for the Serai network (or set to have the correct key
post-construction). Since this cannot be guaranteed to occur, the process must be retryable and the
first successful invocation must be efficiently findable.

## Methodology

We define a contract, the Deployer, to deploy the router. This contract could use `CREATE2` with the
key representing Serai as the salt, yet this would be open to collision attacks with just 2**80
complexity. Instead, we use `CREATE` which would require 2**80 on-chain transactions (infeasible) to
use as the basis of a collision.

In order to efficiently find the contract for a key, the Deployer contract saves the addresses of
deployed contracts (indexed by the initialization code hash). This allows using a single call to a
contract with a known address to find the proper Router.
