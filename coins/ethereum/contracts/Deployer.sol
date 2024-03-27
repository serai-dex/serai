// SPDX-License-Identifier: AGPLv3
pragma solidity ^0.8.0;

/*
The expected deployment process of the Router is as follows:

1) A transaction deploying Deployer is made. Then, a deterministic signature is
   created such that an account with an unknown private key is the creator of
   the contract. Anyone can fund this address, and once anyone does, the
   transaction deploying Deployer can be published by anyone. No other
   transaction may be made from that account.

2) Anyone deploys the Router through the Deployer. This uses a sequential nonce
   such that meet-in-the-middle attacks, with complexity 2**80, aren't feasible.
   While such attacks would still be feasible if the Deployer's address was
   controllable, the usage of a deterministic signature with a NUMS method
   prevents that.

This doesn't have any denial-of-service risks and will resolve once anyone steps
forward as deployer. This does fail to guarantee an identical address across
every chain, though it enables letting anyone efficiently ask the Deployer for
the address (with the Deployer having an identical address on every chain).

Unfortunately, guaranteeing identical addresses aren't feasible. We'd need the
Deployer contract to use a consistent salt for the Router, yet the Router must
be deployed with a specific public key for Serai. Since Ethereum isn't able to
determine a valid public key (one the result of a Serai DKG) from a dishonest
public key, we have to allow multiple deployments with Serai being the one to
determine which to use.

The alternative would be to have a council publish the Serai key on-Ethereum,
with Serai verifying the published result. This would introduce a DoS risk in
the council not publishing the correct key/not publishing any key.
*/

contract Deployer {
  event Deployment(bytes32 indexed init_code_hash, address created);

  function deploy(bytes memory init_code) external {
    address created;
    assembly {
      created := create(0, add(init_code, 0x20), mload(init_code))
    }
    // These may be emitted out of order upon re-entrancy
    emit Deployment(keccak256(init_code), created);
  }
}
