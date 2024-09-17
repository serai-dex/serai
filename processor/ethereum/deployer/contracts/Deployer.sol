// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

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
  mapping(bytes32 => address) public deployments;

  error PriorDeployed();
  error DeploymentFailed();

  function deploy(bytes memory init_code) external {
    // Deploy the contract
    address created_contract;
    assembly {
      created_contract := create(0, add(init_code, 0x20), mload(init_code))
    }
    if (created_contract == address(0)) {
      revert DeploymentFailed();
    }

    bytes32 init_code_hash = keccak256(init_code);

    // Check this wasn't prior deployed
    // We check this *after* deploymeing (in violation of CEI) to handle re-entrancy related bugs
    if (deployments[init_code_hash] != address(0)) {
      revert PriorDeployed();
    }

    // Write the deployment to storage
    deployments[init_code_hash] = created_contract;
  }
}
