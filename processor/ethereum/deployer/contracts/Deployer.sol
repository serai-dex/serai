// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

/*
  The expected deployment process of Serai's Router is as follows:

  1) A transaction deploying Deployer is made. Then, a deterministic signature
     is created such that an account with an unknown private key is the creator
     of the contract. Anyone can fund this address, and once anyone does, the
     transaction deploying Deployer can be published by anyone. No other
     transaction may be made from that account.

  2) Anyone deploys the Router through the Deployer. This uses a sequential
     nonce such that meet-in-the-middle attacks, with complexity 2**80, aren't
     feasible. While such attacks would still be feasible if the Deployer's
     address was controllable, the usage of a deterministic signature with a
     NUMS method prevents that.

  This doesn't have any denial-of-service risks and will resolve once anyone
  steps forward as deployer. This does fail to guarantee an identical address
  for the Router across every chain, though it enables anyone to efficiently
  ask the Deployer for the address (with the Deployer having an identical
  address on every chain).

  Unfortunately, guaranteeing identical addresses for the Router isn't
  feasible. We'd need the Deployer contract to use a consistent salt for the
  Router, yet the Router must be deployed with a specific public key for Serai.
  Since Ethereum isn't able to determine a valid public key (one the result of
  a Serai DKG) from a dishonest public key (one arbitrary), we have to allow
  multiple deployments with Serai being the one to determine which to use.

  The alternative would be to have a council publish the Serai key on-Ethereum,
  with Serai verifying the published result. This would introduce a DoS risk in
  the council not publishing the correct key/not publishing any key.

  This design does not work (well) with contracts expecting initialization due
  to only allowing deploying init code once (which assumes contracts are
  distinct via their constructors). Such designs are unused by Serai so that is
  accepted.
*/

/// @title Deployer of contracts for the Serai network
/// @author Luke Parker <lukeparker@serai.exchange>
contract Deployer {
  /// @return The deployment for some (hashed) init code
  mapping(bytes32 => address) public deployments;

  /// @notice Raised if the provided init code was already prior deployed
  error PriorDeployed();
  /// @notice Raised if the deployment fails
  error DeploymentFailed();

  /// @notice Deploy the specified init code with `CREATE`
  /// @dev This init code is expected to be unique and not prior deployed
  /// @param initCode The init code to pass to `CREATE`
  function deploy(bytes memory initCode) external {
    // Deploy the contract
    address createdContract;
    // slither-disable-next-line assembly
    assembly {
      createdContract := create(0, add(initCode, 0x20), mload(initCode))
    }
    if (createdContract == address(0)) {
      revert DeploymentFailed();
    }

    bytes32 initCodeHash = keccak256(initCode);

    /*
      Check this wasn't prior deployed.

      This is a post-check, not a pre-check (in violation of the CEI pattern).
      If we used a pre-check, a deployed contract could re-enter the Deployer
      to deploy the same contract multiple times due to the inner call updating
      state and then the outer call overwriting it. The post-check causes the
      outer call to error once the inner call updates state.

      This does mean contract deployment may fail if deployment causes
      arbitrary execution which maliciously nests deployment of the
      being-deployed contract. Such an inner call won't fail, yet the outer
      call would. The usage of a re-entrancy guard would cause the inner call
      to fail while the outer call succeeds. This is considered so edge-case it
      isn't worth handling.
    */
    if (deployments[initCodeHash] != address(0)) {
      revert PriorDeployed();
    }

    // Write the deployment to storage
    deployments[initCodeHash] = createdContract;
  }
}
