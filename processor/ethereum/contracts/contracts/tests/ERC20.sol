// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

contract TestERC20 {
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  function name() public pure returns (string memory) {
    return "Test ERC20";
  }

  function symbol() public pure returns (string memory) {
    return "TEST";
  }

  function decimals() public pure returns (uint8) {
    return 18;
  }

  function totalSupply() public pure returns (uint256) {
    return 1_000_000 * 10e18;
  }

  mapping(address => uint256) balances;
  mapping(address => mapping(address => uint256)) allowances;

  constructor() {
    balances[msg.sender] = totalSupply();
  }

  function balanceOf(address owner) public view returns (uint256) {
    return balances[owner];
  }

  function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;
    return true;
  }

  function transferFrom(address from, address to, uint256 value) public returns (bool) {
    allowances[from][msg.sender] -= value;
    balances[from] -= value;
    balances[to] += value;
    return true;
  }

  function approve(address spender, uint256 value) public returns (bool) {
    allowances[msg.sender][spender] = value;
    return true;
  }

  function allowance(address owner, address spender) public view returns (uint256) {
    return allowances[owner][spender];
  }
}
