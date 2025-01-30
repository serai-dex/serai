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

  uint256 public totalSupply;

  mapping(address => uint256) balances;
  mapping(address => mapping(address => uint256)) allowances;

  function balanceOf(address owner) public view returns (uint256) {
    return balances[owner];
  }

  function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;
    emit Transfer(msg.sender, to, value);
    return true;
  }

  function transferFrom(address from, address to, uint256 value) public returns (bool) {
    allowances[from][msg.sender] -= value;
    balances[from] -= value;
    balances[to] += value;
    emit Transfer(from, to, value);
    return true;
  }

  function approve(address spender, uint256 value) public returns (bool) {
    allowances[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

  function allowance(address owner, address spender) public view returns (uint256) {
    return allowances[owner][spender];
  }

  function mint(address owner, uint256 value) external {
    balances[owner] += value;
    totalSupply += value;
    emit Transfer(address(0), owner, value);
  }

  function magicApprove(address owner, address spender, uint256 value) external {
    allowances[owner][spender] = value;
    emit Approval(owner, spender, value);
  }
}
