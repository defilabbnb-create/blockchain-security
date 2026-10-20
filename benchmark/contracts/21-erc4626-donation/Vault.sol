pragma solidity 0.8.19;
contract Vault { uint256 public totalAssets; uint256 public totalSupply; function donate(uint256 amount) external { totalAssets += amount; totalSupply += amount; } }
