pragma solidity 0.8.19;
contract Vault { uint256 public totalAssets = 1000; uint256 public totalSupply = 333; function convertToShares(uint256 assets) external view returns (uint256) { return (assets * totalSupply + totalAssets - 1) / totalAssets; } }
