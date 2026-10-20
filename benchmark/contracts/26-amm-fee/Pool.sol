pragma solidity 0.8.19;
contract Pool { uint256 public fee; function swap(uint256 amount) external { fee = amount; } function withdrawFees() external { fee = 0; } }
