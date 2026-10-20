pragma solidity 0.8.19;
contract Pool { uint256 public reserve0 = 1000; uint256 public reserve1 = 1000; function swap(uint256 input, uint256 output) external { reserve0 += input; reserve1 -= output + 1; } }
