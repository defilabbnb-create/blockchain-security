pragma solidity 0.8.19;
contract Oracle { uint256 public price; uint256 public updatedAt; function setPrice(uint256 next) external { price = next; } function read() external view returns (uint256) { return price; } }
