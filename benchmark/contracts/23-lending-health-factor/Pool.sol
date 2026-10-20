pragma solidity 0.8.19;
contract Pool { mapping(address => uint256) public debt; mapping(address => uint256) public collateral; function borrow(uint256 amount) external { debt[msg.sender] += amount; } function healthFactor(address user) external view returns (uint256) { return collateral[user] / (debt[user] + 1); } }
