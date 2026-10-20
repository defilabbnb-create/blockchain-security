pragma solidity 0.8.19;
contract Pool { mapping(address => uint256) public debt; uint256 public badDebt; function liquidate(address user, uint256 repay) external { debt[user] -= repay; badDebt += debt[user]; } }
