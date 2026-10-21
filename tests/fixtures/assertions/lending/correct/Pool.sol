// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalCash = 1000;
    uint256 public totalBorrows;
    uint256 public totalSupply;
    uint256 public healthFactor = type(uint256).max;

    function depositCollateral(uint256 amount) external { collateral[msg.sender] += amount; totalSupply += amount; }
    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        totalBorrows += amount;
        totalCash -= amount;
        healthFactor = collateral[msg.sender] * 1e18 / debt[msg.sender];
    }
    function accrue(uint256 interest) external { totalBorrows += interest; totalSupply += interest; totalCash += interest; }
}
