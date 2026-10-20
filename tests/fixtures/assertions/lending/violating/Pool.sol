// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalCash;

    function depositCollateral(uint256 amount) external { collateral[msg.sender] += amount; }
    function borrow(uint256 amount) external { totalCash -= amount; }
    function healthFactor(address account) external view returns (uint256) {
        if (debt[account] == 0) return type(uint256).max;
        return collateral[account] * 1e18 / debt[account];
    }
    function accrue(uint256 interest) external { totalCash += interest * 2; }
}
