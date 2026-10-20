// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public badDebt;

    function seed(address account, uint256 collateralAmount, uint256 debtAmount) external {
        collateral[account] = collateralAmount;
        debt[account] = debtAmount;
    }

    function liquidate(address account, uint256 repay) external {
        uint256 paid = repay > debt[account] ? debt[account] : repay;
        debt[account] -= paid;
        uint256 seized = paid > collateral[account] ? collateral[account] : paid;
        collateral[account] -= seized;
    }
}
