// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract CleanLending {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function depositCollateral(uint256 amount) external {
        require(amount > 0, "zero collateral");
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        require(amount > 0 && collateral[msg.sender] >= debt[msg.sender] + amount, "under-collateralized");
        debt[msg.sender] += amount;
    }

    function repay(uint256 amount) external {
        require(amount <= debt[msg.sender], "over-repay");
        debt[msg.sender] -= amount;
    }

    function healthFactor(address account) external view returns (uint256) {
        if (debt[account] == 0) return type(uint256).max;
        return collateral[account] * 1e18 / debt[account];
    }
}
