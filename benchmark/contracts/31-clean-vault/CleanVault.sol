// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract CleanVault {
    mapping(address => uint256) public shares;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        require(assets > 0, "zero deposit");
        shares[msg.sender] += assets;
        totalAssets += assets;
    }

    function withdraw(uint256 assets) external {
        require(assets > 0 && shares[msg.sender] >= assets, "insufficient shares");
        shares[msg.sender] -= assets;
        totalAssets -= assets;
    }

    function totalSupply() external view returns (uint256) {
        return totalAssets;
    }
}
