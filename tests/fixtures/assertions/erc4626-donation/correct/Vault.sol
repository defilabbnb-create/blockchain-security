// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;

    function deposit(uint256 assets) external {
        totalAssets += assets;
        totalSupply += assets;
    }

    function donate(uint256 assets) external {
        totalAssets += assets;
    }
}
