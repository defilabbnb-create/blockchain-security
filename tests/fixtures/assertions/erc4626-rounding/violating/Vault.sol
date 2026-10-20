// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 public totalAssets = 1000;
    uint256 public totalSupply = 333;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * totalSupply + totalAssets - 1) / totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * totalAssets + totalSupply - 1) / totalSupply;
    }
}
