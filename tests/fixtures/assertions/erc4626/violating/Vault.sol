// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0 || totalAssets == 0) return assets;
        return assets * totalSupply / totalAssets;
    }

    function deposit(uint256 assets) external returns (uint256 minted) {
        minted = convertToShares(assets);
        if (minted == 0) minted = assets;
        totalAssets += assets;
        totalSupply += minted;
        shares[msg.sender] += minted;
    }

    function withdraw(uint256 assets) external returns (uint256 burned) {
        burned = convertToShares(assets);
        require(shares[msg.sender] >= burned, "insufficient shares");
        shares[msg.sender] -= burned;
        totalSupply -= burned;
        totalAssets -= assets + 1;
    }
}
