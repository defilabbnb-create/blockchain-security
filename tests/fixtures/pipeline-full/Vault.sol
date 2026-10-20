pragma solidity 0.8.19;

contract Vault {
    uint256 public totalAssets;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        totalAssets += amount;
        totalSupply += amount;
    }

    function withdraw(uint256 amount) external {
        require(totalAssets >= amount, "insufficient");
        totalAssets -= amount;
        totalSupply -= amount;
    }
}
