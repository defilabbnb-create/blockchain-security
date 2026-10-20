// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pool {
    uint256 public reserve0 = 1000;
    uint256 public reserve1 = 1000;

    function swap(uint256 amount0In, uint256 amount1Out) external {
        reserve0 += amount0In;
        reserve1 -= amount1Out + 1;
    }

    function invariantK() external view returns (uint256) { return reserve0 * reserve1; }
}
