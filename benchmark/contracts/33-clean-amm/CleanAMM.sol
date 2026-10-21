// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract CleanAMM {
    uint256 public reserve0;
    uint256 public reserve1;

    function seed(uint256 amount0, uint256 amount1) external {
        require(amount0 > 0 && amount1 > 0, "empty pool");
        reserve0 = amount0;
        reserve1 = amount1;
    }

    function swap(uint256 amount0Out, uint256 amount1Out) external {
        require(amount0Out < reserve0 && amount1Out < reserve1, "insufficient liquidity");
        uint256 oldK = reserve0 * reserve1;
        reserve0 -= amount0Out;
        reserve1 -= amount1Out;
        require(reserve0 * reserve1 >= oldK, "constant product decreased");
    }
}
