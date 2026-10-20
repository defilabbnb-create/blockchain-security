// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// Test: ZKBridge attack
contract ZKBridgeAttacker {
    address target = 0x730470e11675c34B31101011375a595711B11417;
    
    function attack() public {
        // Attack logic
    }
}

// Test: FlashBorrow attack
contract FlashBorrowAttacker {
    address target = 0x2c85223671b31E1c1c129275c5e4337B211501c6;
    
    function attack() public {
        // Attack logic
    }
}
