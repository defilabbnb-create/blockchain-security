pragma solidity 0.8.19;
contract Vault { mapping(address => uint256) public balances; function withdraw(uint256 amount) external { require(balances[msg.sender] >= amount); (bool ok,) = msg.sender.call{value: amount}(""); require(ok); balances[msg.sender] -= amount; } }
