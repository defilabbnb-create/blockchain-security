pragma solidity 0.8.19;
contract Proxy { address public implementation; function setImplementation(address next) external { implementation = next; } function forward(bytes calldata data) external { (bool ok,) = implementation.delegatecall(data); require(ok); } }
