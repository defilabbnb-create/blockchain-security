pragma solidity 0.8.19;
contract Router { function callTarget(address target, bytes calldata data) external { (bool ok,) = target.call(data); require(ok); } }
