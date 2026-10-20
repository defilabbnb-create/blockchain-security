pragma solidity >=0.8.19;

contract SmokeTest {
    function testInvariantSmoke() public pure {
        require(1 + 1 == 2, "fixture");
    }
}
