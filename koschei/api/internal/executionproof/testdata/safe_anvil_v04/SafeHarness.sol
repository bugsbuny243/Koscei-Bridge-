// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeHarnessV04 {
    address internal singleton;
    address[] private ownerList;
    uint256 private thresholdValue;
    uint256 public nonce;

    constructor(address owner) payable {
        require(owner != address(0), "owner");
        ownerList.push(owner);
        thresholdValue = 1;
    }

    function getOwners() external view returns (address[] memory) {
        return ownerList;
    }

    function getThreshold() external view returns (uint256) {
        return thresholdValue;
    }

    function getModulesPaginated(address, uint256) external pure returns (address[] memory array, address next) {
        array = new address[](0);
        next = address(0x1);
    }

    function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
        assembly ("memory-safe") {
            let internalCalldata := add(calldataPayload, 0x20)
            let internalCalldataSize := mload(calldataPayload)
            let success := delegatecall(gas(), targetContract, internalCalldata, internalCalldataSize, 0, 0)
            let responseSize := returndatasize()
            mstore(0x00, success)
            mstore(0x20, responseSize)
            returndatacopy(0x40, 0, responseSize)
            revert(0, add(responseSize, 0x40))
        }
    }

    receive() external payable {}
}

contract SimulateTxAccessorV04 {
    function simulate(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bytes memory response) {
        require(operation == 0, "operation");
        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "call");
        return result;
    }
}

contract NativeSinkV04 {
    receive() external payable {}
}
