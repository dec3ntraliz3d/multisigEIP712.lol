// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IMultisigWallet {
    //custom errors
    error DUPLICATE_OR_UNORDERED_SIGNATURES();
    error INVALID_OWNER();
    error INVALID_SIGNER();
    error INVALID_SIGNATURES_REQUIRED();
    error INSUFFICIENT_VALID_SIGNATURES();
    error NOT_ENOUGH_SIGNERS();
    error NOT_OWNER();
    error NOT_SELF();
    error NOT_FACTORY();
    error TX_FAILED();

    event Deposit(address indexed sender, uint256 amount, uint256 balance);
    event ExecuteTransaction(
        address indexed owner,
        address payable to,
        uint256 value,
        bytes data,
        uint256 nonce,
        bytes32 hash,
        bytes result
    );
    event Owner(address indexed owner, bool added);

    struct UpdateSigner {
        address signer;
        uint256 newSignaturesRequired;
    }
}
