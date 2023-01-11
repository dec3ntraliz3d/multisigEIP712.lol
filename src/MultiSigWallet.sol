// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

// never forget the OG simple sig wallet: https://github.com/christianlundkvist/simple-multisig/blob/master/contracts/SimpleMultiSig.sol

import {MultiSigFactory} from "./MultiSigFactory.sol";
import {EIP712} from "./EIP712.sol";
import {IMultisigWallet} from "./interfaces/IMultisigWallet.sol";
import {SignatureDecoder} from "./SignatureDecoder.sol";

contract MultiSigWallet is EIP712, IMultisigWallet, SignatureDecoder {
    bytes32 private constant EXECUTE_HASH =
        keccak256("Execute(uint256 nonce,address to,uint256 value,bytes data)");
    MultiSigFactory public immutable multiSigFactory;

    mapping(address => bool) public isOwner;
    address[] public owners;
    uint256 public signaturesRequired;
    uint256 public nonce;
    string public name;

    modifier onlyOwner() {
        if (!isOwner[msg.sender]) {
            revert NOT_OWNER();
        }
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) {
            revert NOT_SELF();
        }
        _;
    }

    modifier onlyValidSignaturesRequired() {
        _;
        if (signaturesRequired == 0) {
            revert INVALID_SIGNATURES_REQUIRED();
        }
        if (owners.length < signaturesRequired) {
            revert NOT_ENOUGH_SIGNERS();
        }
    }
    modifier onlyFactory() {
        if (msg.sender != address(multiSigFactory)) {
            revert NOT_FACTORY();
        }
        _;
    }

    constructor(string memory _name, address _factory) payable EIP712(_name) {
        name = _name;
        multiSigFactory = MultiSigFactory(_factory);
    }

    function init(address[] calldata _owners, uint256 _signaturesRequired)
        public
        payable
        onlyFactory
        onlyValidSignaturesRequired
    {
        signaturesRequired = _signaturesRequired;

        // get a local reference of the length to save gas
        uint256 ownerLength = _owners.length;
        for (uint256 i = 0; i < ownerLength; ) {
            address owner = _owners[i];
            if (owner == address(0) || isOwner[owner]) {
                revert INVALID_OWNER();
            }
            isOwner[owner] = true;
            owners.push(owner);

            emit Owner(owner, true);
            unchecked {
                ++i;
            }
        }
    }

    function addSigner(address newSigner, uint256 newSignaturesRequired)
        public
        onlySelf
        onlyValidSignaturesRequired
    {
        if (newSigner == address(0) || isOwner[newSigner]) {
            revert INVALID_SIGNER();
        }

        isOwner[newSigner] = true;
        owners.push(newSigner);
        signaturesRequired = newSignaturesRequired;

        emit Owner(newSigner, true);
        multiSigFactory.emitOwners(
            address(this),
            owners,
            newSignaturesRequired
        );
    }

    function removeSigner(address oldSigner, uint256 newSignaturesRequired)
        public
        onlySelf
        onlyValidSignaturesRequired
    {
        if (!isOwner[oldSigner]) {
            revert NOT_OWNER();
        }

        _removeOwner(oldSigner);
        signaturesRequired = newSignaturesRequired;

        emit Owner(oldSigner, false);
        multiSigFactory.emitOwners(
            address(this),
            owners,
            newSignaturesRequired
        );
    }

    function _removeOwner(address _oldSigner) private {
        isOwner[_oldSigner] = false;
        uint256 ownersLength = owners.length;
        address lastElement = owners[ownersLength - 1];
        // check if the last element of the array is the owner t be removed
        if (lastElement == _oldSigner) {
            owners.pop();
            return;
        } else {
            // if not then iterate through the array and swap the owner to be removed with the last element in the array
            for (uint256 i = ownersLength - 2; i >= 0; ) {
                if (owners[i] == _oldSigner) {
                    address temp = owners[i];
                    owners[i] = lastElement;
                    lastElement = temp;
                    owners.pop();
                    return;
                }
                unchecked {
                    --i;
                }
            }
        }
    }

    function updateSignaturesRequired(uint256 newSignaturesRequired)
        public
        onlySelf
        onlyValidSignaturesRequired
    {
        signaturesRequired = newSignaturesRequired;
    }

    function executeBatch(Transaction[] calldata _transactions)
        public
        onlyOwner
        returns (bytes[] memory)
    {
        bytes[] memory results = new bytes[](_transactions.length);
        for (uint256 i = 0; i < _transactions.length; i++) {
            results[i] = executeTransaction(_transactions[i]);
        }
        return results;
    }

    function executeTransaction(Transaction calldata _transaction)
        public
        onlyOwner
        returns (bytes memory)
    {
        uint256 _nonce = nonce;
        bytes32 _hash = getTransactionHash(
            _nonce,
            _transaction.to,
            _transaction.value,
            _transaction.data
        );
        nonce++;

        uint256 validSignatures;
        address duplicateGuard;
        // get a local reference of the length to save gas
        uint256 _signatureLength = _transaction.signatures.length;
        for (uint256 i = 0; i < _signatureLength; ) {
            address recovered = recover(_hash, _transaction.signatures[i]);
            if (recovered <= duplicateGuard) {
                revert DUPLICATE_OR_UNORDERED_SIGNATURES();
            }
            duplicateGuard = recovered;

            if (isOwner[recovered]) {
                validSignatures++;
            }
            unchecked {
                ++i;
            }
        }

        if (validSignatures < signaturesRequired) {
            revert INSUFFICIENT_VALID_SIGNATURES();
        }

        (bool success, bytes memory result) = payable(_transaction.to).call{
            value: _transaction.value
        }(_transaction.data);
        if (!success) {
            revert TX_FAILED();
        }

        emit ExecuteTransaction(
            msg.sender,
            _transaction.to,
            _transaction.value,
            _transaction.data,
            _nonce,
            _hash,
            result
        );
        return result;
    }

    function getTransactionHash(
        uint256 _nonce,
        address _to,
        uint256 _value,
        bytes calldata _data
    ) public view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(abi.encode(EXECUTE_HASH, _nonce, _to, _value, _data))
            );
    }

    function recover(bytes32 _hash, bytes calldata _signature)
        public
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;
        (r, s, v) = splitSignature(_signature);
        return ecrecover(_hash, v, r, s);
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    function numberOfOwners() public view returns (uint256) {
        return owners.length;
    }
}
