// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// never forget the OG simple sig wallet: https://github.com/christianlundkvist/simple-multisig/blob/master/contracts/SimpleMultiSig.sol

// pragma experimental ABIEncoderV2;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./MultiSigFactory.sol";
import {EIP712} from "./EIP712.sol";
import {IMultisigWallet} from "./interfaces/IMultisigWallet.sol";
import {SignatureDecoder} from "./SignatureDecoder.sol";

contract MultiSigWallet is EIP712, IMultisigWallet, SignatureDecoder {
    using ECDSA for bytes32;
    bytes32 public constant EXECUTE_HASH =
        keccak256("Execute(uint256 nonce,address to,uint256 value,bytes data)");

    MultiSigFactory private immutable multiSigFactory;

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

    function executeBatch(
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data,
        bytes[][] calldata signatures
    ) public onlyOwner returns (bytes[] memory) {
        uint256 toLength = to.length;
        bytes[] memory results = new bytes[](toLength);
        for (uint256 i = 0; i < toLength; i++) {
            results[i] = executeTransaction(
                payable(to[i]),
                value[i],
                data[i],
                signatures[i]
            );
        }
        return results;
    }

    function executeTransaction(
        address payable to,
        uint256 value,
        bytes calldata data,
        bytes[] calldata signatures
    ) public onlyOwner returns (bytes memory) {
        uint256 _nonce = nonce;
        bytes32 _hash = getTransactionHash(_nonce, to, value, data);

        nonce = _nonce + 1;

        uint256 validSignatures;
        address duplicateGuard;
        // get a local reference of the length to save gas
        uint256 signatureLength = signatures.length;
        for (uint256 i = 0; i < signatureLength; ) {
            address recovered = recover(_hash, signatures[i]);
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

        (bool success, bytes memory result) = to.call{value: value}(data);
        if (!success) {
            revert TX_FAILED();
        }

        emit ExecuteTransaction(
            msg.sender,
            to,
            value,
            data,
            _nonce,
            _hash,
            result
        );
        return result;
    }

    function getTransactionHash(
        uint256 _nonce,
        address to,
        uint256 value,
        bytes calldata data
    ) public view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(abi.encode(EXECUTE_HASH, nonce, to, value, data))
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
