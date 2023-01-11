// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {MultiSigWallet} from "../src/MultiSigWallet.sol";
import {MultiSigFactory} from "../src/MultiSigFactory.sol";
import {IMultisigWallet} from "../src/interfaces/IMultisigWallet.sol";

contract MultiSigWalletTest is Test, IMultisigWallet {
    bytes[][] batchSignatures;
    bytes32 private constant EXECUTE_HASH =
        keccak256("Execute(uint256 nonce,address to,uint256 value,bytes data)");
    uint256[] signersPrivKeys;
    address[] signers;
    MultiSigFactory multiSigFactory;
    MultiSigWallet multiSigWallet;

    function setUp() public {
        multiSigFactory = new MultiSigFactory();
        // Create couple of signers
        for (uint8 i = 1; i <= 2; i++) {
            signersPrivKeys.push(i);
            signers.push(vm.addr(i));
        }
        address multiSigAddress = multiSigFactory.create2(
            signers,
            1,
            "Wallet1"
        );
        multiSigWallet = MultiSigWallet(payable(multiSigAddress));
    }

    function testVerifyMultiSigOwners() public {
        for (uint8 i = 0; i < signers.length; i++) {
            assertTrue(multiSigWallet.isOwner(signers[i]));
        }
    }

    function testAddSigner() public {
        uint256 _nonce = multiSigWallet.nonce();
        address _newSigner = vm.addr(3);
        bytes memory _data = abi.encodeWithSignature(
            "addSigner(address,uint256)",
            _newSigner,
            2
        );
        bytes32 _hash = _getTransactionHash(
            _nonce,
            address(multiSigWallet),
            0,
            _data
        );
        uint256 _signaturesRequired = multiSigWallet.signaturesRequired();
        bytes[] memory _signatures = new bytes[](_signaturesRequired);
        for (uint8 i = 0; i < _signaturesRequired; i++) {
            _signatures[i] = _getSignature(signersPrivKeys[i], _hash);
        }

        vm.prank(signers[0]);
        multiSigWallet.executeTransaction(
            Transaction(address(multiSigWallet), 0, _data, _signatures)
        );

        assertTrue(multiSigWallet.isOwner(_newSigner));
        assertEq(multiSigWallet.signaturesRequired(), 2);
    }

    function testRemoveSigner() public {
        uint256 _nonce = multiSigWallet.nonce();
        // remove one signer and change signature required to 1
        bytes memory _data = abi.encodeWithSignature(
            "removeSigner(address,uint256)",
            signers[0],
            1
        );
        bytes32 _hash = _getTransactionHash(
            _nonce,
            address(multiSigWallet),
            0,
            _data
        );
        uint256 _signaturesRequired = multiSigWallet.signaturesRequired();
        bytes[] memory _signatures = new bytes[](_signaturesRequired);
        for (uint8 i = 0; i < _signaturesRequired; i++) {
            _signatures[i] = _getSignature(signersPrivKeys[i], _hash);
        }

        vm.prank(signers[0]);
        multiSigWallet.executeTransaction(
            Transaction(address(multiSigWallet), 0, _data, _signatures)
        );
        assertFalse(multiSigWallet.isOwner(signers[0]));
        assertEq(multiSigWallet.signaturesRequired(), 1);
    }

    function testExecuteTransaction() public {
        address _receiver = vm.addr(100);
        Transaction memory _transaction;
        // Fund multisig wallet with 1 ether
        vm.deal(address(multiSigWallet), 1 ether);

        bytes memory _data = "";
        uint256 _nonce = multiSigWallet.nonce();
        bytes32 _hash = _getTransactionHash(
            _nonce,
            _receiver,
            0.1 ether,
            _data // Empty data
        );

        uint256 _signaturesRequired = multiSigWallet.signaturesRequired();
        bytes[] memory _signatures = new bytes[](_signaturesRequired);
        for (uint8 i = 0; i < _signaturesRequired; i++) {
            _signatures[i] = _getSignature(signersPrivKeys[i], _hash);
        }

        vm.prank(signers[0]);
        multiSigWallet.executeTransaction(
            Transaction(_receiver, 0.1 ether, _data, _signatures)
        );

        // multiSigWallet.executeTransaction(
        //     payable(_receiver),
        //     0.1 ether,
        //     _data,
        //     _signatures
        // );

        assertEq(_receiver.balance, 0.1 ether);
    }

    function testExecuteTransactionBatch() public {
        Transaction[] memory _transactions = new Transaction[](3);
        bytes32[] memory _hashes = new bytes32[](3);
        uint256 _nonce = multiSigWallet.nonce();

        for (uint8 i = 0; i < _transactions.length; i++) {
            _transactions[i].to = vm.addr(i + 100);
            _transactions[i].value = 0.1 ether;
            // Get hashes
            _hashes[i] = _getTransactionHash(
                _nonce,
                _transactions[i].to,
                _transactions[i].value,
                _transactions[i].data
            );
            _nonce++;
        }

        uint256 _signaturesRequired = multiSigWallet.signaturesRequired();
        for (uint256 i = 0; i < _transactions.length; i++) {
            bytes[] memory _signatures = new bytes[](_signaturesRequired);
            for (uint256 j = 0; j < _signaturesRequired; j++) {
                _signatures[j] = _getSignature(signersPrivKeys[j], _hashes[i]);
            }
            _transactions[i].signatures = _signatures;
        }
        vm.deal(address(multiSigWallet), 1 ether);
        vm.prank(signers[0]);
        multiSigWallet.executeBatch(_transactions);

        for (uint8 i = 0; i < _transactions.length; i++) {
            assertEq(_transactions[i].to.balance, 0.1 ether);
        }
    }

    function testUpdateSignaturesRequired() public {
        uint256 _nonce = multiSigWallet.nonce();
        bytes memory _data = abi.encodeWithSignature(
            "updateSignaturesRequired(uint256)",
            2
        );
        bytes32 _hash = _getTransactionHash(
            _nonce,
            address(multiSigWallet),
            0,
            _data
        );
        uint256 _signaturesRequired = multiSigWallet.signaturesRequired();
        bytes[] memory _signatures = new bytes[](_signaturesRequired);
        for (uint8 i = 0; i < _signaturesRequired; i++) {
            _signatures[i] = _getSignature(signersPrivKeys[i], _hash);
        }

        vm.prank(signers[0]);
        multiSigWallet.executeTransaction(
            Transaction(address(multiSigWallet), 0, _data, _signatures)
        );

        assertEq(multiSigWallet.signaturesRequired(), 2);
    }

    function testNumberOfOwners() public {
        assertEq(multiSigWallet.numberOfOwners(), 2);
    }

    // function _getTransactionHash(
    //     uint256 _nonce,
    //     address to,
    //     uint256 value,
    //     bytes memory data
    // ) private view returns (bytes32) {
    //     return
    //         _hashTypedData(
    //             keccak256(abi.encode(EXECUTE_HASH, _nonce, to, value, data))
    //         );
    // }

    function _getTransactionHash(
        uint256 _nonce,
        address _to,
        uint256 _value,
        bytes memory _data
    ) public view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(abi.encode(EXECUTE_HASH, _nonce, _to, _value, _data))
            );
    }

    function _getSignature(uint256 _privateKey, bytes32 _hash)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, _hash);
        return bytes.concat(r, s, bytes1(v));
    }

    function _hashTypedData(bytes32 dataHash) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    multiSigWallet.DOMAIN_SEPARATOR(),
                    dataHash
                )
            );
    }
}
