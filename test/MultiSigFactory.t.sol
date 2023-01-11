// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {MultiSigWallet} from "../src/MultiSigWallet.sol";
import {MultiSigFactory} from "../src/MultiSigFactory.sol";

contract MultiSigFactoryTest is Test {
    address user1 = vm.addr(0x1);
    address user2 = vm.addr(0x2);
    MultiSigFactory multiSigFactory;

    function setUp() public {
        multiSigFactory = new MultiSigFactory();
    }

    function testCreate2DeployMultisigWallet() public {
        address[] memory _owners = new address[](1);
        _owners[0] = user1;
        multiSigFactory.create2(_owners, 1, "Wallet1");
        assertEq(multiSigFactory.numberOfMultiSigs(), 1);
    }

    function testCreate2DeployMultipleMultisigWallet() public {
        address[] memory _owners = new address[](1);
        _owners[0] = user1;
        multiSigFactory.create2(_owners, 1, "Wallet1");
        multiSigFactory.create2(_owners, 1, "Wallet2");
        assertEq(multiSigFactory.numberOfMultiSigs(), 2);
    }

    function testCreate2DeployFailDuplicateName() public {
        address[] memory _owners = new address[](1);
        _owners[0] = user1;
        multiSigFactory.create2(_owners, 1, "Wallet1");
        vm.expectRevert("Create2: Failed on deploy");
        // This will revert because same name "Wallet1" was used for the multisig.
        multiSigFactory.create2(_owners, 1, "Wallet1");
        assertEq(multiSigFactory.numberOfMultiSigs(), 1);
    }

    function testCreate2DeployFromSeperateEOAAddresses() public {
        address[] memory _owners1 = new address[](1);
        _owners1[0] = user1;
        address[] memory _owners2 = new address[](1);
        _owners2[0] = user2;
        vm.prank(user1);
        multiSigFactory.create2(_owners1, 1, "Wallet1");
        vm.prank(user2);
        multiSigFactory.create2(_owners2, 1, "Wallet1");
        assertEq(multiSigFactory.numberOfMultiSigs(), 2);
    }

    function testCreate2ComputeMultisigAddress() public {
        address[] memory _owners = new address[](1);
        _owners[0] = user1;
        address preComputedAddress = multiSigFactory.computedAddress("Wallet1");
        multiSigFactory.create2(_owners, 1, "Wallet1");
        // Check if the multisig was deployed to precomputed address.
        assertTrue(MultiSigWallet(payable(preComputedAddress)).isOwner(user1));
    }
}
