---
name: web3-testing
description: Test smart contracts comprehensively using Hardhat and Foundry with unit tests, integration tests, and mainnet forking. Use when testing Solidity contracts, setting up blockchain test suites, or valid
category: Development & Code Tools
source: antigravity
tags: [javascript, node, api, ai, workflow, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/web3-testing
---


# Web3 Smart Contract Testing

Master comprehensive testing strategies for smart contracts using Hardhat, Foundry, and advanced testing patterns.

## Do not use this skill when

- The task is unrelated to web3 smart contract testing
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Writing unit tests for smart contracts
- Setting up integration test suites
- Performing gas optimization testing
- Fuzzing for edge cases
- Forking mainnet for realistic testing
- Automating test coverage reporting
- Verifying contracts on Etherscan

## Hardhat Testing Setup

```javascript
// hardhat.config.js
require("@nomicfoundation/hardhat-toolbox");
require("@nomiclabs/hardhat-etherscan");
require("hardhat-gas-reporter");
require("solidity-coverage");

module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      forking: {
        url: process.env.MAINNET_RPC_URL,
        blockNumber: 15000000,
      },
    },
    goerli: {
      url: process.env.GOERLI_RPC_URL,
      accounts: [process.env.PRIVATE_KEY],
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY,
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
};
```

## Unit Testing Patterns

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  loadFixture,
  time,
} = require("@nomicfoundation/hardhat-network-helpers");

describe("Token Contract", function () {
  // Fixture for test setup
  async function deployTokenFixture() {
    const [owner, addr1, addr2] = await ethers.getSigners();

    const Token = await ethers.getContractFactory("Token");
    const token = await Token.deploy();

    return { token, owner, addr1, addr2 };
  }

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      const { token, owner } = await loadFixture(deployTokenFixture);
      expect(await token.owner()).to.equal(owner.address);
    });

    it("Should assign total supply to owner", async function () {
      const { token, owner } = await loadFixture(deployTokenFixture);
      const ownerBalance = await token.balanceOf(owner.address);
      expect(await token.totalSupply()).to.equal(ownerBalance);
    });
  });

  describe("Transactions", function () {
    it("Should transfer tokens between accounts", async function () {
      const { token, owner, addr1 } = await loadFixture(deployTokenFixture);

      await expect(token.transfer(addr1.address, 50)).to.changeTokenBalances(
        token,
        [owner, addr1],
        [-50, 50],
      );
    });

    it("Should fail if sender doesn't have enough tokens", async function () {
      const { token, addr1 } = await loadFixture(deployTokenFixture);
      const initialBalance = await token.balanceOf(addr1.address);

      await expect(
        token.connect(addr1).transfer(owner.address, 1),
      ).to.be.revertedWith("Insufficient balance");
    });

    it("Should emit Transfer event", async function () {
      const { token, owner, addr1 } = await loadFixture(deployTokenFixture);

      await expect(token.transfer(addr1.address, 50))
        .to.emit(token, "Transfer")
        .withArgs(owner.address, addr1.address, 50);
    });
  });

  describe("Time-based tests", function () {
    it("Should handle time-locked operations", async function () {
      const { token } = await loadFixture(deployTokenFixture);

      // Increase time by 1 day
      await time.increase(86400);

      // Test time-dependent functionality
    });
  });

  describe("Gas optimization", function () {
    it("Should use gas efficiently", async function () {
      const { token } = await loadFixture(deployTokenFixture);

      const tx = await token.transfer(addr1.address, 100);
      const receipt = await tx.wait();

      expect(receipt.gasUsed).to.be.lessThan(50000);
    });
  });
});
```

## Foundry Testing (Forge)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenTest is Test {
    Token token;
    address owner = address(1);
    address user1 = address(2);
    address user2 = address(3);

    function setUp() public {
        vm.prank(owner);
        token = new Token();
    }

    function testInitialSupply() public {
        assertEq(token.totalSupply(), 1000000 * 10**18);
    }

    function testTransfer() public {
        vm.prank(owner);
        token.transfer(user1, 100);

        assertEq(token.balanceOf(user1), 100);
        assertEq(token.balanceOf(owner), token.totalSupply() - 100);
    
