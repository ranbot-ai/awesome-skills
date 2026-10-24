---
name: defi-protocol-templates
description: Implement DeFi protocols with educational templates for staking, AMMs, governance, and lending systems. Use when building decentralized finance applications or smart contract protocols. 
category: Document Processing
source: antigravity
tags: [api, ai, template, design, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/defi-protocol-templates
---

## Supporting material availability

This catalog copy contains the inline guidance below, but does not include the following supporting paths. They are external prerequisites, not bundled files:

- `<support-root>/references/staking.md`
- `<support-root>/references/liquidity-pools.md`
- `<support-root>/references/governance-tokens.md`
- `<support-root>/references/lending-protocols.md`
- `<support-root>/references/flash-loans.md`
- `<support-root>/assets/staking-contract.sol`
- `<support-root>/assets/amm-contract.sol`
- `<support-root>/assets/governance-token.sol`
- `<support-root>/assets/lending-protocol.sol`

Ask for the original supporting material or an existing installation before using a step that depends on these paths; this catalog does not identify a verified download source for them. Resolve each path relative to that installation, inspect its contents, and verify any applicable license and execution prerequisites. Do not run a command or claim a referenced procedure was followed until its required file exists. Do not fabricate the missing scripts or treat an unrelated file with the same name as equivalent. Independent steps fully documented here can proceed within the user’s authorized scope; report any dependent step as unavailable.


# DeFi Protocol Templates

Educational examples for common DeFi protocols including staking, AMMs, governance, lending, and flash loans.

## Do not use this skill when

- The task is unrelated to defi protocol templates
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

## Use this skill when

- Building staking platforms with reward distribution
- Implementing AMM (Automated Market Maker) protocols
- Creating governance token systems
- Developing lending/borrowing protocols
- Integrating flash loan functionality
- Launching yield farming platforms

These inline contracts are incomplete teaching examples, not audited/funded protocols. They use OpenZeppelin4.x import/inheritance APIs; pin a reviewed compatible version rather than installing5.x blindly. Never deploy with user funds. Staking’s fixed unbounded reward rate has no funding/period management; AMM lacks production-grade reserve/oracle/LP safeguards; governor has no quorum/timelock/action payload; flash loans require a receiver-specific trusted callback. Compile, property/fuzz-test accounting/reentrancy/rounding and obtain independent review before designing a deployment. Token units/decimals differ and fee-on-transfer/rebasing tokens are unsupported.

## Staking Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract StakingRewards is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;
    IERC20 public stakingToken;
    IERC20 public rewardsToken;
    uint256 public rewardRate = 100; // Rewards per second
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public balances;
    uint256 private _totalSupply;
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    constructor(address _stakingToken, address _rewardsToken) {
        stakingToken = IERC20(_stakingToken);
        rewardsToken = IERC20(_rewardsToken);
    }
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }
    function rewardPerToken() public view returns (uint256) {
        if (_totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored +
            ((block.timestamp - lastUpdateTime) * rewardRate * 1e18) / _totalSupply;
    }
    function earned(address account) public view returns (uint256) {
        return (balances[account] *
            (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18 +
            rewards[account];
    }
    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");
        _totalSupply += amount;
        balances[msg.sender] += amount;
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }
    function withdraw(uint256 amount) public nonReent
