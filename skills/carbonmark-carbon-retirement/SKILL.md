---
name: carbonmark-carbon-retirement
description: Price and retire verified carbon credits on Base through Carbonmark's x402 API. Use when a user asks to offset emissions or buy and retire carbon credits. 
category: Document Processing
source: antigravity
tags: [api, ai, agent, llm, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/carbonmark-carbon-retirement
---


# Carbonmark Carbon Retirement

## Overview

Retire tokenized carbon credits on Base mainnet through Carbonmark's x402 Carbon Retirement API (`https://x402.klimalabs.com`), and return the public certificate that proves the retirement.

The skill covers the whole task: list what can be retired and at what price, quote an amount, prepare the retirement for the user's wallet to sign, and fetch the certificate afterwards. Listing, quoting and certificates are free and need no API key or account. A retirement is paid in USDC on Base and is permanent.

No other skill in this catalog covers carbon credits. Use a general payments or wallet skill for the signing step; this skill supplies what to sign and how to check the result.

## When to Use

- The user asks to offset emissions, "retire carbon", "buy carbon credits and retire them", or to compensate a footprint given in tonnes or kilograms of CO2.
- The user asks what carbon credits cost right now, or for a quote.
- The user has a retirement transaction hash and wants the certificate.

Do not use it to estimate a footprint (it does not calculate emissions), to trade or hold credits (it only retires them), or on any chain other than Base mainnet.

## Prerequisites

- Network access to `https://x402.klimalabs.com`. Every call sends only the parameters shown below.
- For a quote or a certificate: nothing else.
- For a retirement: a wallet on Base mainnet (chain ID 8453) that the user controls and that holds USDC, plus a tool that can either send transactions from it or sign EIP-712 typed data with it. This skill never asks for, reads or stores a private key or seed phrase.
- A beneficiary name chosen by the user. It is printed on the public certificate and cannot be changed afterwards.

## How It Works

Base URL: `https://x402.klimalabs.com/api`. All amounts are decimal tonnes: `0.001` is one kilogram.

### 1. Establish the inputs

Ask for anything missing; do not guess:

- **Amount** in tonnes.
- **Beneficiary name** for the certificate, and optionally a public message.
- **Wallet address** that will pay (only needed to prepare a retirement).
- **Who the retirement is credited to**, if not the paying wallet: another address.

Then list the supply:

```bash
curl -s "https://x402.klimalabs.com/api/discover"
```

- `carbonClasses[]` is pooled supply. Each has `carbonClassId`, `name`, `priceUsdcPerTonneFormatted` and `minRetirementTonnesFormatted` (`0.001` for most, `1` for classes that retire in whole tonnes only).
- `marketplaceListings[]` are individual listings at a fixed price. Each has `listingId`, `projectName`, `priceUsdcPerTonneFormatted`, `leftToSellFormatted` (tonnes still available) and `minFillFormatted`. Skip a listing with less left than the amount wanted.

Add `?maxUsdcPricePerTonne=15` to keep only supply at or under 15 USDC per tonne. Do not send `chainId` to `discover`; it rejects it.

Take identifiers only from this response. A made-up `carbonClass` answers `404 no_candidates`. Show the user the options and let them choose, unless they asked for the cheapest.

The prices in `discover` are indicative. A class can cost more per tonne for a large amount, and the fee differs between classes and listings, so "cheapest" means the lowest quoted total for the amount wanted: quote the two or three lowest-priced classes and the two or three lowest-priced listings, and compare.

### 2. Perform the task

**Quote** (free). Identify the supply with exactly one of `carbonClass` (a `carbonClassId`) or `listingId`:

```bash
curl -s "https://x402.klimalabs.com/api/quote?chainId=8453&inputToken=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&amount=0.001&carbonClass=0x0008f35758a4318942ecb5d5414116ce7b1ede2d"
```

`inputToken` is USDC on Base. Read these fields:

| Field | Meaning |
|---|---|
| `pricePerTonneFormatted` | price per tonne for this amount |
| `retirementPriceFormatted` | price of the whole amount, before the fee |
| `feeFormatted` | the service fee |
| `totalFormatted` | expected total when the wallet sends the transactions itself (path A) |
| `relayTotalFormatted` | expected total when a relayer sends them (path B); it adds the relayer's gas and can be several times `totalFormatted` for a small amount |
| `suggestedMaxInputFormatted` | the most that can be spent on path A if the price moves (`slippageBps`, 4% at the time of writing) |

In `humanSummary` the figure after `@` is the price of the whole amount, not the price per tonne.

**Stop and confirm.** Before preparing anything, show the user:

- the class or project, and the amount;
- the expected total in USDC for the path you will use (`totalFormatted` on path A, `relayTotalFormatted` on path B), the exact maximum authorized spend, and any separate wallet network fees;
- the beneficiary name, and the message if there is one, which are public and permanent;
- that a retirement cannot be undone or refunded.

Continue only on an explicit yes in the current conversation. A request for a quote is not permis
