# Ergo Atomic Swaps — Cross-Chain SHA-256 HTLC & Scriptless Adaptor PTLC (Sigma v6)

[![CI](https://github.com/a-shannon/ergo-atomic-swaps/actions/workflows/ci.yml/badge.svg)](https://github.com/a-shannon/ergo-atomic-swaps/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Live Interactive Lab:** [https://a-shannon.github.io/ergo-atomic-swaps/](https://a-shannon.github.io/ergo-atomic-swaps/)

Trustless cross-chain swap primitives on **Ergo Sigma v6 (`treeVersion = 3`)** featuring both hardened Bitcoin/Lightning/EVM-compatible SHA-256 HTLCs and **Zero-Hash Scriptless Adaptor-Signature PTLCs (`83 B` ErgoTree!)** that break on-chain cross-chain hash linkability.

Both reference contracts are verified **100% byte-for-byte** against the official Ergo v6 reference node (`ergo-6.0.3.jar`), and the live web app connects directly to **Ergo Testnet** (`api-testnet.ergoplatform.com` / local node) + **Nautilus EIP-12** using `docs/ergo-testnet-kit.js` (proven byte-for-byte against Scala `sigma-state 6.0.3` in `TestnetKitParitySpec`).

---

## Live Ergo Testnet + Nautilus EIP-12 Support

Open [the live lab](https://a-shannon.github.io/ergo-atomic-swaps/) to:
- Fetch live Ergo Testnet block height and watch real unspent PTLC (`83 B`) and HTLC (`255 B`) boxes at both verified Testnet P2S addresses (a live 83 B PTLC demo box is visible in the watcher!).
- Connect **Nautilus** (hard-guarded to Testnet only) for **1-click Lock, PTLC Refund, HTLC Claim, and HTLC Timeout Refund** — or export offline EIP-12 JSON without any wallet installed (all 1-click spend builders are verified against Scala `SigmaPropVerifier 6.0.3` in `TestnetKitParitySpec`).

### Verified Live On-Chain Ergo Testnet Execution (`ergo-6.0.8`)

| Contract | Live On-Chain Action | Proof / Cost | Ergo Testnet Explorer |
| :--- | :--- | :---: | :--- |
| **`ScriptlessAdaptorSwap` (`83 B`)** | Lock `0.10 tERG` (`T = t·G`, zero hashlock!) + live watcher box | `56 B` / `403` | [`8a74c5a6…`](https://testnet.ergoplatform.com/en/transactions/8a74c5a687da22ae6a7b95303f7fc442c402255ccee89c0432c508c736ec7a22) |
| **`ScriptlessAdaptorSwap` (`83 B`)** | **Zero-Hash Adaptor Claim (`proveDlog(claimant) && proveDlog(T)`)** | `88 B` / `983` | [`2ed59f71…`](https://testnet.ergoplatform.com/en/transactions/2ed59f711f488603cb6d79ca041954c7207317d8ad764f9ea8c901c1628e1e37) |
| **`CrossChainHashSwap` (`255 B`)** | **0-Sig Gasless Submarine Relayer (`mode=1L`, `R4=SELF.id`)** | **`0 B`** / `172` | [`cb9ae260…`](https://testnet.ergoplatform.com/en/transactions/cb9ae260e79a913d1d9099b59f878b243bd6704f6508390b554cfd7ed002cd2d) |

---

## Why Scriptless Adaptor Swaps Matter (Plain English)

Classic atomic swaps lock Bitcoin and Ergo with the **exact same `SHA-256(preimage)` hash**, allowing any chain-analysis bot to instantly correlate both legs of the swap.

With **`ScriptlessAdaptorSwap` (`83 B`)**:
1. Instead of a hashlock, the swap locks to an elliptic-curve point **`T = t · G`** (an Adaptor Point).
2. On Bitcoin (Taproot Schnorr), Bob completes his adaptor pre-signature `s' = k + e·x_B` into a valid on-chain signature `s = s' + t (mod n)`.
3. Alice observes `(R, s)` on Bitcoin, computes **`t = (s - s') mod n`** in one subtraction, and spends Ergo's `proveDlog(claimantPk) && proveDlog(T)` box!
4. **Zero `SHA-256` hash ever touches Ergo** — and multi-hop submarine relays re-randomize `T_2 = T_1 + delta · G` so hops are cryptographically unlinkable!

---

## Contracts & Measured Benchmarks (`sigma-state 6.0.3` / `ergo-6.0.3.jar`)

| Contract | Action | ErgoTree Size | Measured Execution Cost (1M Block Limit) |
| :--- | :--- | :---: | :--- |
| **`CrossChainHashSwap`** | Direct Signed Claim (`sha256` 32B preimage) | **255 B** | **520** (`0.05%`, `56 B` proof) |
| **`CrossChainHashSwap`** | Gasless Submarine Relayer Sweep (`SELF.tokens` + `SELF.id`) | **255 B** | **175** (`0.02%`, **0 B proof / 0 sigs!**) |
| **`CrossChainHashSwap`** | Maker Timeout Refund (0 context vars) | **255 B** | **509** (`0.05%`) |
| **`ScriptlessAdaptorSwap`** | **Zero-Hash PTLC Claim (Live Schnorr Extraction `t = s - s'`)** | **83 B** | **983** (`0.10%`, `88 B` proof) |
| **`ScriptlessAdaptorSwap`** | Unlinkable Hop-2 Re-Randomized PTLC (`T2 = T1 + delta·G`) | **83 B** | **983** (`0.10%`) |

---

## Quick Start

```bash
sbt "test" "run demo"
sbt "run node-parity http://127.0.0.1:9052"
```

See [DESIGN.md](DESIGN.md) for the complete Schnorr adaptor extraction math and eUTXO HTLC hardening invariants.

---

## Scope & Disclaimer

Open-source MIT reference implementation, executable `sigma-state 6.0.3` test suite, and educational browser simulator — not externally audited or deployed with live mainnet funds.
