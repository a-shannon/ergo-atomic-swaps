# Architecture & Cryptographic Design — Ergo Atomic Swaps

## 1. `ScriptlessAdaptorSwap` (`83 B`) — Live Schnorr Adaptor PTLC

```scala
val adaptorClaim =
  sigmaProp(HEIGHT < refundHeight && adaptorPointT != identityPt && adaptorPointT != groupGenerator) &&
  proveDlog(claimantPk) &&
  proveDlog(adaptorPointT)
```

### End-to-End Cross-Chain Extraction (`AdaptorCrypto.scala`)
1. **Setup:** Bob picks secret `t ∈ Z_n` and publishes `T = t · G`. Bob locks ERG in `ScriptlessAdaptorSwap` with `R4 = T`, `R5 = alicePk`, `R6 = bobPk`, `R7 = refundHeight`.
2. **Pre-Signature:** On Bitcoin/Taproot (same `secp256k1` group!), Bob sends Alice `(R', R = R' + T, s' = k + e·x_B mod n)` where `e = SHA256(R || P_B || msg) mod n`. Alice verifies `s'·G == R' + e·P_B`.
3. **Adaptation:** When Bob claims BTC, he must publish `s = (s' + t) mod n` so `s·G == (R' + T) + e·P_B == R + e·P_B`.
4. **Extraction & Zero-Hash Ergo Unlock:** Alice computes `t = (s - s') mod n` and supplies `Seq(aliceSec, DLogProverInput(t))` to Ergo's native Sigma prover (`88 B` proof, `983` BlockCost = `0.10%`).
5. **Multi-Hop Unlinkability:** A routing intermediary transforms `T_2 = T_1 + delta · G`. Observers watching both hops see unrelated elliptic-curve points `T_1 != T_2`, eliminating HTLC hash-correlation surveillance!

---

## 2. `CrossChainHashSwap` (`255 B`) — Hardened eUTXO HTLC + Gasless Submarine Relayer

- **Strict 32-Byte Preimage:** Enforces `preimage.size == 32 && sha256(preimage) == secretHash`.
- **Two Claim Paths:**
  - `mode == 0L`: Direct `proveDlog(claimantPk)` sweep — immune to mempool preimage front-running.
  - `mode == 1L`: **Gasless Submarine Relayer Sweep** (0 claimant signature!) allowing a relayer to finalize a Lightning/BTC swap for an onboarding Ergo user with zero ERG for gas, strictly enforcing `OUTPUTS(0).value >= SELF.value - maxRelayerFee`, `OUTPUTS(0).tokens == SELF.tokens`, `claimantPayHash`, and `OUTPUTS(0).R4 == SELF.id` (blocks double-satisfaction when two HTLCs share the same `secretHash`!).
- **Timeout Refund (`mode == 2L`, default when `var 0` omitted):** `HEIGHT >= refundHeight && proveDlog(makerPk)`.
