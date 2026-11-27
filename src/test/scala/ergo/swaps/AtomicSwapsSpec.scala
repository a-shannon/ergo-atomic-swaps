package ergo.swaps

import org.ergoplatform.ErgoBox.{R4, R5, R6, R7, R8, TokenId}
import org.ergoplatform._
import org.ergoplatform.validation.ValidationRules
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import scorex.crypto.hash.{Blake2b256, Sha256}
import scorex.util.{ModifierId, bytesToId}
import sigma.Extensions.ArrayOps
import sigma.{Colls, Header, VersionContext}
import sigma.ast._
import sigma.crypto.CryptoConstants
import sigma.data.{AvlTreeData, CGroupElement, Digest32Coll, SigmaLeaf}
import sigma.interpreter.{ContextExtension, ProverResult}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.crypto.SigmaProtocolPrivateInput
import sigmastate.eval.CPreHeader

import java.math.BigInteger
import scala.util.{Failure, Success, Try}

class AtomicSwapsSpec extends AnyFlatSpec with Matchers {

  private val CostLimit: Long       = 1_000_000L
  private val OneErg: Long          = 1_000_000_000L
  private val DummyTxId: ModifierId = bytesToId(Blake2b256.hash("SWAPS_DUMMY_TX".getBytes("UTF-8")))
  private val SwapToken: Array[Byte] = Blake2b256.hash("SIGUSD_DEMO_TOKEN_V1".getBytes("UTF-8"))

  private def tok(id: Array[Byte], amt: Long): (TokenId, Long) = (Digest32Coll @@ id.toColl, amt)

  private def preHeader(h: Int): CPreHeader =
    CPreHeader(
      version = 3.toByte,
      parentId = Blake2b256.hash(AdaptorCrypto.be64(h.toLong)).toColl,
      timestamp = 1764800000000L + h.toLong * 120_000L,
      nBits = 19857408L,
      height = h,
      minerPk = CGroupElement(CryptoConstants.dlogGroup.generator),
      votes = Array[Byte](0, 0, 0).toColl
    )

  private def p2pkTree(dlog: DLogProverInput): ErgoTree =
    ErgoTree.fromProposition(
      ErgoTree.defaultHeaderWithVersion(VersionContext.V6SoftForkVersion),
      dlog.publicImage
    )

  private def verifySpend(
      inputBox: ErgoBox,
      outputs: IndexedSeq[ErgoBoxCandidate],
      height: Int,
      ext: ContextExtension = ContextExtension.empty,
      secrets: Seq[SigmaProtocolPrivateInput[_ <: SigmaLeaf]] = Seq.empty
  ): Try[(Boolean, Long, Int)] = Try {
    VersionContext.withVersions(VersionContext.V6SoftForkVersion, VersionContext.V6SoftForkVersion) {
      val utx = new UnsignedErgoLikeTransaction(
        IndexedSeq(new UnsignedInput(inputBox.id, ext)),
        IndexedSeq.empty,
        outputs
      )
      def ctxFor(tx: ErgoLikeTransactionTemplate[_ <: UnsignedInput]) =
        new ErgoLikeContext(
          AvlTreeData.dummy,
          Colls.emptyColl[Header],
          preHeader(height),
          IndexedSeq.empty,
          IndexedSeq(inputBox),
          tx,
          0,
          ext,
          ValidationRules.currentSettings,
          CostLimit,
          0L,
          VersionContext.V6SoftForkVersion
        )
      val prover     = new SigmaPropProver(secrets)
      val verifier   = new SigmaPropVerifier() { override type CTX = ErgoLikeContext }
      val pres       = prover.prove(inputBox.ergoTree, ctxFor(utx), utx.messageToSign).get
      val pr         = ProverResult(pres.proof, ext)
      val stx        = utx.toSigned(IndexedSeq(pr))
      val (ok, cost) = verifier.verify(inputBox.ergoTree, ctxFor(stx), pr, stx.messageToSign).get
      (ok, cost, pres.proof.length)
    }
  }

  private def assertRejected(res: Try[(Boolean, Long, Int)], label: String): Unit = res match {
    case Success((true, cost, _)) => fail(s"SECURITY FAILURE [$label]: unexpectedly verified true (cost=$cost)")
    case Success((false, _, _))   => ()
    case Failure(_)               => ()
  }

  // =================================================================================================
  // SUITE 1: CrossChainHashSwap — Hardened SHA-256 HTLC + Gasless Submarine Relayer Sweep
  // =================================================================================================
  "CrossChainHashSwap (Hardened SHA-256 HTLC + Gasless Relayer)" should
    "support direct signed claim, gasless submarine relayer claim with token preservation & SELF.id receipt, maker refund, and reject wrong preimage / token skim / early refund" in {
      println("\n=== 1. CROSS-CHAIN HASH SWAP (SHA-256 HTLC + Gasless Submarine Relayer) ===")
      val (tree, bytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.CrossChainHashSwapScript)
      bytes.length should be < 4096

      val claimantSec  = DLogProverInput.random()
      val makerSec     = DLogProverInput.random()
      val claimantTree = p2pkTree(claimantSec)
      val claimantHash = Blake2b256.hash(claimantTree.bytes)
      val makerTree    = p2pkTree(makerSec)

      val preimage     = Sha256.hash("BTC_LN_INVOICE_PREIMAGE_SECRET_42".getBytes("UTF-8"))
      val secretHash   = Sha256.hash(preimage)
      val h0           = 2_900_000
      val refundHeight = h0 + 720L
      val maxRelayFee  = 5_000_000L

      val swapBox = new ErgoBox(
        25L * OneErg,
        tree,
        Colls.fromItems(tok(SwapToken, 500_00L)), // 500.00 SigUSD + 25 ERG
        Map(
          R4 -> ByteArrayConstant(secretHash),
          R5 -> GroupElementConstant(claimantSec.publicImage.value),
          R6 -> GroupElementConstant(makerSec.publicImage.value),
          R7 -> LongArrayConstant(Array(refundHeight, maxRelayFee)),
          R8 -> ByteArrayConstant(claimantHash)
        ),
        DummyTxId, 0.toShort, h0
      )

      // 1) Direct Signed Claim (mode == 0L)
      val directOut = new ErgoBoxCandidate(swapBox.value - 1_000_000L, claimantTree, h0 + 10, swapBox.additionalTokens)
      val extDirect = ContextExtension(Map(0.toByte -> LongConstant(0L), 1.toByte -> ByteArrayConstant(preimage)))
      val (okDir, costDir, pfDir) = verifySpend(swapBox, IndexedSeq(directOut), h0 + 10, extDirect, Seq(claimantSec)).get
      okDir shouldBe true
      println(f"[CrossChainHTLC Direct Claim]       ErgoTree=${bytes.length}%4d B | Proof=${pfDir}%2d B | BlockCost=$costDir%4d (${costDir / 10000.0}%.2f%% of 1M)")

      // 2) Gasless Submarine-Swap Relayer Sweep (mode == 1L, ZERO claimant signature!)
      val relayOut = new ErgoBoxCandidate(
        swapBox.value - maxRelayFee, claimantTree, h0 + 10, swapBox.additionalTokens,
        Map(R4 -> ByteArrayConstant(swapBox.id))
      )
      val relayerFeeOut = new ErgoBoxCandidate(maxRelayFee, p2pkTree(DLogProverInput.random()), h0 + 10)
      val extRelay = ContextExtension(Map(0.toByte -> LongConstant(1L), 1.toByte -> ByteArrayConstant(preimage)))
      val (okRel, costRel, pfRel) = verifySpend(swapBox, IndexedSeq(relayOut, relayerFeeOut), h0 + 10, extRelay).get
      okRel shouldBe true
      pfRel shouldBe 0
      println(f"[CrossChainHTLC Gasless Relayer]    Proof=${pfRel}%2d B (0-sig!) | BlockCost=$costRel%4d (${costRel / 10000.0}%.2f%% of 1M)")

      // NEGATIVE 1: Wrong preimage -> REJECTED!
      val badPre = Sha256.hash("WRONG_SECRET".getBytes("UTF-8"))
      assertRejected(verifySpend(swapBox, IndexedSeq(directOut), h0 + 10, ContextExtension(Map(0.toByte -> LongConstant(0L), 1.toByte -> ByteArrayConstant(badPre))), Seq(claimantSec)), "Wrong preimage")

      // NEGATIVE 2: Relayer skims 1 token unit or 1 nanoERG over maxRelayerFee -> REJECTED!
      val skimTokOut = new ErgoBoxCandidate(swapBox.value - maxRelayFee, claimantTree, h0 + 10, Colls.fromItems(tok(SwapToken, 499_99L)), Map(R4 -> ByteArrayConstant(swapBox.id)))
      assertRejected(verifySpend(swapBox, IndexedSeq(skimTokOut, relayerFeeOut), h0 + 10, extRelay), "Relayer token skim")

      val skimErgOut = new ErgoBoxCandidate(swapBox.value - maxRelayFee - 1L, claimantTree, h0 + 10, swapBox.additionalTokens, Map(R4 -> ByteArrayConstant(swapBox.id)))
      assertRejected(verifySpend(swapBox, IndexedSeq(skimErgOut, relayerFeeOut), h0 + 10, extRelay), "Relayer 1-nanoERG skim")

      // NEGATIVE 3: Relayer omits SELF.id receipt (double-satisfaction vector) -> REJECTED!
      val noIdOut = new ErgoBoxCandidate(swapBox.value - maxRelayFee, claimantTree, h0 + 10, swapBox.additionalTokens)
      assertRejected(verifySpend(swapBox, IndexedSeq(noIdOut, relayerFeeOut), h0 + 10, extRelay), "Missing SELF.id receipt on gasless relay")

      // NEGATIVE 4: Maker early refund before refundHeight -> REJECTED!
      val makerOut = new ErgoBoxCandidate(swapBox.value - 1_000_000L, makerTree, h0 + 10, swapBox.additionalTokens)
      assertRejected(verifySpend(swapBox, IndexedSeq(makerOut), h0 + 10, secrets = Seq(makerSec)), "Maker early refund")

      // 3) Maker Timeout Refund (0 context vars!)
      val makerRefOut = new ErgoBoxCandidate(swapBox.value - 1_000_000L, makerTree, refundHeight.toInt, swapBox.additionalTokens)
      val (okRef, costRef, _) = verifySpend(swapBox, IndexedSeq(makerRefOut), refundHeight.toInt, secrets = Seq(makerSec)).get
      okRef shouldBe true
      println(f"[CrossChainHTLC Maker Refund]       0 vars | BlockCost=$costRef%4d (${costRef / 10000.0}%.2f%% of 1M)")
    }

  // =================================================================================================
  // SUITE 2: ScriptlessAdaptorSwap — Live Bitcoin Schnorr Adaptor Extraction -> Zero-Hash Ergo Unlock!
  // =================================================================================================
  "ScriptlessAdaptorSwap (Zero-Hash PTLC via Live Schnorr Adaptor Extraction)" should
    "extract secret scalar t from a completed counterparty Schnorr signature, unlock Ergo with zero hash, prove unlinkable 2-hop rerandomization, and block unauthorized claims" in {
      println("\n=== 2. SCRIPTLESS ADAPTOR SWAP (Zero-Hash PTLC + Live Schnorr Extraction) ===")
      val (tree, bytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.ScriptlessAdaptorSwapScript)
      bytes.length should be < 4096

      val aliceSec = DLogProverInput.random() // Ergo claimant (receives ERG after extracting t from Bob's BTC sig)
      val bobSec   = DLogProverInput.random() // Ergo maker & BTC counterparty
      val h0       = 2_950_000
      val refH     = h0 + 720L

      // Step 1: Bob chooses secret adaptor scalar `t` and publishes point `T = t * G`
      val tSecret = new BigInteger("73918264501928374650192837465019283746501928374650")
      val tPoint  = AdaptorCrypto.point(tSecret)

      // Step 2: Bob locks 100 ERG on Ergo in ScriptlessAdaptorSwap (NO SHA-256 HASH ANYWHERE!)
      val ptlcBox = new ErgoBox(
        100L * OneErg,
        tree,
        Colls.emptyColl,
        Map(
          R4 -> GroupElementConstant(CGroupElement(tPoint)),
          R5 -> GroupElementConstant(aliceSec.publicImage.value),
          R6 -> GroupElementConstant(bobSec.publicImage.value),
          R7 -> LongConstant(refH)
        ),
        DummyTxId, 0.toShort, h0
      )

      // Step 3: On Bitcoin (counterparty chain), Bob sends Alice a Schnorr Adaptor Pre-Signature `(R', s')`
      val btcTxMsg = Sha256.hash("BITCOIN_TAPROOT_SPEND_TX_OUTPUT_ALICE_0.05BTC".getBytes("UTF-8"))
      val bobBtcSec = new BigInteger("555511112222333344445555666677778888999900001111")
      val bobBtcPk  = AdaptorCrypto.point(bobBtcSec)
      val nonceK    = new BigInteger("314159265358979323846264338327950288419716939937")
      val preSig    = AdaptorCrypto.preSign(bobBtcSec, nonceK, tPoint, btcTxMsg)
      AdaptorCrypto.verifyPreSig(bobBtcPk, tPoint, btcTxMsg, preSig) shouldBe true

      // NEGATIVE 1: Before Bob completes the BTC signature, Alice CANNOT spend the Ergo PTLC with only her own key!
      val aliceOut = new ErgoBoxCandidate(ptlcBox.value - 1_000_000L, p2pkTree(aliceSec), h0 + 5)
      assertRejected(verifySpend(ptlcBox, IndexedSeq(aliceOut), h0 + 5, secrets = Seq(aliceSec)), "Claimant alone without adaptor scalar t")

      // Step 4: Bob claims BTC by publishing the adapted Schnorr signature `s = s' + t (mod n)`
      val completedBtcSig = AdaptorCrypto.adapt(preSig, tSecret)
      AdaptorCrypto.verifySchnorr(bobBtcPk, btcTxMsg, completedBtcSig) shouldBe true

      // Step 5: Alice watches Bitcoin, extracts `t_extracted = (s - s') mod n`, and unlocks Ergo with ZERO hash!
      val extractedT = AdaptorCrypto.extractSecret(preSig, completedBtcSig)
      extractedT shouldBe tSecret

      val (okPtlc, costPtlc, pfPtlc) = verifySpend(
        ptlcBox,
        IndexedSeq(aliceOut),
        h0 + 5,
        secrets = Seq(aliceSec, DLogProverInput(extractedT))
      ).get
      okPtlc shouldBe true
      println(f"[ScriptlessAdaptorSwap Zero-Hash]   ErgoTree=${bytes.length}%4d B | Proof=${pfPtlc}%2d B | BlockCost=$costPtlc%4d (${costPtlc / 10000.0}%.2f%% of 1M)")

      // Step 6: Multi-Hop Unlinkability — Hop 2 re-randomizes T2 = T1 + delta * G (T2 != T1 on-chain!)
      val hopDelta  = new BigInteger("888877776666555544443333222211110000999988887777")
      val t2Point   = AdaptorCrypto.rerandomizePoint(tPoint, hopDelta)
      t2Point should not equal tPoint
      val hop2Sec   = AdaptorCrypto.rerandomizeSecret(extractedT, hopDelta)
      val hop2Box = new ErgoBox(
        100L * OneErg, tree, Colls.emptyColl,
        Map(R4 -> GroupElementConstant(CGroupElement(t2Point)), R5 -> GroupElementConstant(aliceSec.publicImage.value), R6 -> GroupElementConstant(bobSec.publicImage.value), R7 -> LongConstant(refH)),
        DummyTxId, 1.toShort, h0
      )
      val (okHop2, costHop2, _) = verifySpend(hop2Box, IndexedSeq(aliceOut), h0 + 6, secrets = Seq(aliceSec, DLogProverInput(hop2Sec))).get
      okHop2 shouldBe true
      println(f"[ScriptlessAdaptorSwap Hop-2 Unlink] T2 != T1 | BlockCost=$costHop2%4d (${costHop2 / 10000.0}%.2f%% of 1M)")

      // NEGATIVE 2: Wrong adaptor secret cannot spend Hop 2 -> REJECTED!
      assertRejected(verifySpend(hop2Box, IndexedSeq(aliceOut), h0 + 6, secrets = Seq(aliceSec, DLogProverInput(extractedT))), "Hop-1 secret cannot unlock re-randomized Hop-2")

      // Step 7: Maker Timeout Refund after refH
      val bobRefOut = new ErgoBoxCandidate(ptlcBox.value - 1_000_000L, p2pkTree(bobSec), refH.toInt)
      verifySpend(ptlcBox, IndexedSeq(bobRefOut), refH.toInt, secrets = Seq(bobSec)).get._1 shouldBe true
    }
}
