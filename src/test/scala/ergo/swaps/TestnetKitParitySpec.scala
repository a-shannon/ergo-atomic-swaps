package ergo.swaps

import org.ergoplatform._
import org.ergoplatform.validation.ValidationRules
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import scorex.crypto.hash.{Blake2b256, Sha256}
import scorex.util.encode.Base16
import sigma.Extensions.ArrayOps
import sigma.ast._
import sigma.crypto.CryptoConstants
import sigma.data.{AvlTreeData, CGroupElement}
import sigma.interpreter.{ContextExtension, ProverResult}
import sigma.serialization.{ErgoTreeSerializer, ValueSerializer}
import sigma.{Colls, Header, VersionContext}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.eval.CPreHeader

import java.nio.file.{Files, Paths}
import scala.sys.process._

/**
  * Node.js <-> Scala `sigma-state 6.0.3` Differential Parity & 1-Click Spend Verification Spec
  * for `docs/ergo-testnet-kit.js` v1.1.0!
  */
class TestnetKitParitySpec extends AnyFlatSpec with Matchers {

  private def preHeader(h: Int): CPreHeader =
    CPreHeader(
      version = 3.toByte,
      parentId = Blake2b256.hash(s"HDR_$h".getBytes("UTF-8")).toColl,
      timestamp = 1765400000000L + h.toLong * 120_000L,
      nBits = 19857408L,
      height = h,
      minerPk = CGroupElement(CryptoConstants.dlogGroup.generator),
      votes = Array[Byte](0, 0, 0).toColl
    )

  private def verifyJsSpend(
      box: ErgoBox,
      outputsSpec: Seq[(Long, String)],
      extMap: Map[Byte, EvaluatedValue[_ <: SType]],
      height: Int,
      signer: DLogProverInput
  ): Long = VersionContext.withVersions(VersionContext.V6SoftForkVersion, VersionContext.V6SoftForkVersion) {
    val ext = ContextExtension(extMap)
    val outs = outputsSpec.map { case (v, hexTree) =>
      val ot = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(Base16.decode(hexTree).get)
      new ErgoBoxCandidate(v, ot, height, Colls.emptyColl, Map.empty)
    }.toIndexedSeq
    val utx = new UnsignedErgoLikeTransaction(IndexedSeq(new UnsignedInput(box.id, ext)), IndexedSeq.empty, outs)
    def ctxFor(tx: ErgoLikeTransactionTemplate[_ <: UnsignedInput]) =
      new ErgoLikeContext(
        AvlTreeData.dummy, Colls.emptyColl[Header], preHeader(height),
        IndexedSeq.empty, IndexedSeq(box), tx, 0, ext,
        ValidationRules.currentSettings, 1_000_000L, 0L, VersionContext.V6SoftForkVersion
      )
    val prover   = new SigmaPropProver(Seq(signer))
    val verifier = new SigmaPropVerifier() { override type CTX = ErgoLikeContext }
    val pres     = prover.prove(box.ergoTree, ctxFor(utx), utx.messageToSign).get
    val pr       = ProverResult(pres.proof, ext)
    val stx      = utx.toSigned(IndexedSeq(pr))
    val (ok, cost) = verifier.verify(box.ergoTree, ctxFor(stx), pr, stx.messageToSign).get
    ok shouldBe true
    cost
  }

  "ergo-testnet-kit.js v1.1.0" should "match Scala Testnet P2S addresses AND verify JS-built PTLC Refund & HTLC Claim/Refund on Scala SigmaPropVerifier 6.0.3" in {
    val kitPath = Paths.get("docs", "ergo-testnet-kit.js").toAbsolutePath
    assume(Files.exists(kitPath), s"Skipping Node.js parity test: $kitPath not present")

    val (ptlcTree, ptlcBytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.ScriptlessAdaptorSwapScript)
    val (htlcTree, htlcBytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.CrossChainHashSwapScript)
    val expPtlc = AtomicSwapContracts.p2sAddress(ptlcTree, mainnet = false)
    val expHtlc = AtomicSwapContracts.p2sAddress(htlcTree, mainnet = false)

    val claimantSec = DLogProverInput.random()
    val makerSec    = DLogProverInput.random()
    val adaptorSec  = DLogProverInput.random()
    val claimantPk  = Base16.encode(CGroupElement(claimantSec.publicImage.value).getEncoded.toArray)
    val makerPk     = Base16.encode(CGroupElement(makerSec.publicImage.value).getEncoded.toArray)
    val adaptorPt   = Base16.encode(CGroupElement(adaptorSec.publicImage.value).getEncoded.toArray)
    val encTest     = ErgoAddressEncoder(ErgoAddressEncoder.TestnetNetworkPrefix)
    val claimantAddr = P2PKAddress(claimantSec.publicImage)(encTest).toString
    val makerAddr    = P2PKAddress(makerSec.publicImage)(encTest).toString
    val preimage     = Blake2b256.hash("ERGO_HTLC_32B_PREIMAGE_TEST_2026".getBytes("UTF-8"))
    val secretHash   = Sha256.hash(preimage)
    val payHash      = Blake2b256.hash(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(P2PKAddress(claimantSec.publicImage)(encTest).script))
    val refundH      = 666600

    val jsCode =
      s"""const kit = require(process.argv[1]);
         |const ptlcBox = {
         |  boxId: '${"33" * 32}', transactionId: '${"33" * 32}', index: 0,
         |  ergoTree: '${Base16.encode(ptlcBytes)}', creationHeight: 666500, value: '100000000', assets: [],
         |  additionalRegisters: {
         |    R4: kit.Sigma.encodeGroupElement('$adaptorPt'),
         |    R5: kit.Sigma.encodeGroupElement('$claimantPk'),
         |    R6: kit.Sigma.encodeGroupElement('$makerPk'),
         |    R7: kit.Sigma.encodeLong(${refundH}n)
         |  }
         |};
         |const htlcBox = {
         |  boxId: '${"44" * 32}', transactionId: '${"44" * 32}', index: 0,
         |  ergoTree: '${Base16.encode(htlcBytes)}', creationHeight: 666500, value: '100000000', assets: [],
         |  additionalRegisters: {
         |    R4: kit.Sigma.encodeByteArray('${Base16.encode(secretHash)}'),
         |    R5: kit.Sigma.encodeGroupElement('$claimantPk'),
         |    R6: kit.Sigma.encodeGroupElement('$makerPk'),
         |    R7: kit.Sigma.encodeLongArray([${refundH}n, 5000000n]),
         |    R8: kit.Sigma.encodeByteArray('${Base16.encode(payHash)}')
         |  }
         |};
         |const ptlcRef = kit.buildEip12PtlcRefundTx({ swapBox: ptlcBox, recipientAddress: '$makerAddr', creationHeight: ${refundH + 1} });
         |const htlcClm = kit.buildEip12HtlcSpendTx({ swapBox: htlcBox, action: 'claim', preimage: '${Base16.encode(preimage)}', recipientAddress: '$claimantAddr', creationHeight: ${refundH - 5} });
         |const htlcRef = kit.buildEip12HtlcSpendTx({ swapBox: htlcBox, action: 'refund', recipientAddress: '$makerAddr', creationHeight: ${refundH + 1} });
         |console.log(JSON.stringify({
         |  ptlc: kit.encodeP2S('${Base16.encode(ptlcBytes)}', 'testnet'),
         |  htlc: kit.encodeP2S('${Base16.encode(htlcBytes)}', 'testnet'),
         |  prOut0Val: ptlcRef.outputs[0].value, prOut0Tree: ptlcRef.outputs[0].ergoTree,
         |  prFeeVal: ptlcRef.outputs[1].value, prFeeTree: ptlcRef.outputs[1].ergoTree,
         |  hcExt0: htlcClm.inputs[0].extension['0'], hcExt1: htlcClm.inputs[0].extension['1'],
         |  hcOut0Val: htlcClm.outputs[0].value, hcOut0Tree: htlcClm.outputs[0].ergoTree,
         |  hrOut0Val: htlcRef.outputs[0].value, hrOut0Tree: htlcRef.outputs[0].ergoTree
         |}));""".stripMargin

    val stdout = Seq("node", "-e", jsCode, kitPath.toString).!!.trim
    def field(k: String): String = s""""$k":"([^"]+)"""".r.findFirstMatchIn(stdout).get.group(1)

    field("ptlc") shouldBe expPtlc
    field("htlc") shouldBe expHtlc

    val ptlcBox = new ErgoBox(
      100_000_000L, ptlcTree, Colls.emptyColl,
      Map(
        ErgoBox.R4 -> GroupElementConstant(adaptorSec.publicImage.value),
        ErgoBox.R5 -> GroupElementConstant(claimantSec.publicImage.value),
        ErgoBox.R6 -> GroupElementConstant(makerSec.publicImage.value),
        ErgoBox.R7 -> LongConstant(refundH.toLong)
      ),
      scorex.util.ModifierId @@ ("33" * 32), 0.toShort, 666500
    )
    val cPr = verifyJsSpend(
      ptlcBox,
      Seq((field("prOut0Val").toLong, field("prOut0Tree")), (field("prFeeVal").toLong, field("prFeeTree"))),
      Map.empty, refundH + 1, makerSec
    )

    val htlcBox = new ErgoBox(
      100_000_000L, htlcTree, Colls.emptyColl,
      Map(
        ErgoBox.R4 -> ByteArrayConstant(secretHash),
        ErgoBox.R5 -> GroupElementConstant(claimantSec.publicImage.value),
        ErgoBox.R6 -> GroupElementConstant(makerSec.publicImage.value),
        ErgoBox.R7 -> LongArrayConstant(Array(refundH.toLong, 5_000_000L)),
        ErgoBox.R8 -> ByteArrayConstant(payHash)
      ),
      scorex.util.ModifierId @@ ("44" * 32), 0.toShort, 666500
    )
    val cHc = verifyJsSpend(
      htlcBox,
      Seq((field("hcOut0Val").toLong, field("hcOut0Tree")), (field("prFeeVal").toLong, field("prFeeTree"))),
      Map(
        0.toByte -> ValueSerializer.deserialize(Base16.decode(field("hcExt0")).get).asInstanceOf[EvaluatedValue[_ <: SType]],
        1.toByte -> ValueSerializer.deserialize(Base16.decode(field("hcExt1")).get).asInstanceOf[EvaluatedValue[_ <: SType]]
      ),
      refundH - 5, claimantSec
    )
    val cHr = verifyJsSpend(
      htlcBox,
      Seq((field("hrOut0Val").toLong, field("hrOut0Tree")), (field("prFeeVal").toLong, field("prFeeTree"))),
      Map.empty, refundH + 1, makerSec
    )
    println(s"[TestnetKitParity] PTLC (83 B) & HTLC (255 B) P2S + JS-built Spend txs PASSED Scala SigmaPropVerifier 6.0.3! (PtlcRefund=$cPr, HtlcClaim=$cHc, HtlcRefund=$cHr)")
  }
}
