package ergo.swaps

import org.ergoplatform.ErgoAddressEncoder
import sigma.VersionContext
import sigma.ast.ErgoTree
import sigma.ast.syntax._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.serialization.ErgoTreeSerializer
import sigmastate.interpreter.Interpreter.ScriptEnv

/**
  * Trustless Cross-Chain Atomic Swaps & Scriptless Adaptor-Signature PTLCs on Ergo Sigma v6 (`treeVersion = 3`).
  *
  * Two plain-purpose reference contracts:
  *   1. `CrossChainHashSwapScript`:
  *        Bitcoin / Lightning / EVM-compatible SHA-256 HTLC hardened for eUTXO:
  *        - Strict 32-byte preimage length check (`sha256(preimage) == secretHash`).
  *        - Direct claimant sweep (`proveDlog(claimantPk)`) OR gasless submarine-swap relayer sweep
  *          enforcing `OUTPUTS(0).value >= SELF.value - maxRelayerFee`, exact `SELF.tokens` forwarding,
  *          `claimantPayHash`, and `OUTPUTS(0).R4 == SELF.id` (anti-double-satisfaction!).
  *        - Maker timeout refund (`HEIGHT >= refundHeight && proveDlog(makerPk)`) requiring 0 context vars.
  *   2. `ScriptlessAdaptorSwapScript`:
  *        Zero-hash Point-Time-Locked Contract (PTLC) powered natively by Ergo's Sigma conjunction
  *        `proveDlog(claimantPk) && proveDlog(adaptorPointT)`.
  *        - Unlocks when the claimant extracts `t = (s - s') mod n` from a counterparty Bitcoin/Taproot
  *          Schnorr adaptor signature — ZERO hashlock ever touches the Ergo blockchain!
  *        - Supports multi-hop point re-randomization (`T_2 = T_1 + delta * G`) for unlinkable routing.
  */
object AtomicSwapContracts {

  def compileV6(source: String, env: ScriptEnv = Map.empty): (ErgoTree, Array[Byte]) = this.synchronized {
    VersionContext.withVersions(VersionContext.V6SoftForkVersion, VersionContext.V6SoftForkVersion) {
      implicit val IR: CompiletimeIRContext = new CompiletimeIRContext
      val compiler = SigmaCompiler(ErgoAddressEncoder.MainnetNetworkPrefix)
      val compiled = compiler.compile(env, source)
      val prop     = compiled.buildTree.asSigmaProp
      val header   = ErgoTree.headerWithVersion(ErgoTree.ConstantSegregationHeader, VersionContext.V6SoftForkVersion)
      val tree     = ErgoTree.fromProposition(header, prop)
      val bytes    = ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(tree)
      (tree, bytes)
    }
  }

  def p2sAddress(tree: ErgoTree, mainnet: Boolean): String = {
    val prefix = if (mainnet) ErgoAddressEncoder.MainnetNetworkPrefix else ErgoAddressEncoder.TestnetNetworkPrefix
    ErgoAddressEncoder(prefix).fromProposition(tree).get.toString
  }

  // =================================================================================================
  // 1. CROSS-CHAIN HASH SWAP (Hardened SHA-256 HTLC + Gasless Submarine-Swap Relayer Mode)
  // =================================================================================================
  val CrossChainHashSwapScript: String =
    """{
      |  // R4: Coll[Byte] — 32-byte SHA-256 hashlock (BTC / Lightning / EVM compatible)
      |  // R5: GroupElement — `claimantPk`
      |  // R6: GroupElement — `makerPk`
      |  // R7: Coll(refundHeight, maxRelayerFee)
      |  // R8: Coll[Byte] — `claimantPayHash` = blake2b256(claimantPropBytes) for gasless submarine relayers
      |  val secretHash      = SELF.R4[Coll[Byte]].get
      |  val claimantPk      = SELF.R5[GroupElement].get
      |  val makerPk         = SELF.R6[GroupElement].get
      |  val cfg             = SELF.R7[Coll[Long]].get
      |  val claimantPayHash = SELF.R8[Coll[Byte]].get
      |
      |  val cfgOk           = secretHash.size == 32 && cfg.size == 2 && claimantPayHash.size == 32
      |  val refundHeight    = cfg(0)
      |  val maxRelayerFee   = cfg(1)
      |
      |  val mode            = getVar[Long](0).getOrElse(2L)
      |  val preimage        = getVar[Coll[Byte]](1).getOrElse(Coll[Byte]())
      |  val preimageValid   = preimage.size == 32 && sha256(preimage) == secretHash
      |
      |  // Branch 0: Direct Claimant Sweep (signed by claimantPk — immune to mempool preimage front-running!)
      |  val directClaim =
      |    sigmaProp(cfgOk && mode == 0L && HEIGHT < refundHeight && preimageValid) &&
      |    proveDlog(claimantPk)
      |
      |  // Branch 1: Gasless Submarine-Swap Relayer Sweep (0 claimant sigs, enforces full ERG - fee + ALL tokens + SELF.id!)
      |  val gaslessRelayClaim = if (cfgOk && mode == 1L && HEIGHT < refundHeight && preimageValid && OUTPUTS.size >= 1) {
      |    val out = OUTPUTS(0)
      |    out.value >= SELF.value - maxRelayerFee &&
      |    out.tokens == SELF.tokens &&
      |    blake2b256(out.propositionBytes) == claimantPayHash &&
      |    out.R4[Coll[Byte]].getOrElse(Coll[Byte]()) == SELF.id
      |  } else false
      |
      |  // Branch 2: Maker Timeout Refund (0 context vars required!)
      |  val makerRefund =
      |    sigmaProp(cfgOk && mode == 2L && HEIGHT >= refundHeight) &&
      |    proveDlog(makerPk)
      |
      |  directClaim || sigmaProp(gaslessRelayClaim) || makerRefund
      |}""".stripMargin

  // =================================================================================================
  // 2. SCRIPTLESS ADAPTOR SWAP (Zero-Hash PTLC — Unlinkable Schnorr Adaptor-Signature Swap!)
  // =================================================================================================
  val ScriptlessAdaptorSwapScript: String =
    """{
      |  // R4: GroupElement — `adaptorPointT = t * G` (extracted from counterparty Schnorr adaptor signature!)
      |  // R5: GroupElement — `claimantPk`
      |  // R6: GroupElement — `makerPk`
      |  // R7: Long — `refundHeight`
      |  val adaptorPointT = SELF.R4[GroupElement].get
      |  val claimantPk    = SELF.R5[GroupElement].get
      |  val makerPk       = SELF.R6[GroupElement].get
      |  val refundHeight  = SELF.R7[Long].get
      |  val identityPt    = groupGenerator.exp(0.toBigInt)
      |
      |  val validPoint    = adaptorPointT != identityPt && adaptorPointT != groupGenerator
      |
      |  // Branch A: Scriptless Claim — proves knowledge of BOTH claimant secret AND extracted adaptor scalar `t`!
      |  // ZERO hash preimage is ever revealed on-chain; indistinguishable from a standard 2-key Sigma spend!
      |  val adaptorClaim =
      |    sigmaProp(HEIGHT < refundHeight && validPoint) &&
      |    proveDlog(claimantPk) &&
      |    proveDlog(adaptorPointT)
      |
      |  // Branch B: Maker Timeout Refund
      |  val makerRefund =
      |    sigmaProp(HEIGHT >= refundHeight) &&
      |    proveDlog(makerPk)
      |
      |  adaptorClaim || makerRefund
      |}""".stripMargin
}
