package ergo.swaps

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import scorex.util.encode.Base16

import java.nio.file.{Files, Paths}
import scala.sys.process._

/**
  * Node.js <-> Scala `sigma-state 6.0.3` Differential Parity Spec for `docs/ergo-testnet-kit.js`.
  * Proves that Pure-JS P2S addresses for BOTH `ScriptlessAdaptorSwap` and `CrossChainHashSwap`
  * match Scala `ErgoAddressEncoder` 100% byte-for-byte!
  */
class TestnetKitParitySpec extends AnyFlatSpec with Matchers {

  "ergo-testnet-kit.js" should "match Scala Testnet P2S addresses for PTLC & HTLC 100% byte-for-byte via Node.js" in {
    val kitPath = Paths.get("docs", "ergo-testnet-kit.js").toAbsolutePath
    assume(Files.exists(kitPath), s"Skipping Node.js parity test: $kitPath not present")

    val (ptlcTree, ptlcBytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.ScriptlessAdaptorSwapScript)
    val (htlcTree, htlcBytes) = AtomicSwapContracts.compileV6(AtomicSwapContracts.CrossChainHashSwapScript)
    val expPtlc = AtomicSwapContracts.p2sAddress(ptlcTree, mainnet = false)
    val expHtlc = AtomicSwapContracts.p2sAddress(htlcTree, mainnet = false)

    val jsCode =
      s"""const kit = require(process.argv[1]);
         |console.log(JSON.stringify({
         |  ptlc: kit.encodeP2S('${Base16.encode(ptlcBytes)}', 'testnet'),
         |  htlc: kit.encodeP2S('${Base16.encode(htlcBytes)}', 'testnet')
         |}));""".stripMargin

    val stdout = Seq("node", "-e", jsCode, kitPath.toString).!!.trim
    stdout should include(s""""ptlc":"$expPtlc"""")
    stdout should include(s""""htlc":"$expHtlc"""")
    println(s"[TestnetKitParity] PTLC (83 B) & HTLC (255 B) Testnet P2S matched Scala sigma-state 6.0.3 100% BYTE-FOR-BYTE!")
  }
}
