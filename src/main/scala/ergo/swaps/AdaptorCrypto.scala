package ergo.swaps

import scorex.crypto.hash.Sha256
import sigma.crypto.CryptoConstants
import sigma.crypto.Platform.Ecp
import sigma.data.CGroupElement

import java.math.BigInteger
import java.nio.{ByteBuffer, ByteOrder}

/**
  * Real `secp256k1` Schnorr Adaptor Signature Cryptography for Scriptless Cross-Chain Swaps (PTLCs).
  *
  * Protocol flow (Zero On-Chain Hash Linkability!):
  *   1. Adaptor secret `t` (scalar mod n), Adaptor public point `T = t * G`.
  *   2. Counterparty Bob (`P_B = x_B * G`) creates a Schnorr Adaptor Pre-Signature `(R', s')` over
  *      Bitcoin/external tx message `msg` locked to `T`:
  *        - Nonce `k`, `R' = k * G`, combined nonce `R = R' + T = (k + t) * G`
  *        - Challenge `e = SHA256(R || P_B || msg) mod n`
  *        - Pre-signature `s' = (k + e * x_B) mod n`
  *        - Anyone verifies `s' * G == R' + e * P_B` (valid pre-sig, NOT yet a valid signature on `R`!)
  *   3. When Bob knows `t`, Bob adapts `s = (s' + t) mod n` -> `(R, s)` is a valid standard Schnorr signature
  *      (`s * G == R + e * P_B`) that broadcasts on Bitcoin / counterparty chain!
  *   4. Alice observes `(R, s)` on the counterparty chain and extracts the adaptor secret in ONE subtraction:
  *        `t_extracted = (s - s') mod n`
  *   5. Alice feeds `DLogProverInput(t_extracted)` + her own key to Ergo's `ScriptlessAdaptorSwap`
  *      (`proveDlog(claimantPk) && proveDlog(T)`) — ZERO SHA-256 hash ever appears on Ergo!
  *   6. Multi-hop relays re-randomize `T_2 = T_1 + delta * G`, breaking all on-chain hop correlation!
  */
object AdaptorCrypto {

  val G: Ecp        = CryptoConstants.dlogGroup.generator
  val Order: BigInteger = CryptoConstants.dlogGroup.order

  def be64(v: Long): Array[Byte] =
    ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(v).array()

  def point(scalar: BigInteger): Ecp =
    CryptoConstants.dlogGroup.exponentiate(G, scalar.mod(Order))

  def addPoints(a: Ecp, b: Ecp): Ecp =
    CryptoConstants.dlogGroup.multiplyGroupElements(a, b)

  def encoded(p: Ecp): Array[Byte] =
    CGroupElement(p).getEncoded.toArray

  def challenge(r: Ecp, pubKey: Ecp, msg: Array[Byte]): BigInteger = {
    val h = Sha256.hash(encoded(r) ++ encoded(pubKey) ++ msg)
    new BigInteger(1, h).mod(Order)
  }

  final case class AdaptorPreSig(rPrime: Ecp, combinedR: Ecp, sPrime: BigInteger)
  final case class SchnorrSig(combinedR: Ecp, s: BigInteger)

  def preSign(signerSecret: BigInteger, nonceK: BigInteger, adaptorPointT: Ecp, msg: Array[Byte]): AdaptorPreSig = {
    val pk        = point(signerSecret)
    val rPrime    = point(nonceK)
    val combinedR = addPoints(rPrime, adaptorPointT)
    val e         = challenge(combinedR, pk, msg)
    val sPrime    = nonceK.add(e.multiply(signerSecret)).mod(Order)
    AdaptorPreSig(rPrime, combinedR, sPrime)
  }

  def verifyPreSig(pubKey: Ecp, adaptorPointT: Ecp, msg: Array[Byte], pre: AdaptorPreSig): Boolean = {
    val expectedR = addPoints(pre.rPrime, adaptorPointT)
    if (expectedR != pre.combinedR) return false
    val e   = challenge(pre.combinedR, pubKey, msg)
    val lhs = point(pre.sPrime)
    val rhs = addPoints(pre.rPrime, CryptoConstants.dlogGroup.exponentiate(pubKey, e))
    lhs == rhs
  }

  def adapt(pre: AdaptorPreSig, adaptorSecretT: BigInteger): SchnorrSig =
    SchnorrSig(pre.combinedR, pre.sPrime.add(adaptorSecretT).mod(Order))

  def verifySchnorr(pubKey: Ecp, msg: Array[Byte], sig: SchnorrSig): Boolean = {
    val e   = challenge(sig.combinedR, pubKey, msg)
    val lhs = point(sig.s)
    val rhs = addPoints(sig.combinedR, CryptoConstants.dlogGroup.exponentiate(pubKey, e))
    lhs == rhs
  }

  def extractSecret(pre: AdaptorPreSig, completed: SchnorrSig): BigInteger =
    completed.s.subtract(pre.sPrime).mod(Order)

  /** Multi-hop point re-randomization: T2 = T1 + delta * G (cryptographically unlinkable to T1!). */
  def rerandomizePoint(t1: Ecp, delta: BigInteger): Ecp =
    addPoints(t1, point(delta))

  def rerandomizeSecret(t1Secret: BigInteger, delta: BigInteger): BigInteger =
    t1Secret.add(delta).mod(Order)
}
