/**
 * Ergo Testnet & Nautilus EIP-12 Browser Kit (`ergo-testnet-kit.js`) — Zero Dependencies.
 *
 * A drop-in, MIT-licensed Pure-JS library for connecting any static web app / GitHub Page
 * directly to the live Ergo Testnet (via public Explorer API or a local Ergo Node) and the
 * Nautilus EIP-12 browser wallet (`window.ergoConnector.nautilus`):
 *
 *   1. Exact RFC 7693 Blake2b-256 (matching Ergo Sigma `blake2b256` bit-for-bit)
 *   2. Exact Ergo Base58Check Address Encoder / Decoder (P2PK & P2S, Testnet/Mainnet guard)
 *   3. Exact Sigma `ValueSerializer` Constant Encoders (`SByte`, `SInt`, `SLong`, `SGroupElement`,
 *      `Coll[Byte]`, `Coll[Long]`, `Coll[GroupElement]`, `Coll[Coll[Byte]]`) — proven byte-for-byte
 *      against Ergo's official Scala `sigma-state 6.0.3` in CI!
 *   4. Live Ergo Testnet Explorer (`https://api-testnet.ergoplatform.com`, CORS `*`) & Node REST client
 *   5. Nautilus EIP-12 Wallet Connect (with hard Testnet safety guard), UTXO coin selection with
 *      full token-change preservation, canonical Miner Fee output, `sign_tx` & `submit_tx`.
 *
 * Usage in any browser page:
 *   <script src="https://a-shannon.github.io/lib/ergo-testnet-kit.js"></script>
 *
 * MIT License — Copyright (c) 2026 A. Shannon
 */
(function (root) {
  "use strict";

  const DEFAULT_TESTNET_API = "https://api-testnet.ergoplatform.com";
  const TESTNET_EXPLORER_WEB = "https://testnet.ergoplatform.com/en";
  // Official Ergo consensus Miner Fee ErgoTree (fee proposition):
  const MINER_FEE_ERGO_TREE =
    "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";
  const MIN_BOX_VALUE = 1000000n; // 0.001 ERG
  const DEFAULT_FEE = 1100000n;   // 0.0011 ERG

  // =========================================================================
  // 1. PURE RFC 7693 BLAKE2B-256 (Bit-exact match with Ergo Sigma blake2b256)
  // =========================================================================
  const MASK64 = 0xffffffffffffffffn;
  const IV = new BigUint64Array([
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
    0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
    0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
  ]);
  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
  ];

  function rotr64(x, n) {
    return ((x >> n) | ((x << (64n - n)) & MASK64)) & MASK64;
  }

  function compress(h, block, t, isLast) {
    const v = new BigUint64Array(16);
    const m = new BigUint64Array(16);
    for (let i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
    v[12] ^= t & MASK64;
    v[13] ^= t >> 64n;
    if (isLast) v[14] ^= MASK64;
    const dv = new DataView(block.buffer, block.byteOffset, 128);
    for (let i = 0; i < 16; i++) m[i] = dv.getBigUint64(i * 8, true);
    function G(a, b, c, d, x, y) {
      v[a] = (v[a] + v[b] + x) & MASK64; v[d] = rotr64(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & MASK64;     v[b] = rotr64(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & MASK64; v[d] = rotr64(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & MASK64;     v[b] = rotr64(v[b] ^ v[c], 63n);
    }
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      G(0, 4, 8, 12, m[s[0]], m[s[1]]);   G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]);  G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]);  G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }

  function blake2b256(input) {
    const data = input instanceof Uint8Array ? input : new TextEncoder().encode(String(input));
    const h = new BigUint64Array(IV);
    h[0] ^= 0x01010020n;
    const block = new Uint8Array(128);
    let offset = 0;
    const len = data.length;
    while (offset + 128 < len) {
      block.set(data.subarray(offset, offset + 128), 0);
      offset += 128;
      compress(h, block, BigInt(offset), false);
    }
    block.fill(0);
    if (offset < len) block.set(data.subarray(offset, len), 0);
    compress(h, block, BigInt(len), true);
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 4; i++) dv.setBigUint64(i * 8, h[i], true);
    return out;
  }

  // =========================================================================
  // 2. BYTE / HEX / BASE58CHECK ERGO ADDRESS CODECS
  // =========================================================================
  function concatBytes(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }

  function toHex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }

  function fromHex(hex) {
    const clean = String(hex).trim().replace(/^0x/i, "");
    if (clean.length % 2 !== 0) throw new Error("Odd hex length: " + clean.length);
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      const b = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(b)) throw new Error("Invalid hex byte at " + i);
      out[i] = b;
    }
    return out;
  }

  const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const B58_MAP = {};
  for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = BigInt(i);

  function base58Encode(bytes) {
    let num = 0n;
    for (let i = 0; i < bytes.length; i++) num = (num << 8n) + BigInt(bytes[i]);
    let encoded = "";
    while (num > 0n) {
      encoded = B58_ALPHABET[Number(num % 58n)] + encoded;
      num /= 58n;
    }
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) encoded = "1" + encoded;
    return encoded;
  }

  function base58Decode(str) {
    const s = String(str).trim();
    if (!s.length) throw new Error("Empty Base58 string");
    let num = 0n;
    for (let i = 0; i < s.length; i++) {
      const v = B58_MAP[s[i]];
      if (v === undefined) throw new Error("Invalid Base58 character: " + s[i]);
      num = num * 58n + v;
    }
    const rev = [];
    while (num > 0n) { rev.push(Number(num & 0xffn)); num >>= 8n; }
    let leadingZeros = 0;
    for (let i = 0; i < s.length && s[i] === "1"; i++) leadingZeros++;
    const out = new Uint8Array(leadingZeros + rev.length);
    for (let i = 0; i < rev.length; i++) out[leadingZeros + i] = rev[rev.length - 1 - i];
    return out;
  }

  function encodeAddress(prefixByte, contentBytes) {
    const body = concatBytes(new Uint8Array([prefixByte & 0xff]), contentBytes);
    const checksum = blake2b256(body).subarray(0, 4);
    return base58Encode(concatBytes(body, checksum));
  }

  function encodeP2S(ergoTreeHex, network = "testnet") {
    const netPrefix = network === "mainnet" ? 0x00 : 0x10;
    return encodeAddress(netPrefix + 0x03, fromHex(ergoTreeHex));
  }

  function encodeP2PK(pubKeyHex33, network = "testnet") {
    const pk = fromHex(pubKeyHex33);
    if (pk.length !== 33) throw new Error("Compressed secp256k1 pubKey must be 33 bytes");
    const netPrefix = network === "mainnet" ? 0x00 : 0x10;
    return encodeAddress(netPrefix + 0x01, pk);
  }

  function decodeAddress(address) {
    const raw = base58Decode(address);
    if (raw.length < 6) throw new Error("Ergo address too short");
    const body = raw.subarray(0, raw.length - 4);
    const givenCs = raw.subarray(raw.length - 4);
    const expCs = blake2b256(body).subarray(0, 4);
    for (let i = 0; i < 4; i++) {
      if (givenCs[i] !== expCs[i]) throw new Error("Invalid Ergo address Blake2b-256 checksum");
    }
    const head = body[0];
    const netByte = head & 0xf0;
    const typeByte = head & 0x0f;
    const network = netByte === 0x00 ? "mainnet" : (netByte === 0x10 ? "testnet" : "unknown");
    const content = body.subarray(1);

    if (typeByte === 0x01) {
      if (content.length !== 33) throw new Error("Invalid P2PK pubkey length: " + content.length);
      const pubKeyHex = toHex(content);
      const ergoTreeHex = "0008cd" + pubKeyHex;
      const payHashHex = toHex(blake2b256(fromHex(ergoTreeHex)));
      return { address, network, type: "P2PK", prefixByte: head, pubKeyHex, ergoTreeHex, payHashHex };
    }
    if (typeByte === 0x03) {
      const ergoTreeHex = toHex(content);
      const payHashHex = toHex(blake2b256(content));
      return { address, network, type: "P2S", prefixByte: head, pubKeyHex: null, ergoTreeHex, payHashHex };
    }
    return { address, network, type: "OTHER_" + typeByte, prefixByte: head, pubKeyHex: null, ergoTreeHex: toHex(content), payHashHex: toHex(blake2b256(content)) };
  }

  // =========================================================================
  // 3. EXACT SIGMA `ValueSerializer` CONSTANT ENCODERS (sigma-state 6.0.3)
  // =========================================================================
  function putULongVlq(val) {
    let x = BigInt(val);
    if (x < 0n) throw new Error("Negative value in unsigned VLQ: " + val);
    const out = [];
    while (true) {
      if ((x & ~0x7fn) === 0n) { out.push(Number(x)); break; }
      out.push(Number((x & 0x7fn) | 0x80n));
      x >>= 7n;
    }
    return new Uint8Array(out);
  }

  function zigzag32(n) {
    const x = BigInt(n | 0);
    return ((x << 1n) ^ (x >> 31n)) & 0xffffffffn;
  }

  function zigzag64(n) {
    const x = BigInt.asIntN(64, BigInt(n));
    return BigInt.asUintN(64, (x << 1n) ^ (x >> 63n));
  }

  const Sigma = {
    encodeByte(b) {
      return toHex(new Uint8Array([0x02, b & 0xff]));
    },
    encodeInt(v) {
      return toHex(concatBytes(new Uint8Array([0x04]), putULongVlq(zigzag32(v))));
    },
    encodeLong(v) {
      return toHex(concatBytes(new Uint8Array([0x05]), putULongVlq(zigzag64(v))));
    },
    encodeGroupElement(pointHex33) {
      const pts = fromHex(pointHex33);
      if (pts.length !== 33) throw new Error("GroupElement must be 33-byte compressed secp256k1 point");
      return toHex(concatBytes(new Uint8Array([0x07]), pts));
    },
    encodeByteArray(bytesOrHex) {
      const bs = bytesOrHex instanceof Uint8Array ? bytesOrHex : fromHex(bytesOrHex);
      return toHex(concatBytes(new Uint8Array([0x0e]), putULongVlq(bs.length), bs));
    },
    encodeLongArray(arr) {
      const parts = [new Uint8Array([0x11]), putULongVlq(arr.length)];
      for (const v of arr) parts.push(putULongVlq(zigzag64(v)));
      return toHex(concatBytes(...parts));
    },
    encodeGroupElementArray(pointHexArray) {
      const parts = [new Uint8Array([0x13]), putULongVlq(pointHexArray.length)];
      for (const hex of pointHexArray) {
        const bs = fromHex(hex);
        if (bs.length !== 33) throw new Error("Each GroupElement must be 33 bytes");
        parts.push(bs);
      }
      return toHex(concatBytes(...parts));
    },
    encodeByteArrayColl(hexArray) {
      // Coll[Coll[Byte]] = TypeCode 24 + 2 = 0x1a
      const parts = [new Uint8Array([0x1a]), putULongVlq(hexArray.length)];
      for (const item of hexArray) {
        const bs = item instanceof Uint8Array ? item : fromHex(item);
        parts.push(putULongVlq(bs.length), bs);
      }
      return toHex(concatBytes(...parts));
    }
  };

  // =========================================================================
  // 4. LIVE ERGO TESTNET EXPLORER & LOCAL NODE REST CLIENT
  // =========================================================================
  async function fetchJson(url, opts = {}) {
    const res = await fetch(url, opts);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} from ${url}: ${body.slice(0, 200)}`);
    }
    return res.json();
  }

  async function fetchNetworkState(apiBase = DEFAULT_TESTNET_API) {
    const base = apiBase.replace(/\/+$/, "");
    // Try Explorer v1 first; fall back to Ergo Node /info
    try {
      const data = await fetchJson(`${base}/api/v1/networkState`);
      return {
        source: "explorer",
        apiBase: base,
        height: Number(data.height),
        lastBlockId: data.lastBlockId,
        blockVersion: data.params ? data.params.blockVersion : null,
        explorerWeb: TESTNET_EXPLORER_WEB
      };
    } catch (_) {
      const info = await fetchJson(`${base}/info`);
      return {
        source: "node",
        apiBase: base,
        height: Number(info.fullHeight || info.headersHeight || 0),
        lastBlockId: info.bestFullHeaderId || null,
        appVersion: info.appVersion || null,
        explorerWeb: TESTNET_EXPLORER_WEB
      };
    }
  }

  async function fetchUnspentBoxes(address, apiBase = DEFAULT_TESTNET_API, limit = 20) {
    const base = apiBase.replace(/\/+$/, "");
    try {
      const data = await fetchJson(`${base}/api/v1/boxes/unspent/byAddress/${encodeURIComponent(address)}?limit=${limit}`);
      return {
        total: Number(data.total || (data.items ? data.items.length : 0)),
        items: (data.items || []).map(b => ({
          boxId: b.boxId,
          transactionId: b.transactionId,
          value: String(b.value),
          creationHeight: Number(b.creationHeight),
          ergoTree: b.ergoTree,
          assets: (b.assets || []).map(a => ({ tokenId: a.tokenId, amount: String(a.amount) })),
          additionalRegisters: b.additionalRegisters || {}
        }))
      };
    } catch (_) {
      const arr = await fetchJson(`${base}/blockchain/box/unspent/byAddress?offset=0&limit=${limit}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(address)
      });
      const list = Array.isArray(arr) ? arr : (arr.items || []);
      return { total: list.length, items: list };
    }
  }

  // =========================================================================
  // 5. NAUTILUS EIP-12 WALLET CONNECTOR & UNSIGNED TX BUILDER
  // =========================================================================
  async function connectNautilus(options = {}) {
    const requireTestnet = options.requireTestnet !== false;
    if (typeof window === "undefined" || !window.ergoConnector || !window.ergoConnector.nautilus) {
      throw new Error("Nautilus wallet extension not detected. Install Nautilus and switch it to Ergo Testnet, or use JSON Export mode.");
    }
    const granted = await window.ergoConnector.nautilus.connect();
    if (!granted) throw new Error("Nautilus connection request was rejected.");
    const ergo = window.ergo;
    const changeAddress = await ergo.get_change_address();
    const decoded = decodeAddress(changeAddress);
    if (requireTestnet && decoded.network !== "testnet") {
      throw new Error(
        `Safety block: Nautilus is currently connected to ERGO ${decoded.network.toUpperCase()} (${changeAddress.slice(0, 10)}…). ` +
        `Switch Nautilus to Testnet before transacting in this Testnet lab!`
      );
    }
    const [utxos, balanceNano, height] = await Promise.all([
      ergo.get_utxos(),
      ergo.get_balance("ERG"),
      ergo.get_current_height()
    ]);
    return {
      ergo,
      changeAddress,
      decoded,
      pubKeyHex: decoded.pubKeyHex,
      ergoTreeHex: decoded.ergoTreeHex,
      payHashHex: decoded.payHashHex,
      balanceNano: BigInt(balanceNano || 0),
      height: Number(height),
      utxos: utxos || []
    };
  }

  /**
   * Build a 100% EIP-12 compliant Unsigned Ergo Transaction locking funds into a Sigma v6 P2S contract box.
   * Automatically preserves all change ERG and 100% of unrelated wallet tokens!
   */
  function buildEip12LockTx(params) {
    const utxos = params.utxos || [];
    const changeDec = decodeAddress(params.changeAddress);
    const lockNano = BigInt(params.lockNanoErg);
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const lockAssets = params.lockAssets || []; // [{ tokenId, amount }]
    const creationHeight = Number(params.creationHeight);
    const registers = params.registers || {};

    if (lockNano < MIN_BOX_VALUE) throw new Error("lockNanoErg must be >= 1,000,000 (0.001 ERG)");

    // Need enough ERG for lock + fee (+ min change if leftover ERG or tokens remain)
    const needTok = new Map();
    for (const a of lockAssets) {
      needTok.set(a.tokenId, (needTok.get(a.tokenId) || 0n) + BigInt(a.amount));
    }

    const selected = [];
    let sumErg = 0n;
    const haveTok = new Map();

    function tokensSatisfied() {
      for (const [tid, req] of needTok.entries()) {
        if ((haveTok.get(tid) || 0n) < req) return false;
      }
      return true;
    }

    for (const u of utxos) {
      selected.push(u);
      sumErg += BigInt(u.value);
      for (const a of (u.assets || [])) {
        haveTok.set(a.tokenId, (haveTok.get(a.tokenId) || 0n) + BigInt(a.amount));
      }
      const leftover = sumErg - lockNano - feeNano;
      const hasChangeTok = Array.from(haveTok.entries()).some(([tid, amt]) => amt > (needTok.get(tid) || 0n));
      const ergOk = leftover === 0n && !hasChangeTok ? true : leftover >= MIN_BOX_VALUE;
      if (ergOk && tokensSatisfied()) break;
    }

    const changeErg = sumErg - lockNano - feeNano;
    const changeAssets = [];
    for (const [tid, amt] of haveTok.entries()) {
      const rem = amt - (needTok.get(tid) || 0n);
      if (rem > 0n) changeAssets.push({ tokenId: tid, amount: rem.toString() });
    }

    if (!tokensSatisfied() || changeErg < 0n || ((changeErg > 0n || changeAssets.length > 0) && changeErg < MIN_BOX_VALUE)) {
      throw new Error(
        `Insufficient Testnet UTXO balance. Have ${(Number(sumErg) / 1e9).toFixed(4)} ERG across ${selected.length} UTXO(s), ` +
        `need at least ${(Number(lockNano + feeNano + MIN_BOX_VALUE) / 1e9).toFixed(4)} ERG (incl. fee & min change).`
      );
    }

    const outputs = [
      {
        value: lockNano.toString(),
        ergoTree: params.contractErgoTreeHex,
        assets: lockAssets.map(a => ({ tokenId: a.tokenId, amount: BigInt(a.amount).toString() })),
        additionalRegisters: registers,
        creationHeight
      },
      {
        value: feeNano.toString(),
        ergoTree: MINER_FEE_ERGO_TREE,
        assets: [],
        additionalRegisters: {},
        creationHeight
      }
    ];

    if (changeErg >= MIN_BOX_VALUE) {
      outputs.push({
        value: changeErg.toString(),
        ergoTree: changeDec.ergoTreeHex,
        assets: changeAssets,
        additionalRegisters: {},
        creationHeight
      });
    }

    return {
      inputs: selected.map(u => Object.assign({}, u, { extension: u.extension || {} })),
      dataInputs: params.dataInputs || [],
      outputs
    };
  }

  async function signAndSubmitNautilus(unsignedTx) {
    if (typeof window === "undefined" || !window.ergo) {
      throw new Error("Nautilus wallet is not connected.");
    }
    const signedTx = await window.ergo.sign_tx(unsignedTx);
    const txId = await window.ergo.submit_tx(signedTx);
    return {
      txId,
      signedTx,
      explorerUrl: `${TESTNET_EXPLORER_WEB}/transactions/${txId}`
    };
  }

  const api = {
    VERSION: "1.0.0",
    DEFAULT_TESTNET_API,
    TESTNET_EXPLORER_WEB,
    MINER_FEE_ERGO_TREE,
    blake2b256,
    toHex,
    fromHex,
    concatBytes,
    base58Encode,
    base58Decode,
    encodeP2S,
    encodeP2PK,
    decodeAddress,
    Sigma,
    fetchNetworkState,
    fetchUnspentBoxes,
    connectNautilus,
    buildEip12LockTx,
    signAndSubmitNautilus
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ErgoTestnetKit = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
