/**
 * Ergo Testnet & Nautilus EIP-12 Browser Kit (`ergo-testnet-kit.js`) v1.2.0 — Zero Dependencies.
 *
 * A drop-in, MIT-licensed Pure-JS library for connecting any static web app / GitHub Page
 * directly to the live Ergo Testnet (via public Explorer API or a local/custom Ergo Node with
 * smart multi-endpoint failover & stale-indexer lag detection) and the Nautilus EIP-12 wallet:
 *
 *   1. Exact RFC 7693 Blake2b-256 (matching Ergo Sigma `blake2b256` bit-for-bit)
 *   2. Exact Ergo Base58Check Address Encoder / Decoder (P2PK & P2S, Testnet/Mainnet guard)
 *   3. Exact Sigma `ValueSerializer` Constant Encoders AND Decoders (`SByte`, `SInt`, `SLong`,
 *      `SGroupElement`, `Coll[Byte]`, `Coll[Long]`, `Coll[GroupElement]`, `Coll[Coll[Byte]]`) —
 *      proven 100% byte-for-byte against Ergo's official Scala `sigma-state 6.0.3` in CI!
 *   4. Multi-endpoint Live Ergo Testnet REST client (`fetchBestNetworkState`, stale-indexer lag
 *      detection, automatic Explorer <-> Ergo Node fallback, `fetchUnspentBoxes`, `submitSignedTx`)
 *   5. Nautilus EIP-12 Wallet Connect (hard Testnet safety guard), UTXO coin selection with full
 *      token-change preservation, canonical Miner Fee output, AND 1-click P2S Lock / Spend /
 *      Sweep / Veto / 0-Sig Finalize / Claim / Refund builders verified against Scala 6.0.3 in CI!
 *
 * Usage in any browser page:
 *   <script src="https://a-shannon.github.io/lib/ergo-testnet-kit.js"></script>
 *
 * MIT License — Copyright (c) 2026 A. Shannon
 */
(function (root) {
  "use strict";

  const DEFAULT_TESTNET_API = "https://api-testnet.ergoplatform.com";
  const DEFAULT_LOCAL_NODE = "http://127.0.0.1:9052";
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
  // 3. EXACT SIGMA `ValueSerializer` CONSTANT ENCODERS & DECODERS (6.0.3)
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

  function getULongVlq(bytes, startOffset = 0) {
    let shift = 0n;
    let res = 0n;
    let off = startOffset;
    while (off < bytes.length) {
      const b = BigInt(bytes[off++]);
      res |= (b & 0x7fn) << shift;
      if ((b & 0x80n) === 0n) return { value: res, offset: off };
      shift += 7n;
      if (shift > 70n) throw new Error("VLQ overflow");
    }
    throw new Error("Truncated VLQ");
  }

  function zigzag32(n) {
    const x = BigInt(n | 0);
    return ((x << 1n) ^ (x >> 31n)) & 0xffffffffn;
  }

  function unzigzag32(u) {
    const x = (u >> 1n) ^ -(u & 1n);
    return Number(BigInt.asIntN(32, x));
  }

  function zigzag64(n) {
    const x = BigInt.asIntN(64, BigInt(n));
    return BigInt.asUintN(64, (x << 1n) ^ (x >> 63n));
  }

  function unzigzag64(u) {
    return BigInt.asIntN(64, (u >> 1n) ^ -(u & 1n));
  }

  const Sigma = {
    encodeByte(b) {
      return toHex(new Uint8Array([0x02, b & 0xff]));
    },
    encodeInt(v) {
      return toHex(concatBytes(new Uint8Array([0x04]), putULongVlq(zigzag32(v))));
    },
    decodeInt(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x04) throw new Error("Expected SInt (0x04), got 0x" + bs[0].toString(16));
      return unzigzag32(getULongVlq(bs, 1).value);
    },
    encodeLong(v) {
      return toHex(concatBytes(new Uint8Array([0x05]), putULongVlq(zigzag64(v))));
    },
    decodeLong(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x05) throw new Error("Expected SLong (0x05), got 0x" + bs[0].toString(16));
      return unzigzag64(getULongVlq(bs, 1).value);
    },
    encodeGroupElement(pointHex33) {
      const pts = fromHex(pointHex33);
      if (pts.length !== 33) throw new Error("GroupElement must be 33-byte compressed secp256k1 point");
      return toHex(concatBytes(new Uint8Array([0x07]), pts));
    },
    decodeGroupElement(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x07 || bs.length !== 34) throw new Error("Expected SGroupElement (0x07 + 33B)");
      return toHex(bs.subarray(1));
    },
    encodeByteArray(bytesOrHex) {
      const bs = bytesOrHex instanceof Uint8Array ? bytesOrHex : fromHex(bytesOrHex);
      return toHex(concatBytes(new Uint8Array([0x0e]), putULongVlq(bs.length), bs));
    },
    decodeByteArray(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x0e) throw new Error("Expected Coll[Byte] (0x0e)");
      const { value: len, offset } = getULongVlq(bs, 1);
      return toHex(bs.subarray(offset, offset + Number(len)));
    },
    encodeLongArray(arr) {
      const parts = [new Uint8Array([0x11]), putULongVlq(arr.length)];
      for (const v of arr) parts.push(putULongVlq(zigzag64(v)));
      return toHex(concatBytes(...parts));
    },
    decodeLongArray(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x11) throw new Error("Expected Coll[Long] (0x11)");
      let { value: len, offset } = getULongVlq(bs, 1);
      const out = [];
      for (let i = 0; i < Number(len); i++) {
        const next = getULongVlq(bs, offset);
        out.push(unzigzag64(next.value));
        offset = next.offset;
      }
      return out;
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
    decodeGroupElementArray(hex) {
      const bs = fromHex(hex);
      if (bs[0] !== 0x13) throw new Error("Expected Coll[GroupElement] (0x13)");
      let { value: len, offset } = getULongVlq(bs, 1);
      const out = [];
      for (let i = 0; i < Number(len); i++) {
        out.push(toHex(bs.subarray(offset, offset + 33)));
        offset += 33;
      }
      return out;
    },
    encodeByteArrayColl(hexArray) {
      const parts = [new Uint8Array([0x1a]), putULongVlq(hexArray.length)];
      for (const item of hexArray) {
        const bs = item instanceof Uint8Array ? item : fromHex(item);
        parts.push(putULongVlq(bs.length), bs);
      }
      return toHex(concatBytes(...parts));
    }
  };

  function regHex(box, key) {
    const regs = (box && box.additionalRegisters) || {};
    const v = regs[key];
    if (!v) return null;
    return typeof v === "string" ? v : (v.serializedValue || null);
  }

  function normalizeRegisters(regs) {
    const out = {};
    if (!regs) return out;
    for (const k of Object.keys(regs).sort()) {
      const v = regs[k];
      out[k] = typeof v === "string" ? v : (v && v.serializedValue ? v.serializedValue : String(v));
    }
    return out;
  }

  function normalizeBoxForEip12(box, extension = {}) {
    return {
      boxId: box.boxId,
      transactionId: box.transactionId,
      index: Number(box.index != null ? box.index : 0),
      ergoTree: box.ergoTree,
      creationHeight: Number(box.creationHeight),
      value: BigInt(box.value).toString(),
      assets: (box.assets || []).map(a => ({ tokenId: a.tokenId, amount: BigInt(a.amount).toString() })),
      additionalRegisters: normalizeRegisters(box.additionalRegisters),
      extension: extension || {}
    };
  }

  // =========================================================================
  // 4. LIVE ERGO TESTNET EXPLORER & LOCAL NODE REST CLIENT
  // =========================================================================
  async function fetchJson(url, opts = {}) {
    const res = await fetch(url, opts);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} from ${url}: ${body.slice(0, 240)}`);
    }
    return res.json();
  }

  async function fetchNetworkState(apiBase = DEFAULT_TESTNET_API) {
    const base = apiBase.replace(/\/+$/, "");
    try {
      const data = await fetchJson(`${base}/api/v1/networkState`);
      let lastBlockTs = null;
      try {
        const blks = await fetchJson(`${base}/api/v1/blocks?limit=1`);
        if (blks && blks.items && blks.items.length) lastBlockTs = Number(blks.items[0].timestamp || 0) || null;
      } catch (_) {}
      const lagMinutes = lastBlockTs ? Math.max(0, Math.round((Date.now() - lastBlockTs) / 60000)) : null;
      return {
        source: "explorer",
        apiBase: base,
        height: Number(data.height),
        lastBlockId: data.lastBlockId,
        blockVersion: data.params ? data.params.blockVersion : null,
        lastBlockTimestamp: lastBlockTs,
        lagMinutes,
        isStale: lagMinutes !== null && lagMinutes > 30,
        explorerWeb: TESTNET_EXPLORER_WEB
      };
    } catch (_) {
      const info = await fetchJson(`${base}/info`);
      const lastBlockTs = Number(info.lastMemPoolUpdateTime || 0) || null;
      return {
        source: "node",
        apiBase: base,
        height: Number(info.fullHeight || info.headersHeight || 0),
        lastBlockId: info.bestFullHeaderId || null,
        appVersion: info.appVersion || null,
        lastBlockTimestamp: lastBlockTs,
        lagMinutes: 0,
        isStale: false,
        explorerWeb: TESTNET_EXPLORER_WEB
      };
    }
  }

  /**
   * Smart Multi-Endpoint Auto-Failover: probes all provided Testnet endpoints in parallel
   * (e.g. local Ergo node `http://127.0.0.1:9052` + public Explorer `https://api-testnet.ergoplatform.com`)
   * and automatically selects the healthy endpoint with the HIGHEST live block height!
   */
  async function fetchBestNetworkState(endpoints = [DEFAULT_LOCAL_NODE, DEFAULT_TESTNET_API]) {
    const unique = Array.from(new Set(endpoints.filter(Boolean).map(e => String(e).trim().replace(/\/+$/, ""))));
    const settled = await Promise.all(
      unique.map(ep =>
        Promise.race([
          fetchNetworkState(ep),
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 4500))
        ]).then(v => ({ ok: true, v })).catch(e => ({ ok: false, ep, err: e.message }))
      )
    );
    const live = settled.filter(s => s.ok).map(s => s.v);
    if (!live.length) throw new Error("All Testnet endpoints unreachable: " + settled.map(s => `${s.ep} (${s.err})`).join("; "));
    live.sort((a, b) => b.height - a.height);
    const best = live[0];
    best.candidates = live.map(c => ({ apiBase: c.apiBase, source: c.source, height: c.height, isStale: c.isStale }));
    return best;
  }

  async function fetchUnspentBoxes(address, apiBase = DEFAULT_TESTNET_API, limit = 20) {
    const base = apiBase.replace(/\/+$/, "");
    try {
      const data = await fetchJson(`${base}/api/v1/boxes/unspent/byAddress/${encodeURIComponent(address)}?limit=${limit}`);
      return {
        total: Number(data.total || (data.items ? data.items.length : 0)),
        items: (data.items || []).map(b => normalizeBoxForEip12(b))
      };
    } catch (_) {
      const arr = await fetchJson(`${base}/blockchain/box/unspent/byAddress?offset=0&limit=${limit}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(address)
      });
      const list = Array.isArray(arr) ? arr : (arr.items || []);
      return { total: list.length, items: list.map(b => normalizeBoxForEip12(b)) };
    }
  }

  async function submitSignedTx(signedTx, apiBase = DEFAULT_TESTNET_API) {
    const base = apiBase.replace(/\/+$/, "");
    try {
      const res = await fetchJson(`${base}/api/v1/mempool/transactions/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signedTx)
      });
      const txId = typeof res === "string" ? res : (res.id || res.txId || JSON.stringify(res));
      return { txId, explorerUrl: `${TESTNET_EXPLORER_WEB}/transactions/${txId}` };
    } catch (_) {
      const res = await fetchJson(`${base}/transactions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(signedTx)
      });
      const txId = typeof res === "string" ? res : (res.id || res.txId || JSON.stringify(res));
      return { txId, explorerUrl: `${TESTNET_EXPLORER_WEB}/transactions/${txId}` };
    }
  }

  // =========================================================================
  // 5. NAUTILUS EIP-12 WALLET CONNECTOR, LOCK & 1-CLICK P2S SPEND BUILDERS
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

  function buildEip12LockTx(params) {
    const utxos = params.utxos || [];
    const changeDec = decodeAddress(params.changeAddress);
    const lockNano = BigInt(params.lockNanoErg);
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const lockAssets = params.lockAssets || [];
    const creationHeight = Number(params.creationHeight);
    const registers = params.registers || {};

    if (lockNano < MIN_BOX_VALUE) throw new Error("lockNanoErg must be >= 1,000,000 (0.001 ERG)");

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
      inputs: selected.map(u => normalizeBoxForEip12(u, u.extension || {})),
      dataInputs: params.dataInputs || [],
      outputs
    };
  }

  /**
   * 1-Click DailyLimitVault Hot Spend (`mode = 0L`, `proveDlog(hotPk)`).
   * Automatically decodes R4/R5/R6 from the live vault box, checks rolling-window allowance,
   * and emits the exact successor vault at OUTPUTS(0), payout at OUTPUTS(1), and miner fee at OUTPUTS(2).
   */
  function buildEip12DailyHotSpendTx(params) {
    const box = normalizeBoxForEip12(params.vaultBox, { "0": Sigma.encodeLong(0n) });
    const hotHex = regHex(box, "R4");
    const coldHex = regHex(box, "R5");
    const cfgHex = regHex(box, "R6");
    if (!hotHex || !coldHex || !cfgHex) throw new Error("DailyLimitVault box missing R4/R5/R6 registers.");

    const cfg = Sigma.decodeLongArray(cfgHex);
    if (cfg.length !== 5) throw new Error("Invalid DailyLimitVault R6 length: " + cfg.length);
    const [limitErg, winBlks, winStart, spentWin, minCarr] = cfg;

    const spendNano = BigInt(params.spendNanoErg);
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const height = BigInt(params.creationHeight);
    const selfVal = BigInt(box.value);
    const spentNow = spendNano + feeNano;
    const succVal = selfVal - spentNow;

    if (spendNano < MIN_BOX_VALUE) throw new Error("spendNanoErg must be >= 0.001 ERG");
    if (succVal < minCarr) throw new Error(`Remaining vault value (${Number(succVal)/1e9} ERG) would fall below minCarrier (${Number(minCarr)/1e9} ERG). Use Cold Master Sweep instead!`);

    const newWindow = height >= winStart + winBlks;
    const effStart = newWindow ? height : winStart;
    const effSpent = newWindow ? spentNow : spentWin + spentNow;
    if (effSpent > limitErg) {
      throw new Error(
        `Daily hot cap exceeded! Effective spend ${(Number(effSpent)/1e9).toFixed(4)} ERG (incl. fee) > ` +
        `limit ${(Number(limitErg)/1e9).toFixed(4)} ERG. Wait until block #${(winStart + winBlks).toString()} or use Cold Master Override.`
      );
    }

    const recipDec = decodeAddress(params.recipientAddress);
    return {
      inputs: [box],
      dataInputs: [],
      outputs: [
        {
          value: succVal.toString(),
          ergoTree: box.ergoTree,
          assets: box.assets,
          additionalRegisters: {
            R4: hotHex,
            R5: coldHex,
            R6: Sigma.encodeLongArray([limitErg, winBlks, effStart, effSpent, minCarr])
          },
          creationHeight: Number(height)
        },
        {
          value: spendNano.toString(),
          ergoTree: recipDec.ergoTreeHex,
          assets: [],
          additionalRegisters: {},
          creationHeight: Number(height)
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: Number(height)
        }
      ]
    };
  }

  /**
   * 1-Click DailyLimitVault Cold Master Override Sweep (`mode = 1L`, `proveDlog(coldPk)`).
   */
  function buildEip12DailyColdSweepTx(params) {
    const box = normalizeBoxForEip12(params.vaultBox, { "0": Sigma.encodeLong(1n) });
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const outVal = BigInt(box.value) - feeNano;
    if (outVal < MIN_BOX_VALUE) throw new Error("Box value too small to cover miner fee.");
    const recipDec = decodeAddress(params.recipientAddress);
    const height = Number(params.creationHeight);
    return {
      inputs: [box],
      dataInputs: [],
      outputs: [
        {
          value: outVal.toString(),
          ergoTree: recipDec.ergoTreeHex,
          assets: box.assets,
          additionalRegisters: {},
          creationHeight: height
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: height
        }
      ]
    };
  }

  /**
   * 1-Click SocialRecoveryWallet Owner Spend (`mode = 0L`) OR 1-Block Instant Owner Veto (`mode = 2L`).
   */
  function buildEip12SocialOwnerTx(params) {
    const vetoMode = Boolean(params.vetoMode);
    const box = normalizeBoxForEip12(params.walletBox, { "0": Sigma.encodeLong(vetoMode ? 2n : 0n) });
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const outVal = BigInt(box.value) - feeNano;
    if (outVal < MIN_BOX_VALUE) throw new Error("Wallet box value too small to cover miner fee.");
    const height = Number(params.creationHeight);

    if (vetoMode) {
      const ownerHex = regHex(box, "R4");
      const guardHex = regHex(box, "R5");
      const stHex = regHex(box, "R7");
      const st = Sigma.decodeLongArray(stHex);
      return {
        inputs: [box],
        dataInputs: [],
        outputs: [
          {
            value: outVal.toString(),
            ergoTree: box.ergoTree,
            assets: box.assets,
            additionalRegisters: {
              R4: ownerHex,
              R5: guardHex,
              R6: ownerHex,
              R7: Sigma.encodeLongArray([0n, st[1], st[2], 0n])
            },
            creationHeight: height
          },
          {
            value: feeNano.toString(),
            ergoTree: MINER_FEE_ERGO_TREE,
            assets: [],
            additionalRegisters: {},
            creationHeight: height
          }
        ]
      };
    }

    const recipDec = decodeAddress(params.recipientAddress);
    return {
      inputs: [box],
      dataInputs: [],
      outputs: [
        {
          value: outVal.toString(),
          ergoTree: recipDec.ergoTreeHex,
          assets: box.assets,
          additionalRegisters: {},
          creationHeight: height
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: height
        }
      ]
    };
  }

  /**
   * 1-Click SocialRecoveryWallet Permissionless 0-Signature Recovery Finalize (`mode = 3L`).
   * Allowed by anyone once `HEIGHT >= unlockHeight` with ZERO signatures (`proofBytes = ""`).
   */
  function buildEip12SocialFinalizeTx(params) {
    const box = normalizeBoxForEip12(params.walletBox, { "0": Sigma.encodeLong(3n) });
    const guardHex = regHex(box, "R5");
    const propHex  = regHex(box, "R6");
    const stHex    = regHex(box, "R7");
    if (!guardHex || !propHex || !stHex) throw new Error("SocialRecoveryWallet box missing R5/R6/R7.");
    const st = Sigma.decodeLongArray(stHex);
    const [phase, threshold, delayBlks, unlockH] = st;
    const height = BigInt(params.creationHeight);
    if (phase !== 1n) throw new Error("Wallet is not in RECOVERY_PENDING state (phase must be 1).");
    if (height < unlockH) throw new Error(`Timelock not elapsed yet: height #${height} < unlockHeight #${unlockH} (${unlockH - height} blocks remaining).`);
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    if (feeNano > 2000000n) throw new Error("Finalize fee cap in SocialRecoveryWallet is 0.002 ERG (2,000,000 nanoERG).");
    const outVal = BigInt(box.value) - feeNano;
    return {
      inputs: [box],
      dataInputs: [],
      outputs: [
        {
          value: outVal.toString(),
          ergoTree: box.ergoTree,
          assets: box.assets,
          additionalRegisters: {
            R4: propHex,
            R5: guardHex,
            R6: propHex,
            R7: Sigma.encodeLongArray([0n, threshold, delayBlks, 0n])
          },
          creationHeight: Number(height)
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: Number(height)
        }
      ]
    };
  }

  /**
   * 1-Click ScriptlessAdaptorSwap (83 B PTLC) Maker Timeout Refund (Branch B: `HEIGHT >= refundHeight && proveDlog(makerPk)`).
   */
  function buildEip12PtlcRefundTx(params) {
    const box = normalizeBoxForEip12(params.swapBox, {});
    const refundH = Sigma.decodeLong(regHex(box, "R7"));
    const height = BigInt(params.creationHeight);
    if (height < refundH) {
      throw new Error(`PTLC timeout not reached yet: current height #${height} < refundHeight #${refundH} (${refundH - height} blocks remaining).`);
    }
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const outVal = BigInt(box.value) - feeNano;
    if (outVal < MIN_BOX_VALUE) throw new Error("Swap box value too small to cover miner fee.");
    const recipDec = decodeAddress(params.recipientAddress);
    return {
      inputs: [box],
      dataInputs: [],
      outputs: [
        {
          value: outVal.toString(),
          ergoTree: recipDec.ergoTreeHex,
          assets: box.assets,
          additionalRegisters: {},
          creationHeight: Number(height)
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: Number(height)
        }
      ]
    };
  }

  /**
   * 1-Click CrossChainHashSwap (255 B HTLC) Direct Claim (`mode = 0L`) OR Maker Timeout Refund (`mode = 2L`).
   */
  function buildEip12HtlcSpendTx(params) {
    const action = params.action || "refund"; // "claim" | "refund"
    const rawBox = normalizeBoxForEip12(params.swapBox, {});
    const cfg = Sigma.decodeLongArray(regHex(rawBox, "R7"));
    const refundH = cfg[0];
    const height = BigInt(params.creationHeight);
    const feeNano = BigInt(params.feeNanoErg != null ? params.feeNanoErg : DEFAULT_FEE);
    const outVal = BigInt(rawBox.value) - feeNano;
    if (outVal < MIN_BOX_VALUE) throw new Error("HTLC box value too small to cover miner fee.");
    const recipDec = decodeAddress(params.recipientAddress);

    if (action === "claim") {
      if (height >= refundH) throw new Error(`HTLC claim window expired: height #${height} >= refundHeight #${refundH}.`);
      const preStr = String(params.preimage || "").trim();
      const preBytes = /^(0x)?[0-9a-fA-F]{64}$/.test(preStr) ? fromHex(preStr) : new TextEncoder().encode(preStr);
      if (preBytes.length !== 32) {
        throw new Error(`CrossChainHashSwap enforces strict 32-byte preimage length (got ${preBytes.length} bytes).`);
      }
      rawBox.extension = {
        "0": Sigma.encodeLong(0n),
        "1": Sigma.encodeByteArray(preBytes)
      };
    } else {
      if (height < refundH) {
        throw new Error(`HTLC timeout not reached yet: current height #${height} < refundHeight #${refundH} (${refundH - height} blocks remaining).`);
      }
      rawBox.extension = {}; // contract defaults getVar[Long](0).getOrElse(2L)
    }

    return {
      inputs: [rawBox],
      dataInputs: [],
      outputs: [
        {
          value: outVal.toString(),
          ergoTree: recipDec.ergoTreeHex,
          assets: rawBox.assets,
          additionalRegisters: {},
          creationHeight: Number(height)
        },
        {
          value: feeNano.toString(),
          ergoTree: MINER_FEE_ERGO_TREE,
          assets: [],
          additionalRegisters: {},
          creationHeight: Number(height)
        }
      ]
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
    VERSION: "1.2.0",
    DEFAULT_TESTNET_API,
    DEFAULT_LOCAL_NODE,
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
    regHex,
    normalizeBoxForEip12,
    fetchNetworkState,
    fetchBestNetworkState,
    fetchUnspentBoxes,
    submitSignedTx,
    connectNautilus,
    buildEip12LockTx,
    buildEip12DailyHotSpendTx,
    buildEip12DailyColdSweepTx,
    buildEip12SocialOwnerTx,
    buildEip12SocialFinalizeTx,
    buildEip12PtlcRefundTx,
    buildEip12HtlcSpendTx,
    signAndSubmitNautilus
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.ErgoTestnetKit = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
