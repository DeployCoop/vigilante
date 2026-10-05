import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Cyclical De Bruijn Pattern Generator (like pwntools cyclic)
 * Uses 4-character permutations: Aa0Aa1...
 */
export function generateDeBruijnPattern(length = 256) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';

  let pattern = '';
  for (let u = 0; u < upper.length; u++) {
    for (let l = 0; l < lower.length; l++) {
      for (let d = 0; d < digits.length; d++) {
        pattern += upper[u] + lower[l] + digits[d];
        if (pattern.length >= length) {
          return pattern.slice(0, length);
        }
      }
    }
  }
  return pattern.slice(0, length);
}

/**
 * Finds the exact buffer overflow offset from a De Bruijn cyclic pattern
 * Handles hex addresses (e.g. 0x30614139) or ascii substrings
 */
export function findDeBruijnOffset(pattern, needle) {
  let pat = pattern;
  let target = needle;

  if (target === undefined) {
    target = pattern;
    pat = generateDeBruijnPattern(2048);
  }

  if (!pat || target === undefined || target === null) return -1;

  if (typeof target === 'number') {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(target, 0);
    const s = buf.toString('latin1').replace(/\0+$/, '');
    const idx = pat.indexOf(s);
    if (idx !== -1) return idx;
  }

  if (typeof target === 'string') {
    if (target.startsWith('0x') || target.startsWith('0X')) {
      let clean = target.slice(2).replace(/^(?:00)+/, '');
      if (clean.length % 2 !== 0) clean = '0' + clean;
      const b1 = Buffer.from(clean, 'hex');
      const b2 = Buffer.from(b1).reverse();
      const s1 = b1.toString('latin1');
      const s2 = b2.toString('latin1');
      if (pat.indexOf(s2) !== -1) return pat.indexOf(s2);
      if (pat.indexOf(s1) !== -1) return pat.indexOf(s1);
    } else {
      return pat.indexOf(target);
    }
  }

  return -1;
}

/**
 * Inspects ELF binary headers for security mitigations (checksec)
 */
export async function checksec(binaryPathOrBuffer) {
  let buf;
  if (typeof binaryPathOrBuffer === 'string') {
    buf = await fs.readFile(binaryPathOrBuffer);
  } else if (Buffer.isBuffer(binaryPathOrBuffer)) {
    buf = binaryPathOrBuffer;
  } else {
    throw new Error('Expected file path or Buffer for checksec');
  }

  // Validate ELF magic: \x7fELF
  if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return {
      isElf: false,
      summary: 'Not a valid ELF binary'
    };
  }

  const is64 = buf[4] === 2;
  const isLittleEndian = buf[5] === 1;
  const e_type = isLittleEndian ? buf.readUInt16LE(16) : buf.readUInt16BE(16);

  // Read Program Headers
  const phoff = is64
    ? (isLittleEndian ? Number(buf.readBigUInt64LE(32)) : Number(buf.readBigUInt64BE(32)))
    : (isLittleEndian ? buf.readUInt32LE(28) : buf.readUInt32BE(28));
  const phentsize = isLittleEndian ? buf.readUInt16LE(is64 ? 54 : 42) : buf.readUInt16BE(is64 ? 54 : 42);
  const phnum = isLittleEndian ? buf.readUInt16LE(is64 ? 56 : 44) : buf.readUInt16BE(is64 ? 56 : 44);

  let hasGnuRelro = false;
  let hasGnuStack = false;
  let isStackExecutable = false;

  for (let i = 0; i < phnum; i++) {
    const offset = phoff + i * phentsize;
    if (offset + phentsize > buf.length) break;

    const p_type = isLittleEndian ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);

    // PT_GNU_RELRO = 0x6474e552
    if (p_type === 0x6474e552) {
      hasGnuRelro = true;
    }
    // PT_GNU_STACK = 0x6474e551
    if (p_type === 0x6474e551) {
      hasGnuStack = true;
      const flagsOffset = is64 ? offset + 4 : offset + 24;
      const p_flags = isLittleEndian ? buf.readUInt32LE(flagsOffset) : buf.readUInt32BE(flagsOffset);
      // PF_X = 1
      isStackExecutable = (p_flags & 1) !== 0;
    }
  }

  // Canary check: search for __stack_chk_fail in binary string table
  const binaryString = buf.toString('latin1');
  const hasCanary = binaryString.includes('__stack_chk_fail');

  // PIE check: ET_DYN (3) indicates shared library or PIE; ET_EXEC (2) is no-PIE
  const isPie = e_type === 3;

  // NX: enabled if GNU_STACK is present and non-executable
  const isNx = hasGnuStack && !isStackExecutable;

  // RELRO classification
  let relro = 'No RELRO';
  if (hasGnuRelro) {
    // Check if BIND_NOW tag is in dynamic section
    relro = binaryString.includes('BIND_NOW') ? 'Full RELRO' : 'Partial RELRO';
  }

  return {
    isElf: true,
    arch: is64 ? 'x86_64' : 'x86',
    bits: is64 ? 64 : 32,
    endian: isLittleEndian ? 'little' : 'big',
    relro,
    canary: hasCanary,
    nx: isNx,
    pie: isPie,
    summary: `Arch: ${is64 ? 'amd64' : 'i386'} | RELRO: ${relro} | Stack Canary: ${hasCanary ? '✔ Found' : '✖ None'} | NX: ${isNx ? '✔ Enabled' : '✖ Disabled'} | PIE: ${isPie ? '✔ PIE' : '✖ No PIE'}`
  };
}

/**
 * Automatically inspects, classifies, and decodes ciphertext or encoded strings
 */
export function autoIdentifyCipher(input) {
  if (!input || typeof input !== 'string') return [];
  const text = input.trim();
  const candidates = [];

  // 1. Base64
  const b64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (text.length >= 4 && text.length % 4 === 0 && b64Regex.test(text)) {
    try {
      const decoded = Buffer.from(text, 'base64').toString('utf8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
        candidates.push({ type: 'Base64', decoded, confidence: 'High' });
      }
    } catch { /* skip */ }
  }

  // 2. Hexadecimal
  const hexRegex = /^[0-9a-fA-F]+$/;
  if (text.length >= 4 && text.length % 2 === 0 && hexRegex.test(text)) {
    try {
      const decoded = Buffer.from(text, 'hex').toString('utf8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
        candidates.push({ type: 'Hex (ASCII)', decoded, confidence: 'High' });
      }
    } catch { /* skip */ }

    // Check specific hash lengths
    if (text.length === 32) candidates.push({ type: 'MD5 Hash', confidence: 'Medium' });
    if (text.length === 40) candidates.push({ type: 'SHA-1 Hash', confidence: 'Medium' });
    if (text.length === 64) candidates.push({ type: 'SHA-256 Hash', confidence: 'High' });
  }

  // 3. JWT Token
  const jwtParts = text.split('.');
  if (jwtParts.length === 3) {
    try {
      const header = JSON.parse(Buffer.from(jwtParts[0], 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString('utf8'));
      candidates.push({
        type: 'JSON Web Token (JWT)',
        header,
        payload,
        isAlgNone: (header.alg || '').toLowerCase() === 'none',
        confidence: 'Definite'
      });
    } catch { /* skip */ }
  }

  // 4. ROT13 / Caesar preview
  const rot13 = text.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
  });
  if (rot13.toLowerCase().includes('flag') || rot13.toLowerCase().includes('vigilante')) {
    candidates.push({ type: 'ROT13', decoded: rot13, confidence: 'High' });
  }

  // 5. URL Encoding
  if (text.includes('%') && /%[0-9a-fA-F]{2}/.test(text)) {
    try {
      const decoded = decodeURIComponent(text);
      candidates.push({ type: 'URL Encoded', decoded, confidence: 'High' });
    } catch { /* skip */ }
  }

  return candidates;
}

/**
 * Decodes and analyzes a JWT token for vulnerabilities (e.g. alg: none)
 */
export function parseJwt(token) {
  if (!token || typeof token !== 'string') throw new Error('JWT string required');
  const parts = token.trim().split('.');
  if (parts.length < 2) throw new Error('Invalid JWT format (expected at least header.payload)');

  const headerRaw = Buffer.from(parts[0], 'base64url').toString('utf8');
  const payloadRaw = Buffer.from(parts[1], 'base64url').toString('utf8');

  const header = JSON.parse(headerRaw);
  const payload = JSON.parse(payloadRaw);

  const vulnerabilities = [];
  if ((header.alg || '').toLowerCase() === 'none') {
    vulnerabilities.push('CRITICAL: JWT allows "none" algorithm (Signature verification bypass)');
  }
  if ((header.alg || '').startsWith('HS') && header.typ === 'JWT') {
    vulnerabilities.push('INFO: Symmetric HMAC signature - test for weak secret or brute force');
  }

  return {
    header,
    payload,
    signature: parts[2] || null,
    vulnerabilities
  };
}

/**
 * Reused keystream / Many-Time-Pad XOR crib dragging utility
 */
export function dragXorCrib(hexCiphertext1, hexCiphertext2, crib) {
  const buf1 = Buffer.from(hexCiphertext1.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  const buf2 = Buffer.from(hexCiphertext2.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  const minLen = Math.min(buf1.length, buf2.length);

  // XOR ciphertexts together: C1 ^ C2 = P1 ^ P2
  const xorDiff = Buffer.alloc(minLen);
  for (let i = 0; i < minLen; i++) {
    xorDiff[i] = buf1[i] ^ buf2[i];
  }

  const cribBuf = Buffer.from(crib, 'utf8');
  const results = [];

  for (let i = 0; i <= minLen - cribBuf.length; i++) {
    const candidate = Buffer.alloc(cribBuf.length);
    for (let j = 0; j < cribBuf.length; j++) {
      candidate[j] = xorDiff[i + j] ^ cribBuf[j];
    }
    const candidateStr = candidate.toString('latin1');
    // Only accept printable ASCII
    if (/^[\x20-\x7E]+$/.test(candidateStr)) {
      results.push({
        offset: i,
        crib,
        revealedPlaintext: candidateStr
      });
    }
  }

  return { minLength: minLen, matches: results };
}

// ==============================================================================
// Advanced CTF Solver Workbench: ROP, Format String, Padding Oracle & RSA Math
// ==============================================================================

export const X86_64_ROP_GADGETS = [
  { mnemonic: 'pop rdi; ret', bytes: Buffer.from([0x5f, 0xc3]), description: 'First argument in System V AMD64 ABI' },
  { mnemonic: 'pop rsi; pop rdx; ret', bytes: Buffer.from([0x5e, 0x5a, 0xc3]), description: 'Second and third function arguments' },
  { mnemonic: 'pop rsi; ret', bytes: Buffer.from([0x5e, 0xc3]), description: 'Second function argument' },
  { mnemonic: 'pop rdx; ret', bytes: Buffer.from([0x5a, 0xc3]), description: 'Third function argument' },
  { mnemonic: 'pop rax; ret', bytes: Buffer.from([0x58, 0xc3]), description: 'Syscall number / return register' },
  { mnemonic: 'pop rbx; ret', bytes: Buffer.from([0x5b, 0xc3]), description: 'Preserved register rbx' },
  { mnemonic: 'pop rbp; ret', bytes: Buffer.from([0x5d, 0xc3]), description: 'Stack frame base pointer' },
  { mnemonic: 'syscall; ret', bytes: Buffer.from([0x0f, 0x05, 0xc3]), description: 'Kernel syscall transition and return' },
  { mnemonic: 'syscall', bytes: Buffer.from([0x0f, 0x05]), description: 'Kernel syscall transition' },
  { mnemonic: 'ret', bytes: Buffer.from([0xc3]), description: 'Return / 16-byte stack alignment' },
  { mnemonic: 'jmp rsp', bytes: Buffer.from([0xff, 0xe4]), description: 'Jump to stack payload' },
  { mnemonic: 'call rsp', bytes: Buffer.from([0xff, 0xd4]), description: 'Call stack payload' }
];

/**
 * Scans an ELF executable buffer for x86_64 Return-Oriented Programming (ROP) gadgets
 */
export function findRopGadgets({
  binaryBuffer,
  targetGadgets = null
} = {}) {
  if (!binaryBuffer || !Buffer.isBuffer(binaryBuffer)) {
    throw new Error('Valid binary Buffer is required for ROP gadget scanning');
  }

  const targets = targetGadgets
    ? X86_64_ROP_GADGETS.filter(g => targetGadgets.includes(g.mnemonic))
    : X86_64_ROP_GADGETS;

  const foundGadgets = [];

  for (const gadget of targets) {
    const pattern = gadget.bytes;
    let offset = 0;

    while ((offset = binaryBuffer.indexOf(pattern, offset)) !== -1) {
      foundGadgets.push({
        mnemonic: gadget.mnemonic,
        description: gadget.description,
        offset,
        offsetHex: '0x' + offset.toString(16),
        opcodeHex: pattern.toString('hex')
      });
      offset += pattern.length;
    }
  }

  // Sort by offset
  foundGadgets.sort((a, b) => a.offset - b.offset);

  return {
    totalFound: foundGadgets.length,
    gadgets: foundGadgets
  };
}

/**
 * Diagnostic helper to determine format string direct parameter access offset
 */
export async function findFormatStringOffset({
  probeFn,
  maxDepth = 30,
  marker = 'V1G1'
} = {}) {
  if (typeof probeFn !== 'function') {
    throw new Error('probeFn async callback required for format string probing');
  }

  const markerBuf = Buffer.from(marker, 'ascii');
  const markerHexBig = markerBuf.toString('hex').toLowerCase();
  const markerHexLittle = Buffer.from(markerBuf).reverse().toString('hex').toLowerCase();

  for (let i = 1; i <= maxDepth; i++) {
    const payload = `${marker}.%${i}$p`;
    const response = await probeFn(payload);
    const respStr = String(response || '').toLowerCase();

    // Check if the hex representation of our marker is leaked
    if (respStr.includes(markerHexLittle) || respStr.includes(markerHexBig) || respStr.includes(marker.toLowerCase())) {
      return {
        matched: true,
        offset: i,
        parameter: `%${i}$p`,
        marker,
        markerHexLittle: '0x' + markerHexLittle,
        response: String(response)
      };
    }
  }

  return {
    matched: false,
    maxDepthScanned: maxDepth
  };
}

/**
 * Diagnostic helper to detect PKCS#7 CBC padding oracle vulnerability
 */
export async function testPaddingOracle({
  probeFn,
  ciphertextHex,
  blockSize = 16
} = {}) {
  if (typeof probeFn !== 'function') {
    throw new Error('probeFn async callback is required');
  }

  const ct = Buffer.from(ciphertextHex.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  if (ct.length < blockSize * 2) {
    throw new Error(`Ciphertext must be at least 2 blocks (${blockSize * 2} bytes)`);
  }

  // 1. Establish baseline response for authentic ciphertext
  const baseline = await probeFn(ct.toString('hex'));

  // 2. Corrupt last byte of penultimate block (which directly alters plaintext of last block's padding)
  const targetIndex = ct.length - blockSize - 1;
  const originalByte = ct[targetIndex];

  let detectedAnomalies = 0;
  const observations = [];

  for (const xorVal of [0x01, 0x55, 0xff]) {
    const mutated = Buffer.from(ct);
    mutated[targetIndex] = originalByte ^ xorVal;

    const probeRes = await probeFn(mutated.toString('hex'));
    const isDifferent =
      probeRes?.valid !== baseline?.valid ||
      probeRes?.status !== baseline?.status ||
      probeRes?.body !== baseline?.body;

    if (isDifferent) {
      detectedAnomalies++;
      observations.push({
        xorVal: '0x' + xorVal.toString(16),
        probeStatus: probeRes?.status,
        baselineStatus: baseline?.status,
        responseMessage: probeRes?.body || probeRes?.message || ''
      });
    }
  }

  const isVulnerable = detectedAnomalies > 0;
  return {
    vulnerable: isVulnerable,
    confidence: detectedAnomalies >= 2 ? 'HIGH' : detectedAnomalies === 1 ? 'MEDIUM' : 'NONE',
    detectedAnomalies,
    observations,
    recommendation: isVulnerable
      ? 'VULNERABILITY CONFIRMED: Target leaks padding validity through response differential. Use CBC byte-by-byte decryption.'
      : 'No padding oracle detected under tested modifications.'
  };
}

/**
 * Computes integer square root for BigInt
 */
export function bigIntSqrt(value) {
  if (value < 0n) throw new Error('Square root of negative BigInt is not real');
  if (value === 0n) return 0n;
  if (value <= 3n) return 1n;

  let x0 = value / 2n;
  let x1 = (x0 + value / x0) / 2n;
  while (x1 < x0) {
    x0 = x1;
    x1 = (x0 + value / x0) / 2n;
  }
  return x0;
}

/**
 * Computes modular multiplicative inverse of a mod m
 */
export function modInverseBigInt(a, m) {
  let [m0, x0, x1] = [m, 0n, 1n];
  let currentA = a % m;
  if (currentA < 0n) currentA += m;

  if (m === 1n) return 0n;

  while (currentA > 1n) {
    if (m0 === 0n) return null; // Not invertible
    const q = currentA / m0;
    let t = m0;
    m0 = currentA % m0;
    currentA = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }

  if (x1 < 0n) x1 += m;
  return x1;
}

/**
 * Comprehensive RSA Weak Prime Analyzer: Trial Division, Fermat Factorization & Wiener Attack
 */
export function rsaWeakPrimes({
  n,
  e = 65537n,
  method = 'all'
} = {}) {
  const bigN = typeof n === 'bigint' ? n : BigInt(String(n));
  const bigE = typeof e === 'bigint' ? e : BigInt(String(e));

  if (bigN <= 3n) {
    return { factorized: false, reason: 'Modulus too small' };
  }

  // --------------------------------------------------------------------------
  // Method 1: Small Prime Trial Division (< 100,000)
  // --------------------------------------------------------------------------
  if (method === 'all' || method === 'trial_division') {
    if (bigN % 2n === 0n) {
      const p = 2n;
      const q = bigN / 2n;
      const phi = (p - 1n) * (q - 1n);
      const d = modInverseBigInt(bigE, phi);
      return {
        factorized: true,
        method: 'trial_division',
        p: p.toString(),
        q: q.toString(),
        phi: phi.toString(),
        d: d ? d.toString() : null
      };
    }

    for (let div = 3n; div <= 100000n; div += 2n) {
      if (bigN % div === 0n) {
        const p = div;
        const q = bigN / div;
        const phi = (p - 1n) * (q - 1n);
        const d = modInverseBigInt(bigE, phi);
        return {
          factorized: true,
          method: 'trial_division',
          p: p.toString(),
          q: q.toString(),
          phi: phi.toString(),
          d: d ? d.toString() : null
        };
      }
    }
  }

  // --------------------------------------------------------------------------
  // Method 2: Fermat Factorization (Close primes |p - q| < 2^32)
  // --------------------------------------------------------------------------
  if (method === 'all' || method === 'fermat') {
    let a = bigIntSqrt(bigN);
    if (a * a < bigN) a += 1n;

    for (let step = 0; step < 100000; step++) {
      const b2 = a * a - bigN;
      const b = bigIntSqrt(b2);
      if (b * b === b2) {
        const p = a + b;
        const q = a - b;
        if (p * q === bigN && p > 1n && q > 1n) {
          const phi = (p - 1n) * (q - 1n);
          const d = modInverseBigInt(bigE, phi);
          return {
            factorized: true,
            method: 'fermat',
            p: p.toString(),
            q: q.toString(),
            phi: phi.toString(),
            d: d ? d.toString() : null
          };
        }
      }
      a += 1n;
    }
  }

  // --------------------------------------------------------------------------
  // Method 3: Wiener's Small Private Exponent Attack (d < 1/3 * N^0.25)
  // --------------------------------------------------------------------------
  if (method === 'all' || method === 'wiener') {
    // Generate continued fraction expansion of e / N
    const quotients = [];
    let num = bigE;
    let den = bigN;

    while (den !== 0n && quotients.length < 200) {
      const q = num / den;
      quotients.push(q);
      const rem = num % den;
      num = den;
      den = rem;
    }

    // Evaluate convergents k / d using standard forward recurrence
    let hPrev2 = 0n, hPrev1 = 1n;
    let kPrev2 = 1n, kPrev1 = 0n;

    for (let i = 0; i < quotients.length; i++) {
      const q_i = quotients[i];
      const h_i = q_i * hPrev1 + hPrev2;
      const k_i = q_i * kPrev1 + kPrev2;
      hPrev2 = hPrev1;
      hPrev1 = h_i;
      kPrev2 = kPrev1;
      kPrev1 = k_i;

      const k = h_i;
      const candD = k_i;

      if (k === 0n || candD === 0n) continue;

      // Check if (e * d - 1) % k === 0
      const edMinus1 = bigE * candD - 1n;
      if (edMinus1 % k === 0n) {
        const phi = edMinus1 / k;
        // Solve x^2 - (N - phi + 1)x + N = 0
        const s = bigN - phi + 1n;
        const discriminant = s * s - 4n * bigN;

        if (discriminant >= 0n) {
          const discSqrt = bigIntSqrt(discriminant);
          if (discSqrt * discSqrt === discriminant) {
            const root1 = (s + discSqrt) / 2n;
            const root2 = (s - discSqrt) / 2n;

            if (root1 * root2 === bigN && root1 > 1n && root2 > 1n) {
              return {
                factorized: true,
                method: 'wiener',
                p: root1.toString(),
                q: root2.toString(),
                phi: phi.toString(),
                d: candD.toString()
              };
            }
          }
        }
      }
    }
  }

  return {
    factorized: false,
    message: 'Composite modulus resisted trial division, Fermat factorization, and Wiener small-d attack'
  };
}
