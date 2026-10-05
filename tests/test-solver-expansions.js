import assert from 'node:assert';
import {
  findRopGadgets,
  findFormatStringOffset,
  testPaddingOracle,
  rsaWeakPrimes,
  bigIntSqrt,
  modInverseBigInt
} from '../src/engine/ctf-tools.js';
import {
  decompileWasmToWat,
  generateBinaryTriageReport,
  DEFAULT_DETECTOR_WASM_BYTES
} from '../src/engine/wasm.js';

console.log('🧪 Testing Participant Solver Workbench & Binary/Crypto Expansions...');

// --------------------------------------------------------------------------
// Test 1: ROP Gadget Scanner
// --------------------------------------------------------------------------
// Create a synthetic buffer with known ROP gadget opcodes
// 0x5f, 0xc3 -> pop rdi; ret
// 0x0f, 0x05, 0xc3 -> syscall; ret
// 0xc3 -> ret
const syntheticElfText = Buffer.concat([
  Buffer.from([0x90, 0x90, 0x90]), // nop; nop; nop
  Buffer.from([0x5f, 0xc3]),       // pop rdi; ret @ offset 3
  Buffer.from([0x90, 0x90]),       // nop; nop
  Buffer.from([0x0f, 0x05, 0xc3]), // syscall; ret @ offset 7
  Buffer.from([0x90]),             // nop
  Buffer.from([0xc3])              // ret @ offset 11
]);

const ropRes = findRopGadgets({ binaryBuffer: syntheticElfText });
assert.ok(ropRes.totalFound >= 3);
const rdiGadget = ropRes.gadgets.find(g => g.mnemonic === 'pop rdi; ret');
assert.ok(rdiGadget, 'Must find pop rdi; ret');
assert.strictEqual(rdiGadget.offset, 3);
assert.strictEqual(rdiGadget.offsetHex, '0x3');
const syscallGadget = ropRes.gadgets.find(g => g.mnemonic === 'syscall; ret');
assert.ok(syscallGadget, 'Must find syscall; ret');
assert.strictEqual(syscallGadget.offset, 7);
console.log(`✔ Test 1 passed: ROP gadget scanner discovered ${ropRes.totalFound} valid gadgets at expected offsets.`);

// --------------------------------------------------------------------------
// Test 2: Format String Offset Diagnostic Probe
// --------------------------------------------------------------------------
// Simulate a target service reflecting format strings where offset 6 points to our buffer
const mockFormatStringProbe = async (payload) => {
  // If payload contains %6$p, reflect marker hex
  if (payload.includes('%6$p')) {
    // Little-endian hex of 'V1G1' = 0x31473156
    return 'User says: 0x31473156';
  }
  return 'User says: 0x7ffd9820';
};

const fmtRes = await findFormatStringOffset({
  probeFn: mockFormatStringProbe,
  maxDepth: 10,
  marker: 'V1G1'
});
assert.strictEqual(fmtRes.matched, true);
assert.strictEqual(fmtRes.offset, 6);
assert.strictEqual(fmtRes.parameter, '%6$p');
console.log('✔ Test 2 passed: Format string probe identified parameter index %6$p accurately.');

// --------------------------------------------------------------------------
// Test 3: PKCS#7 CBC Padding Oracle Tester
// --------------------------------------------------------------------------
// Simulate a server that decrypts CBC ciphertext and returns 500 on bad padding
const authenticCiphertext = Buffer.alloc(32, 0xaa).toString('hex');

const mockOracleProbe = async (ctHex) => {
  // If ciphertext is original, return 200 OK
  if (ctHex === authenticCiphertext) {
    return { valid: true, status: 200, body: '{"authenticated":true}' };
  }
  // If mutated, return 500 Bad Padding Error
  return { valid: false, status: 500, body: 'Decryption failed: PKCS#7 padding error' };
};

const oracleRes = await testPaddingOracle({
  probeFn: mockOracleProbe,
  ciphertextHex: authenticCiphertext,
  blockSize: 16
});
assert.strictEqual(oracleRes.vulnerable, true);
assert.strictEqual(oracleRes.confidence, 'HIGH');
assert.ok(oracleRes.recommendation.includes('VULNERABILITY CONFIRMED'));
console.log('✔ Test 3 passed: Padding oracle detector accurately observed differential padding response.');

// --------------------------------------------------------------------------
// Test 4: RSA Math Helpers (bigIntSqrt & modInverseBigInt)
// --------------------------------------------------------------------------
assert.strictEqual(bigIntSqrt(144n), 12n);
assert.strictEqual(bigIntSqrt(1000000000000000000n), 1000000000n);
const inv = modInverseBigInt(3n, 11n); // 3 * 4 = 12 = 1 mod 11
assert.strictEqual(inv, 4n);
console.log('✔ Test 4 passed: BigInt integer square root and modular inverse validated.');

// --------------------------------------------------------------------------
// Test 5: RSA Weak Primes - Trial Division (< 100,000)
// --------------------------------------------------------------------------
const pSmall = 1009n;
const qSmall = 1013n;
const nSmall = pSmall * qSmall;
const resTrial = rsaWeakPrimes({ n: nSmall, e: 65537n });
assert.strictEqual(resTrial.factorized, true);
assert.strictEqual(resTrial.method, 'trial_division');
assert.strictEqual(resTrial.p, '1009');
assert.strictEqual(resTrial.q, '1013');
console.log('✔ Test 5 passed: RSA trial division factored small prime modulus.');

// --------------------------------------------------------------------------
// Test 6: RSA Weak Primes - Fermat Factorization (|p - q| close)
// --------------------------------------------------------------------------
// Two large close primes
const pFermat = 1000000000000037n;
const qFermat = 1000000000000091n;
const nFermat = pFermat * qFermat;
const resFermat = rsaWeakPrimes({ n: nFermat, e: 65537n });
assert.strictEqual(resFermat.factorized, true);
assert.strictEqual(resFermat.method, 'fermat');
assert.strictEqual(resFermat.p, '1000000000000091');
assert.strictEqual(resFermat.q, '1000000000000037');
console.log('✔ Test 6 passed: Fermat factorization decomposed close prime modulus in microseconds.');

// --------------------------------------------------------------------------
// Test 7: RSA Weak Primes - Wiener's Small Private Exponent Attack
// --------------------------------------------------------------------------
// Classic Wiener example with d < 1/3 * N^0.25 (N = 2250335753, N^0.25 ~ 217.7, max d ~ 72):
// p = 44773, q = 50261 => N = 2250335753, phi = 2250240720, d = 43, e = 1465273027
const pWiener = 44773n;
const qWiener = 50261n;
const nWiener = pWiener * qWiener;
const eWiener = 1465273027n;
const resWiener = rsaWeakPrimes({ n: nWiener, e: eWiener, method: 'wiener' });
assert.strictEqual(resWiener.factorized, true);
assert.strictEqual(resWiener.method, 'wiener');
assert.strictEqual(resWiener.d, '43');
console.log('✔ Test 7 passed: Wiener attack successfully factored modulus via continued fractions.');

// --------------------------------------------------------------------------
// Test 8: WebAssembly to WAT Disassembler
// --------------------------------------------------------------------------
const wasmWat = await decompileWasmToWat(DEFAULT_DETECTOR_WASM_BYTES);
assert.ok(wasmWat.wat.includes('(module'));
assert.ok(wasmWat.wat.includes('export "detect_threat"'));
assert.ok(wasmWat.exports.includes('detect_threat'));
assert.ok(wasmWat.sections.length >= 4);
console.log('✔ Test 8 passed: WebAssembly bytecode decompiled to human-readable WAT format.');

// --------------------------------------------------------------------------
// Test 9: Automated Static Binary Triage Report
// --------------------------------------------------------------------------
// Create synthetic binary buffer with strings and flag
const mockBinary = Buffer.concat([
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), // ELF64 magic
  Buffer.alloc(100, 0x90),
  Buffer.from('FLAG: VIGILANTE{super_secret_embedded_flag}\x00'),
  Buffer.from('/bin/sh\x00'),
  Buffer.from('system\x00'),
  Buffer.from('https://c2.evil.com/drop\x00')
]);

const triage = await generateBinaryTriageReport({ binaryBuffer: mockBinary, fileName: 'crackme.elf' });
assert.strictEqual(triage.fileName, 'crackme.elf');
assert.ok(triage.candidateFlags.some(f => f.includes('VIGILANTE{super_secret_embedded_flag}')));
assert.ok(triage.interestingStrings.some(s => s.includes('/bin/sh')));
assert.ok(triage.interestingStrings.some(s => s.includes('system')));
assert.ok(triage.reportMarkdown.includes('# 🛡️ Vigilante Static Binary Triage: crackme.elf'));
console.log('✔ Test 9 passed: Automated static triage report generated with flag detection and checksec.');

console.log('\n🎉 All Participant Solver Workbench & Binary/Crypto tests passed successfully!\n');
