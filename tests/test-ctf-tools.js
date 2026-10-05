import assert from 'node:assert';
import {
  generateDeBruijnPattern,
  findDeBruijnOffset,
  checksec,
  autoIdentifyCipher,
  parseJwt,
  dragXorCrib
} from '../src/engine/ctf-tools.js';

console.log('🧪 Testing CTF Participant Solver Utilities (checksec, cyclic, cipher, JWT, XOR)...');

// Test 1: De Bruijn cyclic pattern generation
const pattern = generateDeBruijnPattern(100);
assert.strictEqual(pattern.length, 100);
assert.ok(pattern.startsWith('Aa0Aa1Aa2'));
console.log('✔ Test 1 passed: De Bruijn pattern generated accurately.');

// Test 2: Find buffer overflow offset
// If EIP / RIP contains 'Aa3'
const offset = findDeBruijnOffset(pattern, 'Aa3');
assert.strictEqual(offset, 9);
// Hex address test (0x336141 = '3aA' in little endian: 'Aa3')
const offsetHex = findDeBruijnOffset(pattern, '0x416133');
assert.strictEqual(offsetHex, 9);
console.log(`✔ Test 2 passed: Found cyclic buffer overflow offset: ${offset}`);

// Test 3: Checksec on simulated 64-bit ELF binary
const fakeElf = Buffer.alloc(128);
fakeElf[0] = 0x7f; fakeElf[1] = 0x45; fakeElf[2] = 0x4c; fakeElf[3] = 0x46; // \x7fELF
fakeElf[4] = 2; // 64-bit
fakeElf[5] = 1; // Little-endian
fakeElf.writeUInt16LE(3, 16); // ET_DYN (PIE enabled)
fakeElf.write('__stack_chk_fail', 64, 'latin1'); // Stack Canary string

const sec = await checksec(fakeElf);
assert.strictEqual(sec.isElf, true);
assert.strictEqual(sec.arch, 'x86_64');
assert.strictEqual(sec.bits, 64);
assert.strictEqual(sec.canary, true, 'Canary must be detected');
assert.strictEqual(sec.pie, true, 'PIE must be detected');
console.log(`✔ Test 3 passed: checksec correctly parsed ELF headers (${sec.summary}).`);

// Test 4: Cipher auto-identification
const b64Input = Buffer.from('VIGILANTE{hidden_web_token}').toString('base64');
const ciphersB64 = autoIdentifyCipher(b64Input);
assert.ok(ciphersB64.some(c => c.type === 'Base64' && c.decoded.includes('VIGILANTE')));

const hexInput = Buffer.from('hello_world').toString('hex');
const ciphersHex = autoIdentifyCipher(hexInput);
assert.ok(ciphersHex.some(c => c.type === 'Hex (ASCII)' && c.decoded === 'hello_world'));

const rot13Input = 'IVTVYNAGR{synt_ebg13}'; // 'VIGILANTE{flag_rot13}'
const ciphersRot = autoIdentifyCipher(rot13Input);
assert.ok(ciphersRot.some(c => c.type === 'ROT13'));
console.log('✔ Test 4 passed: Auto-identification detected Base64, Hex, and ROT13 candidates.');

// Test 5: JWT parsing & vulnerability detection
const headerB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
const payloadB64 = Buffer.from(JSON.stringify({ user: 'admin', role: 'root' })).toString('base64url');
const jwtToken = `${headerB64}.${payloadB64}.`;

const jwtRes = parseJwt(jwtToken);
assert.strictEqual(jwtRes.payload.user, 'admin');
assert.ok(jwtRes.vulnerabilities.some(v => v.includes('none')), 'Must flag alg: none vulnerability');
console.log('✔ Test 5 passed: JWT parser extracted payload and flagged "alg: none" bypass.');

// Test 6: XOR Many-Time Pad crib dragging
const pt1 = 'SecretKeyOne';
const pt2 = 'AnotherSecret';
const key = 'MYSECRETKEY12'; // Reused key
const ct1 = Buffer.alloc(12);
const ct2 = Buffer.alloc(12);
for (let i = 0; i < 12; i++) {
  ct1[i] = pt1.charCodeAt(i) ^ key.charCodeAt(i);
  ct2[i] = pt2.charCodeAt(i) ^ key.charCodeAt(i);
}
const xorRes = dragXorCrib(ct1.toString('hex'), ct2.toString('hex'), 'Secret');
assert.ok(xorRes.matches.length > 0, 'Crib dragging must find matching crib offset');
console.log(`✔ Test 6 passed: XOR crib dragging revealed plaintext: '${xorRes.matches[0].revealedPlaintext}'.`);

console.log('\n🎉 All CTF Participant Solver Utilities tests passed successfully!\n');
