import assert from 'node:assert';
import {
  SOCRATIC_TIER_CONFIG,
  getSocraticHintTier,
  parseCrashContext,
  sanitizeSocraticResponse
} from '../src/engine/llm.js';
import { generateDeBruijnPattern } from '../src/engine/ctf-tools.js';

console.log('🧪 Testing 3-Tier Socratic Hint System & Crash Context Analyzer...');

// --------------------------------------------------------------------------
// Test 1: Socratic Tier Definitions & Penalty Scale
// --------------------------------------------------------------------------
assert.strictEqual(SOCRATIC_TIER_CONFIG[1].penaltyPercent, 0, 'Tier 1 must have 0% point penalty');
assert.strictEqual(SOCRATIC_TIER_CONFIG[1].name, 'Conceptual Recon');

assert.strictEqual(SOCRATIC_TIER_CONFIG[2].penaltyPercent, 10, 'Tier 2 must have 10% point penalty');
assert.strictEqual(SOCRATIC_TIER_CONFIG[2].name, 'Socratic Probes');

assert.strictEqual(SOCRATIC_TIER_CONFIG[3].penaltyPercent, 25, 'Tier 3 must have 25% point penalty');
assert.strictEqual(SOCRATIC_TIER_CONFIG[3].name, 'Diagnostic Tooling');
console.log('✔ Test 1 passed: 3-Tier Socratic hint configuration and penalty scales validated.');

// --------------------------------------------------------------------------
// Test 2: Flag Sanitization Guardrail
// --------------------------------------------------------------------------
const leakyText = 'Here is the key: VIGILANTE{accidental_flag_leak_here} and also FLAG{another_leak}';
const cleaned = sanitizeSocraticResponse(leakyText);
assert.ok(!cleaned.includes('VIGILANTE{'), 'Raw VIGILANTE flag must be redacted');
assert.ok(!cleaned.includes('FLAG{'), 'Raw FLAG must be redacted');
assert.ok(cleaned.includes('[REDACTED_BY_SOCRATIC_MENTOR_GUARDRAIL]'));
console.log('✔ Test 2 passed: Flag redaction guardrail strictly eliminates flag leaks.');

// --------------------------------------------------------------------------
// Test 3: Crash Parser - ASCII Overwrite (0x41414141 Buffer Overflow)
// --------------------------------------------------------------------------
const gdbCrashAscii = `
Program received signal SIGSEGV, Segmentation fault.
0x0000000041414141 in ?? ()
rax: 0x0000000000000000  rbx: 0x0000000000000000  rcx: 0x00007ffff7fa8740
rdx: 0x00007fffffffe200  rsi: 0x00007fffffffe200  rdi: 0x0000000000000000
rbp: 0x4141414141414141  rsp: 0x00007fffffffe2b8  rip: 0x0000000041414141
`;

const resAscii = parseCrashContext({ crashLog: gdbCrashAscii });
assert.strictEqual(resAscii.signal, 'SIGSEGV (Segmentation Fault)');
assert.strictEqual(resAscii.crashType, 'BUFFER_OVERFLOW_CONTROL_HIJACK');
assert.strictEqual(resAscii.registers.rip, '0x0000000041414141');
assert.strictEqual(resAscii.registers.rbp, '0x4141414141414141');
assert.ok(resAscii.diagnosisExplanation.includes('overwritten directly with user-controlled ASCII'));
assert.ok(resAscii.socraticQuestions.length >= 2);
console.log('✔ Test 3 passed: GDB ASCII stack overwrite diagnosed with Socratic guided questions.');

// --------------------------------------------------------------------------
// Test 4: Crash Parser - De Bruijn Cyclic Pattern Match
// --------------------------------------------------------------------------
// Generate pattern: 'Aa0Aa1Aa2Aa3Aa4Aa5...'
// At offset 12: 'Aa4A' -> in ASCII little-endian: 0x41346141
const gdbCrashCyclic = `
Stopped reason: SIGSEGV
$rip : 0x0000000041346141
$rsp : 0x00007fffffffe300
`;

const resCyclic = parseCrashContext({ crashLog: gdbCrashCyclic });
assert.strictEqual(resCyclic.signal, 'SIGSEGV (Segmentation Fault)');
assert.strictEqual(resCyclic.crashType, 'CYCLIC_BUFFER_OVERFLOW_CONFIRMED');
assert.strictEqual(resCyclic.deBruijnOffset, 12);
assert.ok(resCyclic.diagnosisExplanation.includes('buffer overflow offset is 12 bytes'));
console.log('✔ Test 4 passed: De Bruijn cyclic crash correctly resolved exact 12-byte buffer offset.');

// --------------------------------------------------------------------------
// Test 5: Crash Parser - Null Pointer Dereference
// --------------------------------------------------------------------------
const gdbNullDeref = `
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401150 in parse_token (token=0x0) at vuln.c:42
fault address: 0x0
`;

const resNull = parseCrashContext({ crashLog: gdbNullDeref });
assert.strictEqual(resNull.crashType, 'NULL_POINTER_DEREFERENCE');
assert.strictEqual(resNull.faultAddress, '0x0');
assert.ok(resNull.diagnosisExplanation.includes('null pointer'));
console.log('✔ Test 5 passed: Null pointer dereference accurately classified.');

// --------------------------------------------------------------------------
// Test 6: Crash Parser - Python Unhandled Exception Traceback
// --------------------------------------------------------------------------
const pyTraceback = `
Traceback (most recent call last):
  File "server.py", line 45, in handle_request
    token = headers["X-Auth-Token"]
KeyError: 'X-Auth-Token'
`;

const resPy = parseCrashContext({ crashLog: pyTraceback });
assert.strictEqual(resPy.signal, 'Python Exception Traceback');
assert.strictEqual(resPy.crashType, 'UNHANDLED_PYTHON_EXCEPTION');
assert.ok(resPy.socraticQuestions.length >= 2);
console.log('✔ Test 6 passed: Python exception traceback parsed into debugging inquiries.');

console.log('\n🎉 All 3-Tier Socratic Hint & Crash Analyzer tests passed successfully!\n');
