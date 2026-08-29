import { runPing, runBenchmark, runMtr, runCurlHeaders, runDnsLookup, isBinaryAvailable } from '../src/engine/diagnostics.js';

async function runTests() {
  console.log('🧪 Testing Host Network Diagnostics Engine (ping, ab, mtr, curl, dig)...');

  // Test 1: Binary detection
  const hasPing = await isBinaryAvailable('ping');
  const hasCurl = await isBinaryAvailable('curl');
  const hasDig = await isBinaryAvailable('dig');
  if (!hasPing) throw new Error('Expected ping binary to be available');
  if (!hasCurl) throw new Error('Expected curl binary to be available');
  console.log(`✔ Test 1 passed: isBinaryAvailable detected system tools (ping: ${hasPing}, curl: ${hasCurl}, dig: ${hasDig}).`);

  // Test 2: ICMP Ping against localhost
  const pingRes = await runPing('127.0.0.1', 2);
  if (!pingRes.success || !pingRes.output.includes('bytes from 127.0.0.1')) {
    throw new Error(`Ping failed or unexpected output: ${JSON.stringify(pingRes)}`);
  }
  console.log('✔ Test 2 passed: runPing executed ping -c 2 127.0.0.1 and measured RTT.');

  // Test 3: HTTP Benchmark against localhost
  const benchRes = await runBenchmark('127.0.0.1', { requests: 5, concurrency: 2 });
  if (!benchRes.success && !benchRes.output) {
    throw new Error(`Benchmark failed completely: ${JSON.stringify(benchRes)}`);
  }
  console.log(`✔ Test 3 passed: runBenchmark executed (${benchRes.tool}).`);

  // Test 4: HTTP Header & TLS Inspector (curl -I)
  const curlRes = await runCurlHeaders('127.0.0.1');
  if (!curlRes.command.includes('curl -I')) {
    throw new Error('Curl command structure incorrect');
  }
  console.log('✔ Test 4 passed: runCurlHeaders executed header inspection command.');

  // Test 5: DNS Resolution (dig)
  const digRes = await runDnsLookup('127.0.0.1');
  if (!digRes.command.includes('dig')) {
    throw new Error('DNS lookup command structure incorrect');
  }
  console.log('✔ Test 5 passed: runDnsLookup executed reverse PTR / DNS resolution.');

  // Test 6: MTR / Trace
  const mtrRes = await runMtr('127.0.0.1');
  if (!mtrRes.command.includes('127.0.0.1')) {
    throw new Error('MTR target incorrect');
  }
  console.log(`✔ Test 6 passed: runMtr executed route trace (${mtrRes.tool}).`);

  console.log('🎉 All Host Network Diagnostics Engine tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
