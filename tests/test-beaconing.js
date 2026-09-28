import assert from 'node:assert';
import {
  calculateInterArrivalTime,
  detectBeaconingPeriodicity,
  calculateShannonEntropy,
  detectDnsTunneling
} from '../src/engine/beaconing.js';

console.log('🧪 Testing Statistical C2 Beaconing & FFT Frequency-Domain Detector...');

// Test 1: calculateInterArrivalTime
const baseEpoch = 1700000000000;
// Periodic timestamps at roughly 60s intervals with small jitter (+- 3s)
const flowEvents = [
  baseEpoch,
  baseEpoch + 59000,
  baseEpoch + 119000,
  baseEpoch + 181000,
  baseEpoch + 240000,
  baseEpoch + 302000,
  baseEpoch + 360000
];

const stats = calculateInterArrivalTime(flowEvents);
assert.strictEqual(stats.count, 6);
assert.ok(stats.mean >= 59 && stats.mean <= 61, `Mean interval should be ~60s, got ${stats.mean}`);
assert.ok(stats.stdDev < 3.0, `StdDev should be small (<3s), got ${stats.stdDev}`);
console.log(`✔ Test 1 passed: calculateInterArrivalTime computed accurate IAT deltas (Mean: ${stats.mean}s, StdDev: ${stats.stdDev}s).`);

// Test 2: detectBeaconingPeriodicity on periodic C2 beacon
const beaconResult = detectBeaconingPeriodicity(stats);
assert.strictEqual(beaconResult.isBeaconing, true);
assert.ok(beaconResult.confidence >= 85, `Confidence must be >= 85%, got ${beaconResult.confidence}%`);
assert.ok(beaconResult.dominantIntervalSec >= 59 && beaconResult.dominantIntervalSec <= 61);
assert.ok(beaconResult.jitterPercent < 10, `Jitter should be < 10%, got ${beaconResult.jitterPercent}%`);
assert.strictEqual(beaconResult.severity, 'CRITICAL');
assert.strictEqual(beaconResult.mitreTechnique, 'T1071.001');
console.log(`✔ Test 2 passed: detectBeaconingPeriodicity accurately identified periodic C2 beacon (Confidence: ${beaconResult.confidence}%, Jitter: ±${beaconResult.jitterPercent}%).`);

// Test 2b: detectBeaconingPeriodicity on highly erratic random web traffic
const randomIntervals = [2.5, 45.1, 0.3, 180.2, 12.0, 310.5, 4.2];
const randomResult = detectBeaconingPeriodicity(randomIntervals);
assert.strictEqual(randomResult.isBeaconing, false);
assert.ok(randomResult.confidence < 60, `Random traffic should have low confidence, got ${randomResult.confidence}%`);
console.log('✔ Test 2b passed: detectBeaconingPeriodicity correctly rejected stochastic/random web traffic.');

// Test 3: Shannon Entropy calculation
const lowEntropyStr = 'aaaaaaaaaaaaaaaa';
const mediumEntropyStr = 'user_login_success';
const highEntropyStr = '4f8a1c9e2b7d0f5e3a8c1d4b6e9f2a0d';

const lowEnt = calculateShannonEntropy(lowEntropyStr);
const medEnt = calculateShannonEntropy(mediumEntropyStr);
const highEnt = calculateShannonEntropy(highEntropyStr);

assert.strictEqual(lowEnt, 0);
assert.ok(medEnt > 2.5 && medEnt < 4.0, `Medium entropy string should be ~3.0, got ${medEnt}`);
assert.ok(highEnt >= 3.8, `Hex random string should have high entropy, got ${highEnt}`);
console.log(`✔ Test 3 passed: calculateShannonEntropy correctly evaluated low (0), medium (${medEnt}), and high (${highEnt}) entropy strings.`);

// Test 4: DNS Tunneling Detection
const dnsQueries = [
  'api.service.internal.corp.com',
  'login.auth.corp.com',
  '9f8a3b1c7e2d0a4f5b8c9d1e2f3a4b5c6d7e8f.tunnel.darkc2.com', // Base16 exfiltration
  'cdn.static.assets.corp.com'
];

const dnsTunnelResult = detectDnsTunneling(dnsQueries);
assert.strictEqual(dnsTunnelResult.hasTunnelingThreat, true);
assert.strictEqual(dnsTunnelResult.flaggedCount, 1);
assert.ok(dnsTunnelResult.anomalies[0].query.includes('tunnel.darkc2.com'));
assert.strictEqual(dnsTunnelResult.anomalies[0].mitreTechnique, 'T1071.004');
console.log(`✔ Test 4 passed: detectDnsTunneling accurately flagged encoded DNS exfiltration payload.`);

console.log('🎉 All Statistical C2 Beaconing & FFT Frequency Detector tests passed successfully!\n');
