import assert from 'node:assert';
import {
  ObservabilityRingBuffer,
  buildSocketConnectionMatrix,
  detectAnomalousSocketConnections,
  streamLiveEvents
} from '../src/engine/observability.js';

console.log('🧪 Testing eBPF Real-Time Syscall Observability & Socket Matrix...');

// Test 1: ObservabilityRingBuffer circular capacity & FIFO eviction
const buffer = new ObservabilityRingBuffer(3);
assert.strictEqual(buffer.size, 0);
assert.strictEqual(buffer.capacity, 3);

buffer.push({ syscall: 'execve', pod: 'pod-a', pid: 101 });
buffer.push({ syscall: 'connect', pod: 'pod-b', pid: 102 });
buffer.push({ syscall: 'openat', pod: 'pod-c', pid: 103 });
assert.strictEqual(buffer.size, 3);

const events3 = buffer.getEvents();
assert.strictEqual(events3.length, 3);
assert.strictEqual(events3[0].syscall, 'execve');
assert.strictEqual(events3[2].syscall, 'openat');

// Push 4th event -> FIFO evicts 'execve'
buffer.push({ syscall: 'setuid', pod: 'pod-d', pid: 104 });
assert.strictEqual(buffer.size, 3);
const eventsAfterEvict = buffer.getEvents();
assert.strictEqual(eventsAfterEvict[0].syscall, 'connect');
assert.strictEqual(eventsAfterEvict[2].syscall, 'setuid');

// Filtering
const filtered = buffer.getEvents({ type: 'setuid' });
assert.strictEqual(filtered.length, 1);
assert.strictEqual(filtered[0].pod, 'pod-d');

const summary = buffer.getSummary();
assert.strictEqual(summary.totalEvents, 3);
assert.strictEqual(summary.utilizationPercent, 100);
console.log('✔ Test 1 passed: ObservabilityRingBuffer correctly enforces capacity, FIFO eviction, and event filtering.');

// Test 2: Build Socket Connection Matrix
const rawNetworkEvents = [
  { source: '10.244.1.5', destination: '10.244.2.10', dstPort: 5432, protocol: 'TCP', bytesSent: 1024, bytesReceived: 4096, pod: 'api-service' },
  { source: '10.244.1.5', destination: '10.244.2.10', dstPort: 5432, protocol: 'TCP', bytesSent: 2048, bytesReceived: 8192, pod: 'api-service' },
  { source: '10.244.1.12', destination: '198.51.100.22', dstPort: 4444, protocol: 'TCP', bytesSent: 500, bytesReceived: 200, pod: 'compromised-pod' },
  { source: '10.244.1.8', destination: '203.0.113.88', dstPort: 8888, protocol: 'TCP', bytesSent: 60 * 1024 * 1024, bytesReceived: 1024, pod: 'exfil-pod' }
];

const matrix = buildSocketConnectionMatrix(rawNetworkEvents);
assert.strictEqual(matrix.summary.totalConnections, 4);
assert.strictEqual(matrix.summary.uniqueSourcesCount, 3);
assert.strictEqual(matrix.summary.uniqueDestinationsCount, 3);
assert.strictEqual(matrix.connections.length, 3); // 2 aggregated + 2 distinct

const dbConn = matrix.connections.find(c => c.dstPort === 5432);
assert.ok(dbConn);
assert.strictEqual(dbConn.count, 2);
assert.strictEqual(dbConn.bytesSent, 3072);
assert.strictEqual(dbConn.bytesReceived, 12288);
console.log('✔ Test 2 passed: buildSocketConnectionMatrix correctly aggregates pod network sockets and byte volumes.');

// Test 3: Detect Anomalous Socket Connections
const anomalies = detectAnomalousSocketConnections(matrix, {
  allowedEgressPorts: [80, 443, 5432],
  maxByteThreshold: 10 * 1024 * 1024 // 10MB
});

assert.ok(anomalies.length >= 2, `Expected at least 2 anomalies, got ${anomalies.length}`);

// Reverse shell port 4444
const revShell = anomalies.find(a => a.type === 'SUSPICIOUS_REVERSE_SHELL_PORT');
assert.ok(revShell);
assert.strictEqual(revShell.severity, 'CRITICAL');
assert.strictEqual(revShell.dstPort, 4444);

// Exfiltration anomaly
const exfil = anomalies.find(a => a.type === 'LARGE_DATA_TRANSFER_ANOMALY');
assert.ok(exfil);
assert.strictEqual(exfil.severity, 'HIGH');
console.log('✔ Test 3 passed: detectAnomalousSocketConnections identified C2 reverse shell port and large data transfer.');

// Test 4: Live event streaming harness
let streamReceivedCount = 0;
const stream = streamLiveEvents({ intervalMs: 20, capacity: 50 }, (evt) => {
  streamReceivedCount++;
});

await new Promise(r => setTimeout(r, 90));
stream.stop();
assert.ok(streamReceivedCount >= 2, `Expected at least 2 streamed events, got ${streamReceivedCount}`);
assert.ok(stream.ringBuffer.size >= 2);
console.log('✔ Test 4 passed: streamLiveEvents delivered live events into ring buffer and invoked callbacks.');

console.log('🎉 All eBPF Real-Time Syscall Observability & Socket Matrix tests passed successfully!\n');
