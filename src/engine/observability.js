/**
 * VIGILANTE eBPF Real-Time Syscall Observability & Network Socket Matrix
 * High-performance in-memory ring buffer, syscall stream processing,
 * network socket connection matrix, and lateral movement / anomalous egress detection.
 */

import { EventEmitter } from 'node:events';

/**
 * ObservabilityRingBuffer
 * High-performance circular buffer storing high-frequency syscall & network events.
 */
export class ObservabilityRingBuffer {
  constructor(capacity = 1000) {
    if (capacity <= 0) {
      throw new Error('Capacity must be a positive integer');
    }
    this.capacity = capacity;
    this.buffer = new Array(capacity);
    this.head = 0;
    this.tail = 0;
    this.count = 0;
  }

  /**
   * Push a new event into the circular buffer. Evicts oldest when full (FIFO).
   * @param {Object} event
   * @returns {Object} Added event with timestamp
   */
  push(event) {
    const enriched = {
      id: event.id || `evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: event.timestamp || new Date().toISOString(),
      ...event
    };

    this.buffer[this.head] = enriched;
    this.head = (this.head + 1) % this.capacity;

    if (this.count < this.capacity) {
      this.count++;
    } else {
      this.tail = (this.tail + 1) % this.capacity; // Evict oldest
    }

    return enriched;
  }

  /**
   * Get events from oldest to newest with optional filtering.
   * @param {Object} filter - { type, pod, namespace, pid, comm, limit }
   * @returns {Array<Object>}
   */
  getEvents(filter = {}) {
    const results = [];
    for (let i = 0; i < this.count; i++) {
      const idx = (this.tail + i) % this.capacity;
      const item = this.buffer[idx];
      if (!item) continue;

      if (filter.type && item.type !== filter.type && item.syscall !== filter.type) continue;
      if (filter.pod && item.pod !== filter.pod) continue;
      if (filter.namespace && item.namespace !== filter.namespace) continue;
      if (filter.pid !== undefined && item.pid !== filter.pid) continue;
      if (filter.comm && item.comm !== filter.comm) continue;

      results.push(item);
    }

    if (filter.limit && filter.limit > 0) {
      return results.slice(-filter.limit);
    }
    return results;
  }

  get size() {
    return this.count;
  }

  clear() {
    this.buffer = new Array(this.capacity);
    this.head = 0;
    this.tail = 0;
    this.count = 0;
  }

  /**
   * Summarize buffered events
   * @returns {Object}
   */
  getSummary() {
    const types = {};
    const pods = {};
    const namespaces = {};
    let errorCount = 0;

    for (let i = 0; i < this.count; i++) {
      const idx = (this.tail + i) % this.capacity;
      const item = this.buffer[idx];
      if (!item) continue;

      const t = item.syscall || item.type || 'unknown';
      types[t] = (types[t] || 0) + 1;

      if (item.pod) {
        pods[item.pod] = (pods[item.pod] || 0) + 1;
      }
      if (item.namespace) {
        namespaces[item.namespace] = (namespaces[item.namespace] || 0) + 1;
      }
      if (item.ret !== undefined && item.ret < 0) {
        errorCount++;
      }
    }

    return {
      totalEvents: this.count,
      capacity: this.capacity,
      utilizationPercent: Math.round((this.count / this.capacity) * 100),
      eventTypes: types,
      topPods: Object.entries(pods).sort((a, b) => b[1] - a[1]).slice(0, 5),
      namespaces,
      errorCount
    };
  }
}

/**
 * Builds a real-time matrix of pod-to-pod and pod-to-external IP/port socket connections.
 * @param {Array<Object>} networkEvents
 * @returns {Object} Matrix of connections and summary stats
 */
export function buildSocketConnectionMatrix(networkEvents = []) {
  const connectionMap = new Map();
  const summary = {
    totalConnections: 0,
    uniqueSources: new Set(),
    uniqueDestinations: new Set(),
    protocols: {},
    totalBytesSent: 0,
    totalBytesReceived: 0
  };

  for (const event of networkEvents) {
    const src = event.source || event.srcIp || event.saddr || 'unknown';
    const dst = event.destination || event.dstIp || event.daddr || 'unknown';
    const dstPort = Number(event.dstPort || event.dport || 0);
    const protocol = (event.protocol || event.proto || 'TCP').toUpperCase();
    const bytesSent = Number(event.bytesSent || event.bytes_sent || 0);
    const bytesReceived = Number(event.bytesReceived || event.bytes_recv || 0);

    const key = `${src}->${dst}:${dstPort}/${protocol}`;

    summary.uniqueSources.add(src);
    summary.uniqueDestinations.add(dst);
    summary.protocols[protocol] = (summary.protocols[protocol] || 0) + 1;
    summary.totalBytesSent += bytesSent;
    summary.totalBytesReceived += bytesReceived;
    summary.totalConnections++;

    if (connectionMap.has(key)) {
      const existing = connectionMap.get(key);
      existing.count += 1;
      existing.bytesSent += bytesSent;
      existing.bytesReceived += bytesReceived;
      existing.lastSeen = event.timestamp || new Date().toISOString();
      if (event.state) existing.state = event.state;
    } else {
      connectionMap.set(key, {
        key,
        source: src,
        destination: dst,
        dstPort,
        protocol,
        count: 1,
        bytesSent,
        bytesReceived,
        state: event.state || 'ESTABLISHED',
        firstSeen: event.timestamp || new Date().toISOString(),
        lastSeen: event.timestamp || new Date().toISOString(),
        pod: event.pod || null,
        namespace: event.namespace || null
      });
    }
  }

  return {
    connections: Array.from(connectionMap.values()),
    summary: {
      totalConnections: summary.totalConnections,
      uniqueSourcesCount: summary.uniqueSources.size,
      uniqueDestinationsCount: summary.uniqueDestinations.size,
      protocols: summary.protocols,
      totalBytesSent: summary.totalBytesSent,
      totalBytesReceived: summary.totalBytesReceived
    }
  };
}

/**
 * Detects anomalous socket connections comparing against a baseline of allowed connections.
 * @param {Object} matrix - Output from buildSocketConnectionMatrix
 * @param {Object} baseline - { allowedEgressPorts: [], allowedCidrs: [], crossNamespaceAllowed: false, maxByteThreshold: 10485760 }
 * @returns {Array<Object>} List of detected anomalies
 */
export function detectAnomalousSocketConnections(matrix, baseline = {}) {
  const anomalies = [];
  const connections = matrix?.connections || [];

  const allowedPorts = new Set(baseline.allowedEgressPorts || [80, 443, 53, 6443, 8080, 8443, 9090]);
  const suspiciousPorts = new Set([4444, 1337, 6667, 31337, 5555, 9999, 12345]);
  const maxByteThreshold = baseline.maxByteThreshold || 50 * 1024 * 1024; // 50MB default

  for (const conn of connections) {
    // 1. Check for suspicious backdoor / reverse shell ports
    if (suspiciousPorts.has(conn.dstPort)) {
      anomalies.push({
        severity: 'CRITICAL',
        type: 'SUSPICIOUS_REVERSE_SHELL_PORT',
        source: conn.source,
        destination: conn.destination,
        dstPort: conn.dstPort,
        protocol: conn.protocol,
        details: `Connection detected to known C2/reverse shell port ${conn.dstPort}`,
        recommendation: `Isolate source workload ${conn.pod || conn.source} and terminate network connection immediately.`,
        timestamp: conn.lastSeen
      });
    }

    // 2. Check for unexpected egress to non-standard ports
    if (!allowedPorts.has(conn.dstPort) && !suspiciousPorts.has(conn.dstPort)) {
      // Check if external destination
      const isInternal = isPrivateIp(conn.destination) || conn.destination.endsWith('.svc.cluster.local') || conn.destination === 'localhost' || conn.destination === '127.0.0.1';
      if (!isInternal) {
        anomalies.push({
          severity: 'HIGH',
          type: 'UNAUTHORIZED_EXTERNAL_EGRESS_PORT',
          source: conn.source,
          destination: conn.destination,
          dstPort: conn.dstPort,
          protocol: conn.protocol,
          details: `Egress to external IP ${conn.destination} on unapproved port ${conn.dstPort}`,
          recommendation: `Verify egress firewall rules and inspect process network sockets on ${conn.source}.`,
          timestamp: conn.lastSeen
        });
      }
    }

    // 3. Check for massive data exfiltration threshold
    const totalBytes = conn.bytesSent + conn.bytesReceived;
    if (totalBytes > maxByteThreshold) {
      anomalies.push({
        severity: 'HIGH',
        type: 'LARGE_DATA_TRANSFER_ANOMALY',
        source: conn.source,
        destination: conn.destination,
        dstPort: conn.dstPort,
        protocol: conn.protocol,
        details: `Connection transferred ${(totalBytes / (1024 * 1024)).toFixed(2)} MB exceeding threshold of ${(maxByteThreshold / (1024 * 1024)).toFixed(2)} MB`,
        recommendation: `Investigate potential data exfiltration from workload ${conn.source} to ${conn.destination}.`,
        timestamp: conn.lastSeen
      });
    }

    // 4. Check for unauthorized cross-namespace lateral movement
    if (baseline.crossNamespaceAllowed === false && conn.namespace && conn.destNamespace && conn.namespace !== conn.destNamespace) {
      anomalies.push({
        severity: 'MEDIUM',
        type: 'UNAUTHORIZED_CROSS_NAMESPACE_TRAFFIC',
        source: conn.source,
        destination: conn.destination,
        dstPort: conn.dstPort,
        details: `Workload in namespace '${conn.namespace}' attempted lateral connection to namespace '${conn.destNamespace}'`,
        recommendation: `Enforce Kubernetes NetworkPolicy default deny between namespaces.`,
        timestamp: conn.lastSeen
      });
    }
  }

  return anomalies;
}

/**
 * Check if IP is in RFC1918 private ranges
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    return second >= 16 && second <= 31;
  }
  return false;
}

/**
 * Stream live observability events (synthetic/eBPF probe harness)
 * @param {Object} options - { intervalMs, maxEvents }
 * @param {Function} onEvent - Callback invoked on each event
 * @returns {Object} Stream controller { stop: Function, ringBuffer: ObservabilityRingBuffer }
 */
export function streamLiveEvents(options = {}, onEvent) {
  const emitter = new EventEmitter();
  const ringBuffer = new ObservabilityRingBuffer(options.capacity || 500);
  const intervalMs = options.intervalMs || 500;
  let active = true;
  let timer = null;

  const syscalls = ['execve', 'connect', 'openat', 'setuid', 'ptrace', 'bpf', 'memfd_create'];
  const pods = ['auth-service-7f89d', 'api-gateway-3ab21', 'payment-db-0', 'ingress-nginx-99ac'];
  const namespaces = ['prod', 'default', 'kube-system', 'data'];

  timer = setInterval(() => {
    if (!active) {
      clearInterval(timer);
      return;
    }

    const syscall = syscalls[Math.floor(Math.random() * syscalls.length)];
    const pod = pods[Math.floor(Math.random() * pods.length)];
    const namespace = namespaces[Math.floor(Math.random() * namespaces.length)];

    const evt = {
      syscall,
      pod,
      namespace,
      pid: Math.floor(Math.random() * 30000) + 1000,
      comm: syscall === 'execve' ? 'bash' : 'node',
      ret: Math.random() > 0.1 ? 0 : -13, // 10% permission denied
      timestamp: new Date().toISOString()
    };

    if (syscall === 'connect') {
      evt.destination = '192.168.1.50';
      evt.dstPort = 443;
      evt.protocol = 'TCP';
      evt.bytesSent = Math.floor(Math.random() * 5000);
      evt.bytesReceived = Math.floor(Math.random() * 15000);
    }

    const recorded = ringBuffer.push(evt);
    if (typeof onEvent === 'function') {
      onEvent(recorded);
    }
    emitter.emit('event', recorded);
  }, intervalMs);

  return {
    ringBuffer,
    emitter,
    stop: () => {
      active = false;
      if (timer) clearInterval(timer);
    }
  };
}
