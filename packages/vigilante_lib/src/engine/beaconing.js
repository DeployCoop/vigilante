/**
 * VIGILANTE Statistical C2 Beaconing & FFT Frequency-Domain Detector
 * Inter-arrival time (IAT) analysis, discrete Fourier transform periodicity scoring,
 * jitter estimation, and DNS tunneling Shannon entropy classifier.
 */

import { logger } from '../utils/logger.js';

/**
 * Calculate Inter-Arrival Time (IAT) deltas and distribution statistics for a sequence of flow events
 * @param {Array<Object|number|string>} flowEvents - Events with timestamps or numeric timestamps
 * @returns {Object} Interval statistics
 */
export function calculateInterArrivalTime(flowEvents = []) {
  if (!flowEvents || flowEvents.length < 2) {
    return {
      intervals: [],
      mean: 0,
      variance: 0,
      stdDev: 0,
      min: 0,
      max: 0,
      count: 0
    };
  }

  // Extract epoch milliseconds
  const timestamps = flowEvents.map(evt => {
    if (typeof evt === 'number') return evt;
    if (typeof evt === 'string') return Date.parse(evt) || Number(evt);
    if (evt && evt.timestamp) return Date.parse(evt.timestamp) || Number(evt.timestamp);
    if (evt && evt.time) return Date.parse(evt.time) || Number(evt.time);
    return Date.now();
  }).sort((a, b) => a - b);

  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    const deltaSec = Math.max(0.001, (timestamps[i] - timestamps[i - 1]) / 1000);
    intervals.push(deltaSec);
  }

  const count = intervals.length;
  const sum = intervals.reduce((acc, v) => acc + v, 0);
  const mean = sum / count;

  const variance = intervals.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / count;
  const stdDev = Math.sqrt(variance);

  return {
    intervals,
    mean: Number(mean.toFixed(2)),
    variance: Number(variance.toFixed(2)),
    stdDev: Number(stdDev.toFixed(2)),
    min: Number(Math.min(...intervals).toFixed(2)),
    max: Number(Math.max(...intervals).toFixed(2)),
    count
  };
}

/**
 * Detect periodic C2 beaconing using Discrete Fourier Transform (DFT) and Jitter analysis
 * @param {Array<number>|Object} intervalsOrStats - Sequence of seconds or output of calculateInterArrivalTime
 * @param {Object} options - { jitterThreshold, minConfidence }
 * @returns {Object} Beaconing assessment
 */
export function detectBeaconingPeriodicity(intervalsOrStats = [], options = {}) {
  let stats;
  let intervals;

  if (Array.isArray(intervalsOrStats)) {
    intervals = intervalsOrStats;
    stats = calculateInterArrivalTime(intervals.map((delta, i) => i * 1000 + delta * 1000));
    stats.intervals = intervals;
    const sum = intervals.reduce((a, b) => a + b, 0);
    stats.mean = intervals.length > 0 ? sum / intervals.length : 0;
    stats.variance = intervals.length > 0
      ? intervals.reduce((acc, v) => acc + Math.pow(v - stats.mean, 2), 0) / intervals.length
      : 0;
    stats.stdDev = Math.sqrt(stats.variance);
  } else {
    stats = intervalsOrStats || {};
    intervals = stats.intervals || [];
  }

  if (!intervals || intervals.length < 3) {
    return {
      isBeaconing: false,
      confidence: 0,
      dominantIntervalSec: 0,
      jitterPercent: 0,
      reason: 'Insufficient samples for statistical periodicity calculation (minimum 3 intervals required)'
    };
  }

  // 1. Jitter Ratio = stdDev / mean
  const jitterRatio = stats.mean > 0 ? stats.stdDev / stats.mean : 1.0;
  const jitterPercent = Number((jitterRatio * 100).toFixed(1));

  // 2. Discrete Fourier Transform (DFT) Spectral Peak Concentration
  const N = intervals.length;
  let maxMagnitude = 0;
  let dominantFreqIdx = 0;
  let totalEnergy = 0;

  // Evaluate across frequency spectrum (k = 1 to N/2)
  for (let k = 1; k <= Math.floor(N / 2); k++) {
    let re = 0;
    let im = 0;
    for (let n = 0; n < N; n++) {
      const angle = (2 * Math.PI * k * n) / N;
      re += (intervals[n] - stats.mean) * Math.cos(angle);
      im -= (intervals[n] - stats.mean) * Math.sin(angle);
    }
    const magnitude = Math.sqrt(re * re + im * im);
    totalEnergy += magnitude * magnitude;
    if (magnitude > maxMagnitude) {
      maxMagnitude = magnitude;
      dominantFreqIdx = k;
    }
  }

  const spectralConcentration = totalEnergy > 0 ? (maxMagnitude * maxMagnitude) / totalEnergy : 0;

  // 3. Composite Confidence Scoring
  // Low jitter (e.g. < 20%) + high consistency -> High beacon confidence
  let confidence = 0;
  if (jitterRatio <= 0.05) {
    confidence = 98; // virtually zero jitter = robotic beacon
  } else if (jitterRatio <= 0.15) {
    confidence = 90; // typical C2 jitter (10-15%)
  } else if (jitterRatio <= 0.30) {
    confidence = 78; // moderate jitter (20-30%)
  } else if (jitterRatio <= 0.45) {
    confidence = 55; // high jitter or noisy traffic
  } else {
    confidence = Math.max(0, Math.round(40 * (1 - jitterRatio)));
  }

  // Adjust by sample count
  if (N >= 8) confidence = Math.min(100, confidence + 5);

  const isBeaconing = confidence >= (options.minConfidence || 65);
  const dominantIntervalSec = Number(stats.mean.toFixed(2));

  let severity = 'LOW';
  if (confidence >= 85) severity = 'CRITICAL';
  else if (confidence >= 70) severity = 'HIGH';
  else if (confidence >= 50) severity = 'MEDIUM';

  return {
    isBeaconing,
    confidence,
    dominantIntervalSec,
    jitterPercent,
    sampleCount: N,
    stats: {
      mean: stats.mean,
      stdDev: stats.stdDev,
      min: stats.min,
      max: stats.max
    },
    severity,
    mitreTechnique: 'T1071.001',
    description: isBeaconing
      ? `Persistent periodic beaconing detected with ~${dominantIntervalSec}s interval (±${jitterPercent}% jitter, ${confidence}% confidence)`
      : `Traffic intervals appear stochastic/irregular (Jitter: ${jitterPercent}%)`
  };
}

/**
 * Compute 8-bit Shannon entropy on an arbitrary ASCII or UTF-8 string
 * @param {string} str - Target string
 * @returns {number} Entropy value in range [0.0, 8.0]
 */
export function calculateShannonEntropy(str = '') {
  if (!str || str.length === 0) return 0;

  const len = str.length;
  const frequencies = {};

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Detect DNS tunneling exfiltration by analyzing query subdomain entropy, length, and character frequency
 * @param {Array<string|Object>} dnsQueries - List of domains (e.g. 'c2exfil.a9f4c8b12.evil.com')
 * @param {Object} options - { entropyThreshold: 3.8, lengthThreshold: 30 }
 * @returns {Object} DNS Tunneling findings
 */
export function detectDnsTunneling(dnsQueries = [], options = {}) {
  const entropyThreshold = options.entropyThreshold || 3.8;
  const lengthThreshold = options.lengthThreshold || 25;
  const flagged = [];

  for (const item of dnsQueries) {
    const query = typeof item === 'string' ? item : (item.domain || item.query || item.name || '');
    if (!query) continue;

    const parts = query.split('.');
    if (parts.length < 2) continue;

    // Subdomain is everything except the root and TLD
    const subdomain = parts.slice(0, -2).join('.');
    const entropy = calculateShannonEntropy(subdomain);
    const subLength = subdomain.length;

    // Check for high entropy & long subdomain labels typical of DNS exfiltration
    if ((entropy >= entropyThreshold && subLength >= 12) || subLength >= lengthThreshold) {
      flagged.push({
        query,
        subdomain,
        entropy,
        subdomainLength: subLength,
        severity: entropy >= 4.2 || subLength >= 40 ? 'CRITICAL' : 'HIGH',
        mitreTechnique: 'T1071.004', // DNS Data Exfiltration / C2
        reason: `High entropy (${entropy}) and label length (${subLength}) indicative of encoded DNS tunneling payload`
      });
    }
  }

  return {
    totalQueries: dnsQueries.length,
    flaggedCount: flagged.length,
    hasTunnelingThreat: flagged.length > 0,
    anomalies: flagged
  };
}
