/**
 * VIGILANTE Local Offline Semantic CTI & Vector Threat Search
 * Air-gapped semantic vector embedding generator (128-dimensional dense float vector),
 * cosine similarity search, and embedded catalog mapping natural language analyst queries
 * directly to MITRE ATT&CK techniques, tactics, and SIGMA detection rules.
 */

import { logger } from '../utils/logger.js';

/**
 * Deterministic string hash for vector dimension bucket mapping (FNV-1a 32-bit)
 * @param {string} str
 * @returns {number} 32-bit unsigned integer
 */
function fnv1aHash(str) {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/**
 * Generate a 128-dimensional dense float vector from text using subword n-grams and term hashing
 * @param {string} text - Input query or threat description
 * @param {number} dimensions - Number of vector dimensions (default: 128)
 * @returns {Float64Array} Unit L2-normalized dense vector
 */
export function generateLocalEmbedding(text = '', dimensions = 128) {
  const vector = new Float64Array(dimensions);
  if (!text || typeof text !== 'string') {
    return vector;
  }

  const clean = text.toLowerCase().replace(/[^a-z0-9_\-\s]/g, ' ');
  const tokens = clean.split(/\s+/).filter(Boolean);

  // 1. Unigram feature weights
  for (const token of tokens) {
    const h = fnv1aHash(token);
    const dim = h % dimensions;
    vector[dim] += 2.0;

    // 2. Character 3-grams for subword morphological matching
    if (token.length >= 3) {
      for (let i = 0; i <= token.length - 3; i++) {
        const tri = token.substring(i, i + 3);
        const h3 = fnv1aHash(tri);
        const dim3 = h3 % dimensions;
        vector[dim3] += 0.5;
      }
    }
  }

  // 3. L2 Unit Normalization
  let norm = 0;
  for (let i = 0; i < dimensions; i++) {
    norm += vector[i] * vector[i];
  }
  norm = Math.sqrt(norm);

  if (norm > 0) {
    for (let i = 0; i < dimensions; i++) {
      vector[i] /= norm;
    }
  }

  return vector;
}

/**
 * Calculate mathematical cosine similarity between two dense float vectors
 * @param {Float64Array|Array<number>} vecA
 * @param {Float64Array|Array<number>} vecB
 * @returns {number} Cosine similarity in range [-1.0, 1.0]
 */
export function cosineSimilarity(vecA, vecB) {
  if (!vecA || !vecB || vecA.length !== vecB.length) return 0;

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }

  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (denom === 0) return 0;

  const sim = dotProduct / denom;
  return Number(Math.max(-1, Math.min(1, sim)).toFixed(4));
}

// Built-in offline catalog of MITRE ATT&CK techniques & threat scenarios
const BUILTIN_THREAT_CORPUS = [
  {
    id: 'T1059.004',
    name: 'Unix Shell',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversary executes interactive bash, sh, or zsh commands in container workloads or web pods.'
  },
  {
    id: 'T1003.001',
    name: 'LSASS Memory Dumping',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries dump process memory of LSASS or in-memory credentials via unlinked binaries or procdump.'
  },
  {
    id: 'T1021.002',
    name: 'SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    description: 'Lateral movement over port 445 SMB, administrative file shares, and PsExec remote service creation.'
  },
  {
    id: 'T1071.001',
    name: 'Web Protocols C2 Beaconing',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversary uses periodic HTTP or HTTPS beacons with jitter to communicate with external command and control servers.'
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    tacticId: 'TA0040',
    description: 'Ransomware encryption of target filesystems, databases, and mounted volumes causing high entropy and data lockout.'
  },
  {
    id: 'T1078',
    name: 'Valid Accounts & Cloud Credentials',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    description: 'Compromised cloud access keys, AWS STS tokens, Kubernetes service accounts, and GitHub personal access tokens.'
  },
  {
    id: 'T1574.006',
    name: 'Dynamic Linker Hijacking',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Rootkit hijacking using ld.so.preload to inject malicious shared libraries into target processes.'
  },
  {
    id: 'T1611',
    name: 'Escape to Host',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    description: 'Container breakout to underlying Kubernetes node via privileged container, cgroups abuse, or nsenter.'
  },
  {
    id: 'T1071.004',
    name: 'DNS Data Exfiltration Tunneling',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    description: 'Covert data exfiltration using high-entropy encoded DNS subdomains and TXT query channels.'
  }
];

let cachedIndexedCatalog = null;

/**
 * Initializes and vectorizes the offline semantic threat catalog
 * @returns {Array<Object>} Vectorized catalog
 */
export function initSemanticThreatCatalog() {
  if (cachedIndexedCatalog) {
    return cachedIndexedCatalog;
  }

  cachedIndexedCatalog = BUILTIN_THREAT_CORPUS.map(item => {
    const fullText = `${item.id} ${item.name} ${item.tactic} ${item.description}`;
    const embedding = generateLocalEmbedding(fullText);
    return {
      ...item,
      embedding
    };
  });

  logger.info('VECTORCTI', `Initialized semantic catalog with ${cachedIndexedCatalog.length} threat models.`);
  return cachedIndexedCatalog;
}

/**
 * Air-gapped semantic vector search matching natural language analyst queries against CTI models
 * @param {string} queryText - e.g. "dumped memory credentials filelessly"
 * @param {Object} options - { limit: 5, minSimilarity: 0.15 }
 * @returns {Array<Object>} Ranked matches
 */
export function semanticThreatSearch(queryText = '', options = {}) {
  const catalog = initSemanticThreatCatalog();
  const queryEmbedding = generateLocalEmbedding(queryText);
  const limit = options.limit || 5;
  const minSimilarity = options.minSimilarity || 0.10;

  const scored = catalog.map(item => {
    const sim = cosineSimilarity(queryEmbedding, item.embedding);
    return {
      id: item.id,
      name: item.name,
      tactic: item.tactic,
      tacticId: item.tacticId,
      description: item.description,
      similarityScore: sim,
      confidencePercent: Math.round(Math.max(0, sim) * 100)
    };
  });

  // Filter and sort by score descending
  const results = scored
    .filter(item => item.similarityScore >= minSimilarity)
    .sort((a, b) => b.similarityScore - a.similarityScore)
    .slice(0, limit);

  return results;
}
