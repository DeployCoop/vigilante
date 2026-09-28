import assert from 'node:assert';
import {
  generateLocalEmbedding,
  cosineSimilarity,
  initSemanticThreatCatalog,
  semanticThreatSearch
} from '../src/engine/vectorcti.js';

console.log('🧪 Testing Local Offline Semantic CTI & Vector Threat Search Engine...');

// Test 1: generateLocalEmbedding & cosineSimilarity
const vec1 = generateLocalEmbedding('bash shell reverse execution in container');
const vec2 = generateLocalEmbedding('interactive sh terminal shell spawned in web pod');
const vec3 = generateLocalEmbedding('accounting payroll database financial backup');

assert.strictEqual(vec1.length, 128);
assert.strictEqual(vec2.length, 128);

const simRelated = cosineSimilarity(vec1, vec2);
const simUnrelated = cosineSimilarity(vec1, vec3);

assert.ok(simRelated > 0.20, `Related shell execution queries should have high similarity, got ${simRelated}`);
assert.ok(simUnrelated < 0.10, `Unrelated payroll query should have low similarity, got ${simUnrelated}`);
assert.ok(simRelated > simUnrelated * 2, 'Related query similarity must exceed unrelated query similarity');
console.log(`✔ Test 1 passed: generateLocalEmbedding & cosineSimilarity differentiated related (${simRelated}) vs unrelated (${simUnrelated}) threat queries.`);

// Test 2: initSemanticThreatCatalog
const catalog = initSemanticThreatCatalog();
assert.ok(catalog.length >= 8);
assert.ok(catalog.every(c => c.embedding && c.embedding.length === 128));
console.log(`✔ Test 2 passed: initSemanticThreatCatalog indexed ${catalog.length} vectorized MITRE threat models.`);

// Test 3: semanticThreatSearch - Search for memory dumping
const memoryQuery = 'adversaries dumping credentials from process memory';
const memResults = semanticThreatSearch(memoryQuery, { limit: 3 });

assert.ok(memResults.length > 0);
assert.strictEqual(memResults[0].id, 'T1003.001');
assert.strictEqual(memResults[0].tactic, 'Credential Access');
console.log(`✔ Test 3 passed: semanticThreatSearch accurately mapped "${memoryQuery}" to ${memResults[0].id} (${memResults[0].name}).`);

// Test 4: semanticThreatSearch - Search for ransomware encryption
const ransomQuery = 'ransomware encrypted all volumes and databases';
const ransomResults = semanticThreatSearch(ransomQuery, { limit: 3 });

assert.ok(ransomResults.length > 0);
assert.strictEqual(ransomResults[0].id, 'T1486');
assert.strictEqual(ransomResults[0].tactic, 'Impact');
console.log(`✔ Test 4 passed: semanticThreatSearch accurately mapped "${ransomQuery}" to ${ransomResults[0].id} (${ransomResults[0].name}).`);

// Test 5: semanticThreatSearch - Search for covert DNS tunneling
const dnsQuery = 'covert data exfiltration over DNS subdomains';
const dnsResults = semanticThreatSearch(dnsQuery, { limit: 3 });

assert.ok(dnsResults.length > 0);
assert.strictEqual(dnsResults[0].id, 'T1071.004');
console.log(`✔ Test 5 passed: semanticThreatSearch accurately mapped "${dnsQuery}" to ${dnsResults[0].id} (${dnsResults[0].name}).`);

console.log('🎉 All Local Offline Semantic CTI & Vector Threat Search tests passed successfully!\n');
