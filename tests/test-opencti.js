import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  resolveOpenCtiConfig,
  openCtiGraphQL,
  checkOpenCtiConnection,
  detectObservableType,
  normalizeOpenCtiIndicator,
  listOpenCtiIndicators,
  lookupOpenCtiObservable,
  syncOpenCtiIndicators,
  readOpenCtiIndicatorCache,
  matchOpenCtiIndicators,
  buildStixPattern,
  createOpenCtiIndicator,
  createOpenCtiObservable,
  createOpenCtiRelationship,
  pushStixBundleToOpenCti,
  DEFAULT_OPENCTI_URL,
  DEFAULT_OPENCTI_TIMEOUT_MS,
  OPENCTI_CACHE_FILE
} from '../src/engine/opencti.js';
import { matchCtiIndicators } from '../src/engine/cti.js';

console.log('🧪 Testing OpenCTI Threat Intelligence Integration...');

// Isolate the config dir so syncs write to a temp tree and no real
// config.yaml (with a possible opencti.token) leaks into these tests.
const tmpXdg = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-opencti-test-'));
process.env.XDG_CONFIG_HOME = tmpXdg;
delete process.env.OPENCTI_TOKEN;
delete process.env.OPENCTI_URL;
delete process.env.OPENCTI_TIMEOUT_MS;

const TEST_TOKEN = 'test-opencti-token';

const KNOWN_IP = '203.0.113.10';
const KNOWN_DOMAIN = 'evil.example.com';
const KNOWN_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function indicatorNode(id, pattern, score) {
  return {
    id,
    name: `Indicator ${id}`,
    pattern,
    pattern_type: 'stix',
    x_opencti_score: score,
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: null,
    revoked: false,
    confidence: 75,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-11-01T00:00:00Z',
    labels: { edges: [{ node: { value: 'apt-test' } }] },
    killChainPhases: { edges: [{ node: { kill_chain_name: 'mitre-attack', phase_name: 'command-and-control' } }] }
  };
}

// A mock OpenCTI GraphQL endpoint. It answers by operation name and records
// every request so tests can assert on the exact query/variables sent.
function startMockServer({ mode = 'ok' } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      if (mode === 'hang') return; // never respond: exercises the timeout
      let parsed = {};
      try { parsed = JSON.parse(body || '{}'); } catch { parsed = {}; }
      requests.push({ query: parsed.query || '', variables: parsed.variables || {}, headers: req.headers });
      if (mode === 'http500') {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal Server Error');
        return;
      }
      if (mode === 'graphql-errors') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ errors: [{ message: 'Forbidden: KNOWLEDGE access required' }] }));
        return;
      }
      const q = parsed.query || '';
      let payload = { data: {} };
      if (q.includes('me {')) {
        payload = { data: { me: { id: 'user--1', name: 'Admin', user_email: 'admin@opencti.local' } } };
      } else if (q.includes('stixCyberObservables')) {
        const wanted = parsed.variables?.filters?.filters?.[0]?.values?.[0];
        if (wanted === KNOWN_IP) {
          payload = {
            data: {
              stixCyberObservables: {
                edges: [{
                  node: {
                    id: 'ipv4-addr--1',
                    entity_type: 'IPv4-Addr',
                    observable_value: KNOWN_IP,
                    x_opencti_score: 85,
                    indicators: { edges: [{ node: indicatorNode('indicator--1', `[ipv4-addr:value = '${KNOWN_IP}']`, 85) }] }
                  }
                }]
              }
            }
          };
        } else {
          payload = { data: { stixCyberObservables: { edges: [] } } };
        }
      } else if (q.includes('indicators(')) {
        if (parsed.variables?.after === 'cursor-1') {
          payload = {
            data: {
              indicators: {
                edges: [{ node: indicatorNode('indicator--3', `[file:hashes.'SHA-256' = '${KNOWN_SHA256}']`, 60) }],
                pageInfo: { hasNextPage: false, endCursor: null }
              }
            }
          };
        } else {
          payload = {
            data: {
              indicators: {
                edges: [
                  { node: indicatorNode('indicator--1', `[ipv4-addr:value = '${KNOWN_IP}']`, 85) },
                  { node: indicatorNode('indicator--2', `[domain-name:value = '${KNOWN_DOMAIN}']`, 70) }
                ],
                pageInfo: { hasNextPage: true, endCursor: 'cursor-1' }
              }
            }
          };
        }
      } else if (q.includes('indicatorAdd')) {
        const input = parsed.variables?.input || {};
        payload = {
          data: {
            indicatorAdd: {
              id: 'indicator--new',
              name: input.name || null,
              pattern: input.pattern || null,
              pattern_type: 'stix',
              x_opencti_score: input.x_opencti_score ?? null,
              valid_from: input.valid_from || null,
              valid_until: input.valid_until || null,
              revoked: false,
              confidence: null
            }
          }
        };
      } else if (q.includes('stixCyberObservableAdd')) {
        payload = {
          data: {
            stixCyberObservableAdd: {
              id: 'ipv4-addr--new',
              entity_type: 'IPv4-Addr',
              observable_value: KNOWN_IP,
              x_opencti_score: 85
            }
          }
        };
      } else if (q.includes('stixCoreRelationshipAdd')) {
        const input = parsed.variables?.input || {};
        payload = {
          data: {
            stixCoreRelationshipAdd: {
              id: 'relationship--new',
              relationship_type: input.relationship_type || 'indicates',
              description: input.description || null,
              start_time: input.start_time || null,
              stop_time: input.stop_time || null
            }
          }
        };
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port, requests });
    });
  });
}

// Test 1: config resolution (precedence + normalization)
{
  const cfg = resolveOpenCtiConfig({ url: 'https://opencti.example.com/', token: TEST_TOKEN, timeoutMs: 5000 });
  assert.strictEqual(cfg.url, 'https://opencti.example.com');
  assert.strictEqual(cfg.graphqlUrl, 'https://opencti.example.com/graphql');
  assert.strictEqual(cfg.token, TEST_TOKEN);
  assert.strictEqual(cfg.timeoutMs, 5000);
  assert.strictEqual(cfg.configured, true);

  const missing = resolveOpenCtiConfig({ token: null });
  assert.strictEqual(missing.configured, false);
  assert.strictEqual(missing.url, DEFAULT_OPENCTI_URL);
  assert.strictEqual(missing.timeoutMs, DEFAULT_OPENCTI_TIMEOUT_MS);
  console.log('✔ Test 1 passed: resolveOpenCtiConfig precedence, URL normalization, token absence.');
}

// Test 2: transport fails closed without a token (no network call)
{
  let err = null;
  try {
    await openCtiGraphQL({ url: 'http://127.0.0.1:1', token: null, query: '{ me { id } }' });
  } catch (e) { err = e; }
  assert.ok(err, 'openCtiGraphQL must throw without a token');
  assert.ok(err.message.includes('not configured'), `Expected a not-configured error, got: ${err.message}`);
  console.log('✔ Test 2 passed: openCtiGraphQL refuses to call without a token.');
}

// Test 3: connection probe — success, GraphQL error, HTTP 500
{
  const ok = await startMockServer({ mode: 'ok' });
  const good = await checkOpenCtiConnection({ url: `http://127.0.0.1:${ok.port}`, token: TEST_TOKEN });
  assert.strictEqual(good.connected, true);
  assert.strictEqual(good.user.id, 'user--1');
  assert.strictEqual(good.user.email, 'admin@opencti.local');
  ok.server.close();

  const gqlErr = await startMockServer({ mode: 'graphql-errors' });
  const bad = await checkOpenCtiConnection({ url: `http://127.0.0.1:${gqlErr.port}`, token: TEST_TOKEN });
  assert.strictEqual(bad.connected, false);
  assert.ok(bad.error.includes('KNOWLEDGE'), `Expected the GraphQL error surfaced, got: ${bad.error}`);
  gqlErr.server.close();

  const httpErr = await startMockServer({ mode: 'http500' });
  const down = await checkOpenCtiConnection({ url: `http://127.0.0.1:${httpErr.port}`, token: TEST_TOKEN });
  assert.strictEqual(down.connected, false);
  assert.ok(down.error.includes('500'), `Expected the HTTP status surfaced, got: ${down.error}`);
  httpErr.server.close();
  console.log('✔ Test 3 passed: checkOpenCtiConnection reports success and both failure classes honestly.');
}

// Test 4: observable lookup — found (with indicator) and not found
{
  const mock = await startMockServer({ mode: 'ok' });
  const base = { url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN };

  const hit = await lookupOpenCtiObservable(KNOWN_IP, base);
  assert.strictEqual(hit.found, true);
  assert.strictEqual(hit.type, 'ipv4');
  assert.strictEqual(hit.observables.length, 1);
  assert.strictEqual(hit.observables[0].observableValue, KNOWN_IP);
  assert.strictEqual(hit.indicators.length, 1);
  assert.strictEqual(hit.indicators[0].score, 85);
  assert.strictEqual(hit.indicators[0].iocType, 'ipv4');
  assert.strictEqual(hit.indicators[0].iocValue, KNOWN_IP);
  assert.deepStrictEqual(hit.indicators[0].labels, ['apt-test']);

  const miss = await lookupOpenCtiObservable('198.51.100.99', base);
  assert.strictEqual(miss.found, false);
  assert.strictEqual(miss.indicators.length, 0);

  // The request carries a Bearer token and a FilterGroup, never the token in the body.
  const lookupReq = mock.requests.find((r) => r.query.includes('stixCyberObservables'));
  assert.strictEqual(lookupReq.headers.authorization, `Bearer ${TEST_TOKEN}`);
  assert.ok(!JSON.stringify(lookupReq.variables).includes(TEST_TOKEN));
  assert.strictEqual(lookupReq.variables.filters.mode, 'and');
  mock.server.close();
  console.log('✔ Test 4 passed: lookupOpenCtiObservable normalizes hits and misses, Bearer auth, no token in body.');
}

// Test 5: observable type detection + STIX pattern builder validation
{
  assert.strictEqual(detectObservableType('203.0.113.10'), 'ipv4');
  assert.strictEqual(detectObservableType('2001:db8::1'), 'ipv6');
  assert.strictEqual(detectObservableType('evil.example.com'), 'domain');
  assert.strictEqual(detectObservableType('https://evil.example.com/payload'), 'url');
  assert.strictEqual(detectObservableType(KNOWN_SHA256), 'sha256');
  assert.strictEqual(detectObservableType('not an observable'), 'unknown');

  assert.strictEqual(buildStixPattern('203.0.113.10', 'ipv4'), "[ipv4-addr:value = '203.0.113.10']");
  assert.strictEqual(buildStixPattern('evil.example.com', 'domain'), "[domain-name:value = 'evil.example.com']");
  assert.strictEqual(buildStixPattern(KNOWN_SHA256, 'sha256'), `[file:hashes.'SHA-256' = '${KNOWN_SHA256}']`);
  assert.throws(() => buildStixPattern('999.999.999.999', 'ipv4'), /Invalid IPv4/);
  assert.throws(() => buildStixPattern('x', 'bogus'), /Unsupported observable type/);
  console.log('✔ Test 5 passed: detectObservableType + buildStixPattern classify and validate.');
}

// Test 6: indicator list pagination + normalization
{
  const mock = await startMockServer({ mode: 'ok' });
  const { indicators, count, hasMore } = await listOpenCtiIndicators({ url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN });
  assert.strictEqual(count, 3);
  assert.strictEqual(indicators.length, 3);
  assert.strictEqual(hasMore, false);
  assert.strictEqual(indicators[0].iocType, 'ipv4');
  assert.strictEqual(indicators[0].iocValue, KNOWN_IP);
  assert.strictEqual(indicators[1].iocType, 'domain');
  assert.strictEqual(indicators[1].iocValue, KNOWN_DOMAIN);
  assert.strictEqual(indicators[2].iocType, 'sha256');
  assert.strictEqual(indicators[2].iocValue, KNOWN_SHA256);

  // The list request filters out revoked + non-STIX indicators.
  const listReq = mock.requests.find((r) => r.query.includes('indicators('));
  const filterKeys = listReq.variables.filters.filters.map((f) => f.key).sort();
  assert.deepStrictEqual(filterKeys, ['pattern_type', 'revoked']);
  assert.strictEqual(listReq.variables.first, 100);
  mock.server.close();
  console.log('✔ Test 6 passed: listOpenCtiIndicators paginates and normalizes all three IOC kinds.');
}

// Test 7: sync writes the cache; a watermarked re-sync merges by id (no dupes)
{
  const mock = await startMockServer({ mode: 'ok' });
  const base = { url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN };
  const first = await syncOpenCtiIndicators(base);
  assert.strictEqual(first.ok, true);
  assert.strictEqual(first.synced, 3);
  assert.strictEqual(first.count, 3);
  const cachePath = path.join(tmpXdg, 'vigilante', 'cti', OPENCTI_CACHE_FILE);
  assert.strictEqual(first.file, cachePath);
  assert.ok(fsSync.existsSync(cachePath), 'cache file must exist under the isolated XDG dir');
  const cache = readOpenCtiIndicatorCache();
  assert.strictEqual(cache.count, 3);
  assert.strictEqual(cache.url, base.url);

  const second = await syncOpenCtiIndicators(base);
  assert.strictEqual(second.count, 3, 'watermarked re-sync must not duplicate indicators');
  mock.server.close();
  console.log('✔ Test 7 passed: syncOpenCtiIndicators writes and merges the cache by id.');
}

// Test 8: offline cache matching (shape + severity mapping)
{
  const cache = readOpenCtiIndicatorCache();
  assert.ok(cache, 'cache from Test 7 must still be present');
  const matches = matchOpenCtiIndicators([KNOWN_IP, KNOWN_DOMAIN, 'clean.example.com'], { cache });
  assert.strictEqual(matches.length, 2);
  const ipMatch = matches.find((m) => m.value === KNOWN_IP);
  assert.strictEqual(ipMatch.source, 'OpenCTI');
  assert.strictEqual(ipMatch.type, 'OPENCTI_IPV4');
  assert.strictEqual(ipMatch.severity, 'CRITICAL', 'score 85 must map to CRITICAL');
  const domainMatch = matches.find((m) => m.value === KNOWN_DOMAIN);
  assert.strictEqual(domainMatch.severity, 'HIGH', 'score 70 must map to HIGH');
  assert.strictEqual(matchOpenCtiIndicators(['nothing-here'], { cache }).length, 0);
  assert.deepStrictEqual(matchOpenCtiIndicators(['x'], { cache: null }), []);
  console.log('✔ Test 8 passed: matchOpenCtiIndicators matches offline with score-based severity.');
}

// Test 9: matchCtiIndicators consults the OpenCTI cache (wiring proof)
{
  // 198.51.100.99 is TEST-NET-2: absent from the Feodo samples and URLhaus,
  // present only in the synced OpenCTI cache after we add it there.
  const cache = readOpenCtiIndicatorCache();
  const extra = normalizeOpenCtiIndicator(indicatorNode('indicator--9', "[ipv4-addr:value = '198.51.100.99']", 55));
  cache.indicators.push(extra);
  cache.count = cache.indicators.length;
  await fs.writeFile(path.join(tmpXdg, 'vigilante', 'cti', OPENCTI_CACHE_FILE), JSON.stringify(cache, null, 2), 'utf8');

  const matches = await matchCtiIndicators(['198.51.100.99', '8.8.8.8']);
  const hit = matches.find((m) => m.value === '198.51.100.99');
  assert.ok(hit, 'matchCtiIndicators must surface the OpenCTI-cached indicator');
  assert.strictEqual(hit.source, 'OpenCTI');
  assert.strictEqual(hit.severity, 'HIGH', 'score 55 must map to HIGH');
  assert.ok(!matches.some((m) => m.value === '8.8.8.8'), 'benign IP must not match');
  console.log('✔ Test 9 passed: matchCtiIndicators surfaces OpenCTI cache hits alongside feed matches.');
}

// Test 10: write-back — indicator, observable, relationship mutations
{
  const mock = await startMockServer({ mode: 'ok' });
  const base = { url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN };

  const created = await createOpenCtiIndicator({ ...base, value: KNOWN_IP, type: 'ipv4', score: 85, description: 'C2 seen by Vigilante' });
  assert.strictEqual(created.id, 'indicator--new');
  assert.strictEqual(created.pattern, "[ipv4-addr:value = '203.0.113.10']");
  assert.strictEqual(created.score, 85);
  const indReq = mock.requests.find((r) => r.query.includes('indicatorAdd'));
  assert.strictEqual(indReq.variables.input.pattern_type, 'stix');
  assert.strictEqual(indReq.variables.input.pattern_version, '2.1');

  const obs = await createOpenCtiObservable({ ...base, value: KNOWN_IP, type: 'ipv4', score: 85 });
  assert.strictEqual(obs.id, 'ipv4-addr--new');
  assert.strictEqual(obs.observableValue, KNOWN_IP);
  const obsReq = mock.requests.find((r) => r.query.includes('stixCyberObservableAdd'));
  assert.ok(obsReq.query.includes('IPv4Addr'), 'observable mutation must use the IPv4Addr argument');

  const rel = await createOpenCtiRelationship({ ...base, fromId: 'indicator--new', toId: 'malware--1', relationshipType: 'indicates' });
  assert.strictEqual(rel.id, 'relationship--new');
  assert.strictEqual(rel.relationshipType, 'indicates');
  const relReq = mock.requests.find((r) => r.query.includes('stixCoreRelationshipAdd'));
  assert.strictEqual(relReq.variables.input.fromId, 'indicator--new');

  assert.throws(() => buildStixPattern('', 'ipv4'), /requires a value/);
  await assert.rejects(
    () => createOpenCtiIndicator({ ...base, value: 'not-an-ip', type: 'ipv4' }),
    /Invalid IPv4/
  );
  mock.server.close();
  console.log('✔ Test 10 passed: create indicator / observable / relationship send the right mutations.');
}

// Test 11: STIX bundle push — indicators + observables, relationships skipped
{
  const mock = await startMockServer({ mode: 'ok' });
  const base = { url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN };
  const bundle = {
    type: 'bundle',
    id: 'bundle--test',
    objects: [
      { type: 'indicator', id: 'indicator--a', name: 'Bad IP', pattern: `[ipv4-addr:value = '${KNOWN_IP}']`, pattern_type: 'stix', confidence: 80 },
      { type: 'domain-name', id: 'domain-name--a', value: KNOWN_DOMAIN },
      { type: 'relationship', id: 'relationship--a', relationship_type: 'indicates', source_ref: 'indicator--a', target_ref: 'malware--1' },
      { type: 'identity', id: 'identity--a', name: 'Someone' }
    ]
  };
  const result = await pushStixBundleToOpenCti(bundle, base);
  assert.strictEqual(result.pushed.indicators, 1);
  assert.strictEqual(result.pushed.observables, 1);
  assert.strictEqual(result.skipped.relationships, 1);
  assert.strictEqual(result.skipped.other, 1);
  assert.strictEqual(result.failures.length, 0);
  assert.strictEqual(result.ok, true);
  mock.server.close();
  console.log('✔ Test 11 passed: pushStixBundleToOpenCti pushes indicators/observables and skips relationships honestly.');
}

// Test 12: stalled instance aborts on timeout (AbortSignal, <5s bound)
{
  const mock = await startMockServer({ mode: 'hang' });
  const started = Date.now();
  let err = null;
  try {
    await lookupOpenCtiObservable(KNOWN_IP, { url: `http://127.0.0.1:${mock.port}`, token: TEST_TOKEN, timeoutMs: 150 });
  } catch (e) { err = e; }
  const elapsedMs = Date.now() - started;
  mock.server.close();
  assert.ok(err, 'lookup must reject when the instance never responds');
  assert.ok(elapsedMs < 5000, `lookup must abort in <5s, took ${elapsedMs}ms`);
  console.log(`✔ Test 12 passed: lookup aborts a stalled instance in ${elapsedMs}ms (timeoutMs 150).`);
}

// Test 13: normalizeOpenCtiIndicator handles a bare node without throwing
{
  const bare = normalizeOpenCtiIndicator({});
  assert.strictEqual(bare.id, null);
  assert.strictEqual(bare.iocType, 'unknown');
  assert.strictEqual(bare.iocValue, null);
  assert.deepStrictEqual(bare.labels, []);
  console.log('✔ Test 13 passed: normalizeOpenCtiIndicator is safe on a bare node.');
}

await fs.rm(tmpXdg, { recursive: true, force: true });
console.log('🎉 All OpenCTI integration tests passed successfully!');
