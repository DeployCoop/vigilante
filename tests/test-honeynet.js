import assert from 'node:assert';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  startDecoyService,
  createHoneynetMesh,
  plantBreadcrumbs,
  DECOY_TYPES
} from '../src/engine/honeynet.js';

async function runTests() {
  console.log('🧪 Testing Dynamic Ephemeral Honeynet & Breadcrumb Mesh Engine...');

  // Test 1: SSH Decoy Interaction
  let sshAlert = null;
  const sshDecoy = await startDecoyService(DECOY_TYPES.SSH, 0, {
    onAlert: (alert) => { sshAlert = alert; }
  });
  assert.ok(sshDecoy.port > 0, 'SSH decoy must bind to a dynamic port');

  // Connect to SSH decoy and send client banner
  await new Promise((resolve) => {
    const client = net.createConnection({ port: sshDecoy.port }, () => {
      client.once('data', (banner) => {
        assert.ok(banner.toString().includes('SSH-2.0-OpenSSH'), 'Must receive OpenSSH banner');
        client.write('SSH-2.0-ClientProbe_v1.0\r\n');
        setTimeout(() => {
          client.end();
          resolve();
        }, 50);
      });
    });
  });

  assert.ok(sshAlert, 'SSH alert callback must have been triggered');
  assert.strictEqual(sshAlert.serviceType, 'SSH');
  assert.strictEqual(sshAlert.severity, 'CRITICAL');
  assert.ok(sshAlert.payload.includes('ClientProbe'));
  await sshDecoy.stop();
  console.log(`✔ Test 1 passed: SSH decoy captured client probe on port ${sshDecoy.port}.`);

  // Test 2: Redis Decoy Interaction
  let redisAlert = null;
  const redisDecoy = await startDecoyService(DECOY_TYPES.REDIS, 0, {
    onAlert: (alert) => { redisAlert = alert; }
  });

  await new Promise((resolve) => {
    const client = net.createConnection({ port: redisDecoy.port }, () => {
      client.write('PING\r\n');
      client.once('data', (resp) => {
        assert.ok(resp.toString().includes('+PONG'), 'Must receive +PONG from Redis decoy');
        client.end();
        resolve();
      });
    });
  });

  assert.ok(redisAlert, 'Redis alert callback must have fired');
  assert.strictEqual(redisAlert.serviceType, 'REDIS');
  assert.ok(redisAlert.command.includes('PING'));
  await redisDecoy.stop();
  console.log(`✔ Test 2 passed: Redis decoy responded to RESP commands and logged attacker interaction.`);

  // Test 3: HTTP Decoy Interaction
  let httpAlert = null;
  const httpDecoy = await startDecoyService(DECOY_TYPES.HTTP, 0, {
    onAlert: (alert) => { httpAlert = alert; }
  });

  const httpResp = await new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${httpDecoy.port}/admin/login`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    }).on('error', reject);
  });

  assert.strictEqual(httpResp.statusCode, 200);
  assert.ok(httpAlert, 'HTTP alert callback must have fired');
  assert.strictEqual(httpAlert.url, '/admin/login');
  assert.strictEqual(httpAlert.method, 'GET');
  await httpDecoy.stop();
  console.log(`✔ Test 3 passed: HTTP decoy served deceptive console and registered probe.`);

  // Test 4: createHoneynetMesh & Teardown
  const mesh = await createHoneynetMesh({ services: ['SSH', 'REDIS', 'HTTP'] });
  assert.strictEqual(mesh.status, 'ACTIVE');
  assert.strictEqual(mesh.decoys.length, 3);
  await mesh.teardown();
  console.log(`✔ Test 4 passed: createHoneynetMesh orchestrated and tore down ${mesh.decoys.length} ephemeral services.`);

  // Test 5: plantBreadcrumbs
  const testDir = path.join(os.tmpdir(), `vigilante-test-crumbs-${Date.now()}`);
  const planted = await plantBreadcrumbs(testDir, ['aws', 'kube', 'history']);
  assert.strictEqual(planted.length, 3, 'Must plant 3 breadcrumb artifacts');

  const awsBreadcrumb = planted.find(p => p.type === 'AWS_CREDENTIALS');
  assert.ok(awsBreadcrumb);
  const awsContent = await fs.readFile(awsBreadcrumb.path, 'utf8');
  assert.ok(awsContent.includes('AKIAVIGILANTE'));

  const kubeBreadcrumb = planted.find(p => p.type === 'KUBECONFIG_TOKEN');
  assert.ok(kubeBreadcrumb);
  const kubeContent = await fs.readFile(kubeBreadcrumb.path, 'utf8');
  assert.ok(kubeContent.includes('honeycanary'));

  // Cleanup
  await fs.rm(testDir, { recursive: true, force: true });
  console.log(`✔ Test 5 passed: plantBreadcrumbs generated realistic AWS, Kubeconfig, and bash lures.`);

  console.log('🎉 All Dynamic Ephemeral Honeynet & Breadcrumb Mesh tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Honeynet tests failed:', err);
  process.exit(1);
});
