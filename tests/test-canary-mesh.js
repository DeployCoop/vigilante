import http from 'node:http';
import {
  generateCloudHoneytoken,
  plantDecoyBreadcrumbs,
  startCanaryWebhookListener,
  listActiveCanaries
} from '../src/engine/deception.js';

async function runTests() {
  console.log('🧪 Testing Cloud Honeytoken & Webhook Trap Mesh...');

  // Test 1: Generate AWS Honeytoken
  const awsToken = await generateCloudHoneytoken('aws', { label: 'decoy-prod-s3-rw' });
  if (!awsToken.tokenData.accessKeyId.startsWith('AKIA') || !awsToken.id) {
    throw new Error('Failed to generate valid AWS canary token');
  }
  console.log(`✔ Test 1 passed: Generated decoy AWS STS token (${awsToken.tokenData.accessKeyId}).`);

  // Test 2: Generate GitHub PAT Honeytoken
  const ghToken = await generateCloudHoneytoken('github', { label: 'decoy-repo-deploy' });
  if (!ghToken.tokenData.token.startsWith('ghp_')) {
    throw new Error('Failed to generate valid GitHub canary token');
  }
  console.log(`✔ Test 2 passed: Generated decoy GitHub PAT token (${ghToken.tokenData.token.substring(0, 10)}...).`);

  // Test 3: Plant Breadcrumbs into ConfigMap
  const configMapYaml = plantDecoyBreadcrumbs('configmap', awsToken);
  if (!configMapYaml.includes('kind: ConfigMap') || !configMapYaml.includes('AWS_ACCESS_KEY_ID: AKIA')) {
    throw new Error('Failed to plant breadcrumbs into ConfigMap');
  }
  console.log('✔ Test 3 passed: Successfully planted honeytoken breadcrumbs into Kubernetes ConfigMap.');

  // Test 4: Start In-Process Webhook Listener & Trigger Callback
  const trapListener = await startCanaryWebhookListener({ autoIsolate: true });
  console.log(`✔ Test 4a: Webhook listener active on port ${trapListener.port}`);

  // Simulate an intruder sending a GET request with the canary ID
  await new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${trapListener.port}/canary?cid=${awsToken.id}`, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve(data);
      });
    });
    req.on('error', reject);
  });

  // Verify that the canary asset was marked as tripped
  const canaries = await listActiveCanaries();
  const trippedAsset = canaries.find(c => c.id === awsToken.id);
  if (!trippedAsset || !trippedAsset.tripped) {
    throw new Error('Canary token not marked as tripped after webhook callback');
  }
  console.log(`✔ Test 4b passed: Webhook callback successfully tripped honeytoken and activated alarm.`);

  await trapListener.close();
  console.log('🎉 ALL 4 CLOUD HONEYTOKEN MESH TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Cloud Honeytoken test failure:', err);
  process.exit(1);
});
