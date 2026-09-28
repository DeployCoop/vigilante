import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import {
  FalcoModule,
  SuricataModule,
  ZeekModule,
  ZAPModule,
  BloodHoundModule
} from '../src/index.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';

async function runTests() {
  console.log('🧪 Testing In-Cluster Threat Detection & Analysis Modules...');

  const modules = [
    { mod: new FalcoModule(), id: 'falco', expectedCategory: 'detection' },
    { mod: new SuricataModule(), id: 'suricata', expectedCategory: 'detection' },
    { mod: new ZeekModule(), id: 'zeek', expectedCategory: 'detection' },
    { mod: new ZAPModule(), id: 'zap', expectedCategory: 'recon' },
    { mod: new BloodHoundModule(), id: 'bloodhound', expectedCategory: 'recon' }
  ];

  // Test 1: Metadata and configuration
  for (const { mod, id, expectedCategory } of modules) {
    assert.strictEqual(mod.id, id);
    assert(mod.name.length > 0);
    assert.strictEqual(mod.category, expectedCategory);
    assert.strictEqual(mod.defaultEnabled, false);
    assert.deepStrictEqual(mod.dependencies, []);
  }
  console.log('✔ Test 1 passed: All 5 threat modules initialized with correct metadata.');

  // Test 2: Chart directories and templates exist
  for (const { id } of modules) {
    const chartPath = path.resolve(`src/modules/${id}/charts/${id}/Chart.yaml`);
    const valuesPath = path.resolve(`src/modules/${id}/charts/${id}/values.yaml`);
    const defaultVal = path.resolve(`src/modules/${id}/values/${id}.yaml`);
    const exampleVal = path.resolve(`values.example/${id}/${id}.yaml`);

    assert(await fs.access(chartPath).then(() => true).catch(() => false), `Missing Chart.yaml for ${id}`);
    assert(await fs.access(valuesPath).then(() => true).catch(() => false), `Missing values.yaml for ${id}`);
    assert(await fs.access(defaultVal).then(() => true).catch(() => false), `Missing default values for ${id}`);
    assert(await fs.access(exampleVal).then(() => true).catch(() => false), `Missing example values for ${id}`);
  }
  console.log('✔ Test 2 passed: Verified Helm charts and template files for all 5 modules.');

  // Test 3: Endpoints generation
  for (const { mod, id } of modules) {
    const eps = await mod.getEndpoints({ domain: 'lab.local', namespace: id });
    assert(Array.isArray(eps) && eps.length >= 1, `Endpoints should be generated for ${id}`);
    assert(eps[0].url.includes(`lab.local`), `URL should include lab.local for ${id}`);
  }
  console.log('✔ Test 3 passed: Endpoints correctly reflect domain and namespace.');

  // Test 4: Values templating with resolveChartValuesArgs
  for (const { id } of modules) {
    const defaultVal = path.resolve(`src/modules/${id}/values/${id}.yaml`);
    const args = await resolveChartValuesArgs({
      moduleId: id,
      chartName: id,
      defaultValuesPath: defaultVal,
      domain: 'lab.local',
      tlsSecretName: `${id}-tls`,
      namespace: id
    });
    assert(args.includes('-f'), `resolveChartValuesArgs should return -f flag for ${id}`);
  }
  console.log('✔ Test 4 passed: resolveChartValuesArgs successfully templated module values.');

  // Test 5: Status offline handling
  for (const { mod } of modules) {
    const st = await mod.status({ clusterName: 'nonexistent-cluster' });
    assert.strictEqual(st.installed, false);
    assert.strictEqual(st.status, 'Not Installed');
  }
  console.log('✔ Test 5 passed: status() reports Not Installed when cluster is offline.');

  console.log('🎉 ALL 5 THREAT MODULE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ Threat module test failed:', err);
  process.exit(1);
});
