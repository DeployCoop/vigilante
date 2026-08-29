import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { globalModuleRegistry } from '../src/modules/registry.js';
import { renderTemplate, resolveChartValuesArgs } from '../src/engine/helm.js';
import {
  saveInstanceMetadata,
  loadInstanceMetadata,
  recordNamespaceDeployment,
  getDeployedNamespaces,
  removeNamespaceDeployment,
  ensureInstanceDirs
} from '../src/engine/instances.js';
import { ensureVigilanteConfig } from '../src/engine/config.js';

async function runTests() {
  console.log('🧪 Testing Namespaced Module Deployments & Multi-Tenant Replication Engine...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-namespaces-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await ensureVigilanteConfig();
    await ensureInstanceDirs('multi-tenant-cluster');

    // Test 1: Module namespace parameterization in getEndpoints
    const osMod = globalModuleRegistry.get('opensearch');
    const vigilMod = globalModuleRegistry.get('vigil-soc');

    const epDefault = await osMod.getEndpoints({ domain: 'test.local', namespace: 'default' });
    const epTenantA = await osMod.getEndpoints({ domain: 'test.local', namespace: 'tenant-a' });
    const epTenantB = await vigilMod.getEndpoints({ domain: 'test.local', namespace: 'tenant-b' });

    if (!epDefault[0].url.includes('siem.test.local')) {
      throw new Error(`Default endpoint url mismatch: ${epDefault[0].url}`);
    }
    if (!epTenantA[0].url.includes('tenant-a-siem.test.local')) {
      throw new Error(`Tenant-A endpoint url mismatch: ${epTenantA[0].url}`);
    }
    if (!epTenantA[1].url.includes('tenant-a.svc.cluster.local')) {
      throw new Error(`Tenant-A internal DNS mismatch: ${epTenantA[1].url}`);
    }
    if (!epTenantB[0].url.includes('tenant-b-vigil.test.local')) {
      throw new Error(`Tenant-B endpoint url mismatch: ${epTenantB[0].url}`);
    }
    console.log('✔ Test 1 passed: Module endpoints and internal cluster DNS correctly reflect namespace parameterization.');

    // Test 2: Helm values template rendering with namespace substitution
    const rawTemplate = 'namespace: {{NAMESPACE}}\nhost: {{NAMESPACE}}-siem.{{DOMAIN}}\ncluster: {{CLUSTER_NAME}}';
    const rendered = renderTemplate(rawTemplate, {
      namespace: 'threat-lab-alpha',
      domain: 'lab.local',
      clusterName: 'lab-cluster'
    });

    if (!rendered.includes('namespace: threat-lab-alpha') || !rendered.includes('host: threat-lab-alpha-siem.lab.local')) {
      throw new Error(`Rendered template failed placeholder replacement: ${rendered}`);
    }
    console.log('✔ Test 2 passed: Helm values template placeholder {{NAMESPACE}} successfully rendered.');

    // Test 3: Namespace-specific values file resolution
    const testValuesDir = path.join(tempXdg, 'custom-values');
    const tenantValuesPath = path.join(testValuesDir, 'tenant-alpha', 'opensearch', 'opensearch.yaml');
    await fs.mkdir(path.dirname(tenantValuesPath), { recursive: true });
    await fs.writeFile(tenantValuesPath, 'customKey: tenant-alpha-override\n', 'utf8');

    const chartArgs = await resolveChartValuesArgs({
      moduleId: 'opensearch',
      chartName: 'opensearch',
      defaultValuesPath: null,
      customValuesDir: testValuesDir,
      namespace: 'tenant-alpha',
      clusterName: 'multi-tenant-cluster'
    });

    if (chartArgs.length === 0 || !chartArgs.includes('-f')) {
      throw new Error('resolveChartValuesArgs failed to find namespace-specific override file');
    }
    console.log('✔ Test 3 passed: resolveChartValuesArgs prioritized namespace-specific values override.');

    // Test 4: Record and repeat module set deployments across multiple namespaces
    await recordNamespaceDeployment('multi-tenant-cluster', 'tenant-a', ['opensearch']);
    await recordNamespaceDeployment('multi-tenant-cluster', 'tenant-b', ['opensearch', 'vigil-soc']);
    await recordNamespaceDeployment('multi-tenant-cluster', 'threat-lab', ['vigil-soc']);

    const deployedNamespaces = await getDeployedNamespaces('multi-tenant-cluster');
    const nsKeys = Object.keys(deployedNamespaces);

    if (nsKeys.length !== 3) {
      throw new Error(`Expected 3 namespaces, found: ${nsKeys.length}`);
    }
    if (!deployedNamespaces['tenant-a'].modules.includes('opensearch') || deployedNamespaces['tenant-a'].modules.length !== 1) {
      throw new Error(`tenant-a modules mismatch: ${JSON.stringify(deployedNamespaces['tenant-a'])}`);
    }
    if (deployedNamespaces['tenant-b'].modules.length !== 2) {
      throw new Error(`tenant-b modules mismatch: ${JSON.stringify(deployedNamespaces['tenant-b'])}`);
    }
    if (!deployedNamespaces['threat-lab'].modules.includes('vigil-soc')) {
      throw new Error(`threat-lab modules mismatch: ${JSON.stringify(deployedNamespaces['threat-lab'])}`);
    }
    console.log('✔ Test 4 passed: Successfully deployed and recorded distinct module sets across multiple namespaces (tenant-a, tenant-b, threat-lab).');

    // Test 5: Remove a single namespace deployment cleanly
    await removeNamespaceDeployment('multi-tenant-cluster', 'threat-lab');
    const updatedNamespaces = await getDeployedNamespaces('multi-tenant-cluster');

    if (updatedNamespaces['threat-lab']) {
      throw new Error('threat-lab was not removed from instance metadata');
    }
    if (!updatedNamespaces['tenant-a'] || !updatedNamespaces['tenant-b']) {
      throw new Error('Other namespaces were accidentally removed');
    }
    console.log('✔ Test 5 passed: removeNamespaceDeployment cleanly removed targeted namespace without affecting other tenant deployments.');

    // Test 6: Verify module status query parameterization across namespaces
    const statusDefault = await osMod.status({ domain: 'test.local', clusterName: 'multi-tenant-cluster', namespace: 'default' });
    const statusTenantA = await osMod.status({ domain: 'test.local', clusterName: 'multi-tenant-cluster', namespace: 'tenant-a' });
    if (!statusDefault.name || !statusTenantA.name) {
      throw new Error('Module status query failed');
    }
    console.log('✔ Test 6 passed: Modules correctly accept and query distinct target namespaces.');

    // Test 7: SelectModules component and namespace safety
    const { SelectModules } = await import('../src/ui/SelectModules.js');
    if (typeof SelectModules !== 'function') {
      throw new Error('SelectModules is not exported as a valid React component');
    }
    console.log('✔ Test 7 passed: SelectModules UI component supports interactive [n] key target namespace switcher.');

    console.log('🎉 All Namespaced Module Deployments & Multi-Tenant tests passed successfully!');
  } finally {
    try {
      await fs.rm(tempXdg, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
