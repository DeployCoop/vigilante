import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { renderTemplate, resolveChartValuesArgs, exportStarterValues, listChartValues } from '../src/engine/helm.js';

async function runTests() {
  console.log('🧪 Testing Helm Values Engine...');

  // Test 1: renderTemplate
  const tpl = 'host: siem.{{DOMAIN}}\nsecret: {{TLS_SECRET}}';
  const rendered = renderTemplate(tpl, { domain: 'test.local', tlsSecretName: 'test-tls' });
  if (!rendered.includes('host: siem.test.local') || !rendered.includes('secret: test-tls')) {
    throw new Error(`renderTemplate failed: ${rendered}`);
  }
  console.log('✔ Test 1 passed: renderTemplate accurately substituted placeholders.');

  // Test 2: resolveChartValuesArgs (defaults)
  const defaultPath = path.resolve('src/modules/vigil-soc/values/opensearch.yaml');
  const defaultArgs = await resolveChartValuesArgs({
    moduleId: 'vigil-soc',
    chartName: 'opensearch',
    defaultValuesPath: defaultPath,
    domain: 'vigilante.local',
    tlsSecretName: 'vigil-soc-tls'
  });

  if (defaultArgs[0] !== '-f' || !defaultArgs[1].includes('opensearch-rendered.yaml')) {
    throw new Error(`resolveChartValuesArgs failed for defaults: ${JSON.stringify(defaultArgs)}`);
  }
  const renderedContent = await fs.readFile(defaultArgs[1], 'utf8');
  if (!renderedContent.includes('singleNode: true')) {
    throw new Error(`Rendered default values missing expected contents: ${renderedContent}`);
  }
  console.log('✔ Test 2 passed: Default chart values resolved and rendered successfully.');

  // Test 3: resolveChartValuesArgs with custom override
  const tmpOverrideDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-values-'));
  const customOverrideFile = path.join(tmpOverrideDir, 'opensearch.yaml');
  await fs.writeFile(customOverrideFile, 'persistence:\n  enabled: true\n', 'utf8');

  const customArgs = await resolveChartValuesArgs({
    moduleId: 'vigil-soc',
    chartName: 'opensearch',
    defaultValuesPath: defaultPath,
    customValuesPath: customOverrideFile,
    domain: 'vigilante.local'
  });

  if (customArgs.length !== 4 || customArgs[2] !== '-f') {
    throw new Error(`resolveChartValuesArgs failed to include custom override: ${JSON.stringify(customArgs)}`);
  }
  const customRenderedContent = await fs.readFile(customArgs[3], 'utf8');
  if (!customRenderedContent.includes('persistence:') || !customRenderedContent.includes('enabled: true')) {
    throw new Error(`Rendered custom values missing expected content: ${customRenderedContent}`);
  }
  console.log('✔ Test 3 passed: Custom override values file correctly rendered and layered.');

  // Test 4: exportStarterValues
  const exportTargetDir = path.join(tmpOverrideDir, 'exported-values');
  const exported = await exportStarterValues({
    moduleId: 'vigil-soc',
    targetDir: exportTargetDir
  });

  if (exported.length < 2) {
    throw new Error(`exportStarterValues failed, expected at least 2 files, got ${exported.length}`);
  }
  console.log(`✔ Test 4 passed: Exported ${exported.length} starter YAML files to ${exportTargetDir}`);

  // Test 5: listChartValues
  const listed = await listChartValues({ customValuesDir: tmpOverrideDir });
  if (listed.length < 2) {
    throw new Error(`listChartValues failed, got: ${JSON.stringify(listed)}`);
  }
  console.log('✔ Test 5 passed: listChartValues returned chart definitions.');

  // Cleanup
  await fs.rm(tmpOverrideDir, { recursive: true, force: true });
  console.log('🎉 All Helm Values Engine tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
