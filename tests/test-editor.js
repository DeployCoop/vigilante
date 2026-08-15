import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { ensureOverrideFileExists } from '../src/utils/editor.js';

async function runTests() {
  console.log('🧪 Testing Editor & Override Initializer...');

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-editor-'));
  const targetPath = path.join(tmpDir, 'values', 'vigil-soc', 'opensearch.yaml');
  const defaultPath = path.resolve('src/modules/vigil-soc/values/opensearch.yaml');

  // Test 1: ensureOverrideFileExists creates when missing
  const created = await ensureOverrideFileExists(targetPath, defaultPath, {
    domain: 'mytest.local',
    tlsSecretName: 'mytest-tls'
  });

  if (!created) {
    throw new Error('ensureOverrideFileExists should return true for newly created file');
  }

  const content = await fs.readFile(targetPath, 'utf8');
  if (!content.includes('singleNode: true')) {
    throw new Error(`Generated override missing expected contents: ${content}`);
  }
  console.log('✔ Test 1 passed: ensureOverrideFileExists initialized starter file.');

  // Test 2: ensureOverrideFileExists returns false if already exists
  const createdAgain = await ensureOverrideFileExists(targetPath, defaultPath);
  if (createdAgain) {
    throw new Error('ensureOverrideFileExists should return false when file already exists');
  }
  console.log('✔ Test 2 passed: ensureOverrideFileExists preserved existing file.');

  // Cleanup
  await fs.rm(tmpDir, { recursive: true, force: true });
  console.log('🎉 All Editor tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
