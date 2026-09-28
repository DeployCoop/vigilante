import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  DEFAULT_DETECTOR_WASM_BYTES,
  loadWasmPlugin,
  executeWasmDetector,
  listWasmPlugins,
  installWasmPlugin
} from '../src/engine/wasm.js';

async function runTests() {
  console.log('🧪 Testing WebAssembly (Wasm) Extensible Detection & Containment Engine...');

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-wasm-'));
  process.env.XDG_CONFIG_HOME = tempDir;

  // Test 1: Load in-memory Wasm plugin
  const plugin = await loadWasmPlugin(DEFAULT_DETECTOR_WASM_BYTES);
  if (typeof plugin.exports.detect_threat !== 'function') {
    throw new Error('detect_threat was not exported by Wasm instance');
  }
  console.log('✔ Test 1 passed: Sandboxed WebAssembly plugin loaded and validated.');

  // Test 2: Execute Wasm detector on normal traffic
  const cleanVerdict = executeWasmDetector(plugin, { destPort: 80, rate: 10 });
  if (cleanVerdict.verdict !== 'CLEAN' || cleanVerdict.rawScore !== 90) {
    throw new Error(`Unexpected clean verdict: ${JSON.stringify(cleanVerdict)}`);
  }
  console.log(`✔ Test 2 passed: Normal event evaluated by Wasm: [${cleanVerdict.verdict}] (Score: ${cleanVerdict.rawScore}).`);

  // Test 3: Execute Wasm detector on anomalous traffic
  const threatVerdict = executeWasmDetector(plugin, { destPort: 445, rate: 800 });
  if (threatVerdict.verdict !== 'CRITICAL_ANOMALY' || threatVerdict.rawScore !== 1245) {
    throw new Error(`Unexpected threat verdict: ${JSON.stringify(threatVerdict)}`);
  }
  console.log(`✔ Test 3 passed: Anomalous event evaluated by Wasm: [${threatVerdict.verdict}] (Score: ${threatVerdict.rawScore}).`);

  // Test 4: Install and list persistent Wasm plugins
  const installedPath = await installWasmPlugin('custom-smb-detector', DEFAULT_DETECTOR_WASM_BYTES);
  const plugins = await listWasmPlugins();
  if (plugins.length !== 1 || plugins[0].name !== 'custom-smb-detector') {
    throw new Error(`Expected 1 installed plugin, got: ${plugins.length}`);
  }
  console.log(`✔ Test 4 passed: Plugin installed to disk and discovered in registry (${installedPath}).`);

  console.log('🎉 ALL 4 WASM PLUGIN TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Wasm test failure:', err);
  process.exit(1);
});
