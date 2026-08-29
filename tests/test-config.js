import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  getXdgConfigHome,
  getVigilanteConfigDir,
  getVigilanteConfigFile,
  getVigilanteValuesDir,
  ensureVigilanteConfig,
  loadConfig,
  saveConfig
} from '../src/engine/config.js';
import { resolveTheme, THEMES } from '../src/ui/theme.js';
import { listChartValues, exportStarterValues } from '../src/engine/helm.js';

async function runTests() {
  console.log('🧪 Testing XDG Configuration & Theming Engine...');

  // Setup isolated XDG_CONFIG_HOME for testing
  const tempXdg = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-xdg-'));
  process.env.XDG_CONFIG_HOME = tempXdg;

  // Test 1: XDG Path Resolvers
  const configHome = getXdgConfigHome();
  const vigilanteDir = getVigilanteConfigDir();
  const configFile = getVigilanteConfigFile();
  const valuesDir = getVigilanteValuesDir();

  if (configHome !== tempXdg) throw new Error(`Expected ${tempXdg}, got ${configHome}`);
  if (vigilanteDir !== path.join(tempXdg, 'vigilante')) throw new Error(`Invalid vigilanteDir: ${vigilanteDir}`);
  if (configFile !== path.join(tempXdg, 'vigilante', 'config.yaml')) throw new Error(`Invalid configFile: ${configFile}`);
  if (valuesDir !== path.join(tempXdg, 'vigilante', 'values')) throw new Error(`Invalid valuesDir: ${valuesDir}`);
  console.log('✔ Test 1 passed: XDG directory and file paths resolved correctly.');

  // Test 2: ensureVigilanteConfig initializes directory and default config.yaml
  const initRes = await ensureVigilanteConfig();
  if (!initRes.created) throw new Error('Expected created=true on initial run');
  const exists = await fs.access(configFile).then(() => true).catch(() => false);
  if (!exists) throw new Error('config.yaml was not created');
  console.log('✔ Test 2 passed: ensureVigilanteConfig initialized default config.yaml and values directory.');

  // Test 3: loadConfig parses YAML defaults properly
  const config = loadConfig();
  if (config.theme?.name !== 'default') throw new Error(`Expected theme default, got: ${config.theme?.name}`);
  if (config.defaults?.domain !== 'vigilante.local') throw new Error(`Expected vigilante.local, got: ${config.defaults?.domain}`);
  if (!config.theme?.colors?.primary) throw new Error('Expected default primary color');
  if (config.hostr?.enabled !== true) throw new Error('Expected hostr.enabled default to be true');
  if (config.hostr?.autoSyncOnUp !== true) throw new Error('Expected hostr.autoSyncOnUp default to be true');
  if (config.hostr?.autoCleanOnDown !== true) throw new Error('Expected hostr.autoCleanOnDown default to be true');
  console.log('✔ Test 3 passed: loadConfig parsed config.yaml structure, defaults, and hostr settings.');

  // Test 4: saveConfig and custom theme / color persistence
  await saveConfig({
    theme: {
      name: 'dracula',
      colors: {
        primary: 'purple',
        header: 'magenta'
      }
    },
    defaults: {
      domain: 'custom.soc.local',
      clusterName: 'soc-cluster'
    },
    hostr: {
      enabled: false,
      autoSyncOnUp: false,
      autoCleanOnDown: true
    }
  });

  const updatedConfig = loadConfig();
  if (updatedConfig.theme?.name !== 'dracula') throw new Error(`Expected dracula, got ${updatedConfig.theme?.name}`);
  if (updatedConfig.theme?.colors?.primary !== 'purple') throw new Error('Expected purple primary override');
  if (updatedConfig.defaults?.domain !== 'custom.soc.local') throw new Error('Expected custom domain');
  if (updatedConfig.hostr?.enabled !== false) throw new Error('Expected hostr.enabled to be false');
  if (updatedConfig.hostr?.autoSyncOnUp !== false) throw new Error('Expected hostr.autoSyncOnUp to be false');
  console.log('✔ Test 4 passed: saveConfig persisted and reloaded customized settings including hostr toggle.');

  // Test 5: resolveTheme with built-in and overridden palettes
  const resolvedCyberpunk = resolveTheme({ theme: { name: 'cyberpunk' } });
  if (resolvedCyberpunk.primary !== THEMES.cyberpunk.primary) throw new Error('Cyberpunk theme mismatch');

  const resolvedDraculaCustom = resolveTheme(updatedConfig);
  if (resolvedDraculaCustom.name !== 'dracula') throw new Error('Dracula theme name mismatch');
  if (resolvedDraculaCustom.primary !== 'purple') throw new Error('Dracula custom color override mismatch');
  if (resolvedDraculaCustom.border !== THEMES.dracula.border) throw new Error('Dracula fallback color missing');
  console.log('✔ Test 5 passed: resolveTheme correctly merges predefined palettes and user color overrides.');

  // Test 6: Helm values export to XDG values directory
  const exportedXdg = await exportStarterValues({
    useXdg: true,
    domain: 'custom.soc.local'
  });
  if (exportedXdg.length === 0) throw new Error('Expected exported chart templates');
  const osValuesPath = path.join(valuesDir, 'opensearch', 'opensearch.yaml');
  const osExists = await fs.access(osValuesPath).then(() => true).catch(() => false);
  if (!osExists) throw new Error(`Expected exported values file at ${osValuesPath}`);
  console.log(`✔ Test 6 passed: exportStarterValues successfully populated $XDG_CONFIG_HOME/vigilante/values/ (${exportedXdg.length} files).`);

  // Test 7: listChartValues identifies active XDG override
  const chartItems = await listChartValues();
  const osItem = chartItems.find(c => c.chartName === 'opensearch');
  if (!osItem || !osItem.userOverridePath) {
    throw new Error('listChartValues should detect active override in XDG directory');
  }
  if (!osItem.userOverridePath.includes('opensearch.yaml')) {
    throw new Error(`Invalid override path: ${osItem.userOverridePath}`);
  }
  console.log('✔ Test 7 passed: listChartValues correctly discovers XDG values overrides.');

  // Cleanup
  await fs.rm(tempXdg, { recursive: true, force: true });
  console.log('🎉 All XDG Configuration & Theming Engine tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
