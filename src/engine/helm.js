import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

/**
 * Replace template placeholders in values content
 * @param {string} content
 * @param {Object} context
 * @returns {string}
 */
export function renderTemplate(content, context = {}) {
  let rendered = content;
  const placeholders = {
    '{{DOMAIN}}': context.domain || 'vigilante.local',
    '{{TLS_SECRET}}': context.tlsSecretName || 'vigil-soc-tls',
    '{{NAMESPACE}}': context.namespace || 'default',
    '{{CLUSTER_NAME}}': context.clusterName || 'vigilante-dev'
  };

  for (const [key, val] of Object.entries(placeholders)) {
    rendered = rendered.replaceAll(key, val);
  }

  return rendered;
}

/**
 * Resolve Helm values arguments (-f default -f custom) for a chart
 * @param {Object} params
 * @param {string} params.moduleId - e.g. 'vigil-soc'
 * @param {string} params.chartName - e.g. 'opensearch' or 'opensearch-dashboards'
 * @param {string} params.defaultValuesPath - Path to module's default values.yaml
 * @param {string} [params.customValuesPath] - Explicit CLI values file
 * @param {string} [params.customValuesDir] - Explicit CLI values directory
 * @param {string} [params.domain='vigilante.local']
 * @param {string} [params.tlsSecretName='vigil-soc-tls']
 * @param {string} [params.namespace='default']
 * @param {string} [params.clusterName='vigilante-dev']
 * @param {Function} [params.onLog] - Optional logger
 * @returns {Promise<string[]>} Helm CLI args array (e.g. ['-f', 'path1', '-f', 'path2'])
 */
export async function resolveChartValuesArgs({
  moduleId,
  chartName,
  defaultValuesPath,
  customValuesPath,
  customValuesDir,
  domain = 'vigilante.local',
  tlsSecretName = 'vigil-soc-tls',
  namespace = 'default',
  clusterName = 'vigilante-dev',
  onLog = null
}) {
  const args = [];
  const cwd = process.cwd();

  // 1. Render default values template if available
  if (defaultValuesPath) {
    try {
      await fs.access(defaultValuesPath);
      const rawContent = await fs.readFile(defaultValuesPath, 'utf8');
      const renderedContent = renderTemplate(rawContent, {
        domain,
        tlsSecretName,
        namespace,
        clusterName
      });

      const tempDir = path.join(os.tmpdir(), 'vigilante-helm-values');
      await fs.mkdir(tempDir, { recursive: true });
      const renderedFilePath = path.join(tempDir, `${moduleId}-${chartName}-rendered.yaml`);
      await fs.writeFile(renderedFilePath, renderedContent, 'utf8');

      args.push('-f', renderedFilePath);
    } catch (err) {
      if (onLog) onLog(`[helm] Warning: Could not read default values at ${defaultValuesPath}: ${err.message}`);
    }
  }

  // 2. Discover user custom override files
  const candidatePaths = [];

  // A. Explicit CLI file passed
  if (customValuesPath) {
    candidatePaths.push(path.resolve(cwd, customValuesPath));
  }

  // B. Explicit CLI directory passed
  if (customValuesDir) {
    candidatePaths.push(path.resolve(cwd, customValuesDir, moduleId, `${chartName}.yaml`));
    candidatePaths.push(path.resolve(cwd, customValuesDir, moduleId, `${chartName}.yml`));
    candidatePaths.push(path.resolve(cwd, customValuesDir, `${chartName}.yaml`));
    candidatePaths.push(path.resolve(cwd, customValuesDir, `${chartName}.yml`));
  }

  // C. Default workspace ./values/<module>/<chart>.yaml or ./values/<chart>.yaml
  candidatePaths.push(path.resolve(cwd, 'values', moduleId, `${chartName}.yaml`));
  candidatePaths.push(path.resolve(cwd, 'values', moduleId, `${chartName}.yml`));
  candidatePaths.push(path.resolve(cwd, 'values', `${chartName}.yaml`));
  candidatePaths.push(path.resolve(cwd, 'values', `${chartName}.yml`));

  // D. Default workspace ./config/values/<module>/<chart>.yaml
  candidatePaths.push(path.resolve(cwd, 'config', 'values', moduleId, `${chartName}.yaml`));
  candidatePaths.push(path.resolve(cwd, 'config', 'values', moduleId, `${chartName}.yml`));
  candidatePaths.push(path.resolve(cwd, 'config', 'values', `${chartName}.yaml`));
  candidatePaths.push(path.resolve(cwd, 'config', 'values', `${chartName}.yml`));

  // Find first existing user custom file
  let appliedCustom = false;
  for (const candidate of candidatePaths) {
    try {
      await fs.access(candidate);
      if (onLog) onLog(`[helm] Applying custom values override: ${path.relative(cwd, candidate)}`);

      // Always render user custom file as well to resolve any {{DOMAIN}}, {{TLS_SECRET}}, etc.
      const rawUserContent = await fs.readFile(candidate, 'utf8');
      const renderedUserContent = renderTemplate(rawUserContent, {
        domain,
        tlsSecretName,
        namespace,
        clusterName
      });

      const tempDir = path.join(os.tmpdir(), 'vigilante-helm-values');
      await fs.mkdir(tempDir, { recursive: true });
      const userRenderedFilePath = path.join(tempDir, `${moduleId}-${chartName}-user-rendered.yaml`);
      await fs.writeFile(userRenderedFilePath, renderedUserContent, 'utf8');

      args.push('-f', userRenderedFilePath);
      appliedCustom = true;
      break;
    } catch {
      // File does not exist, check next candidate
    }
  }

  return args;
}

/**
 * Export default starter values files into target directory
 * @param {Object} options
 * @param {string} [options.moduleId] - Optional specific module to export
 * @param {string} [options.targetDir='./values'] - Destination directory
 * @param {string} [options.domain='vigilante.local']
 * @param {string} [options.clusterName='vigilante-dev']
 * @param {Function} [options.onLog]
 * @returns {Promise<Array<{ moduleId: string, chartName: string, destPath: string }>>}
 */
export async function exportStarterValues({
  moduleId = null,
  targetDir = './values',
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  onLog = null
} = {}) {
  const cwd = process.cwd();
  const destBase = path.resolve(cwd, targetDir);
  const exported = [];

  // Discover modules with values templates
  const modulesDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../modules');
  const availableModules = await getAvailableModuleIds(modulesDir);

  const targetModules = moduleId ? [moduleId] : availableModules;

  for (const mod of targetModules) {
    const modValuesDir = path.join(modulesDir, mod, 'values');
    try {
      const files = await fs.readdir(modValuesDir);
      const yamlFiles = files.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

      for (const file of yamlFiles) {
        const srcPath = path.join(modValuesDir, file);
        const modDestDir = path.join(destBase, mod);
        await fs.mkdir(modDestDir, { recursive: true });
        const destPath = path.join(modDestDir, file);

        const rawContent = await fs.readFile(srcPath, 'utf8');
        const rendered = renderTemplate(rawContent, {
          domain,
          tlsSecretName: `${mod}-tls`,
          namespace: mod,
          clusterName
        });

        await fs.writeFile(destPath, rendered, 'utf8');
        const chartName = file.replace(/\.(yaml|yml)$/, '');
        exported.push({ moduleId: mod, chartName, destPath });

        if (onLog) onLog(`✔ Exported starter values: ${path.relative(cwd, destPath)}`);
      }
    } catch (err) {
      if (onLog) onLog(`[helm] Note: No default values found for module '${mod}' (${err.message})`);
    }
  }

  return exported;
}

/**
 * Helper to discover modules that have a values directory
 */
async function getAvailableModuleIds(modulesDir) {
  const modIds = [];
  try {
    const entries = await fs.readdir(modulesDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        try {
          await fs.access(path.join(modulesDir, entry.name, 'values'));
          modIds.push(entry.name);
        } catch {
          // No values dir
        }
      }
    }
  } catch {
    // Ignore
  }
  return modIds.length > 0 ? modIds : ['opensearch', 'vigil-soc'];
}

/**
 * List all configurable chart values across modules and check for active user overrides
 * @param {Object} options
 * @param {string} [options.customValuesDir]
 * @returns {Promise<Array<{ moduleId: string, chartName: string, defaultPath: string, userOverridePath: string|null }>>}
 */
export async function listChartValues({ customValuesDir } = {}) {
  const cwd = process.cwd();
  const modulesDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../modules');
  const results = [];

  const availableModules = await getAvailableModuleIds(modulesDir);

  for (const mod of availableModules) {
    const modValuesDir = path.join(modulesDir, mod, 'values');
    try {
      const files = await fs.readdir(modValuesDir);
      const yamlFiles = files.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

      for (const file of yamlFiles) {
        const chartName = file.replace(/\.(yaml|yml)$/, '');
        const defaultPath = path.join(modValuesDir, file);

        // Check if user override exists
        let userOverridePath = null;
        const candidates = [
          path.resolve(cwd, 'values', mod, file),
          path.resolve(cwd, 'values', file),
          path.resolve(cwd, 'config', 'values', mod, file),
          path.resolve(cwd, 'config', 'values', file)
        ];

        if (customValuesDir) {
          candidates.unshift(path.resolve(cwd, customValuesDir, mod, file));
          candidates.unshift(path.resolve(cwd, customValuesDir, file));
        }

        for (const cand of candidates) {
          try {
            await fs.access(cand);
            userOverridePath = path.relative(cwd, cand);
            break;
          } catch {
            // Not found
          }
        }

        results.push({
          moduleId: mod,
          chartName,
          defaultPath: path.relative(cwd, defaultPath),
          userOverridePath
        });
      }
    } catch {
      // Ignore
    }
  }

  return results;
}
