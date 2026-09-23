import { OpenSearchModule } from './opensearch/index.js';
import { VigilSOCModule } from './vigil-soc/index.js';
import { VigilLocalModule } from './vigil-local/index.js';
import { KCTFModule } from './kctf/index.js';
import { OpenVASModule } from './openvas/index.js';
import { WazuhModule } from './wazuh/index.js';

export class ModuleRegistry {
  constructor() {
    this.modules = new Map();
    this.registerDefaultModules();
  }

  registerDefaultModules() {
    this.register(new OpenSearchModule());
    this.register(new VigilSOCModule());
    this.register(new VigilLocalModule());
    this.register(new KCTFModule());
    this.register(new OpenVASModule());
    this.register(new WazuhModule());
  }

  /**
   * Register a module instance
   * @param {import('./base.js').BaseModule} moduleInstance
   */
  register(moduleInstance) {
    if (!moduleInstance.id) {
      throw new Error('Cannot register module without an id');
    }
    this.modules.set(moduleInstance.id, moduleInstance);
  }

  /**
   * Get a module by ID
   * @param {string} id
   */
  get(id) {
    return this.modules.get(id);
  }

  /**
   * Get all registered modules
   */
  getAll() {
    return Array.from(this.modules.values());
  }

  /**
   * Get all registered module IDs
   */
  getIds() {
    return Array.from(this.modules.keys());
  }

  /**
   * Resolve modules by IDs and compute dependency installation order
   * @param {string[]} requestedIds
   */
  resolveModules(requestedIds) {
    const resolved = [];
    const visited = new Set();
    const visiting = new Set();

    const resolve = (id) => {
      if (visiting.has(id)) {
        throw new Error(`Circular dependency detected involving module: ${id}`);
      }
      if (visited.has(id)) return;

      const mod = this.get(id);
      if (!mod) {
        throw new Error(`Module '${id}' is not registered.`);
      }

      visiting.add(id);

      for (const depId of mod.dependencies || []) {
        resolve(depId);
      }

      visiting.delete(id);
      visited.add(id);
      resolved.push(mod);
    };

    for (const id of requestedIds) {
      resolve(id);
    }

    return resolved;
  }

  /**
   * Uninstall a specific module from a cluster namespace
   */
  async uninstallModule({
    moduleId,
    namespace = 'default',
    clusterName = 'vigilante-dev',
    deleteNamespace = false,
    onLog = null
  }) {
    const mod = this.get(moduleId);
    if (!mod) {
      throw new Error(`Module '${moduleId}' is not registered.`);
    }

    if (onLog) {
      onLog(`[registry] Triggering uninstallation for module '${mod.name}' (${moduleId}) in namespace '${namespace}'...`);
    }

    await mod.uninstall({
      clusterName,
      namespace,
      deleteNamespace,
      onLog
    });

    return {
      success: true,
      moduleId,
      name: mod.name,
      namespace,
      clusterName,
      uninstalled: true
    };
  }

  /**
   * Reset and cleanly reinstall a specific module in-place
   */
  async resetModule({
    moduleId,
    domain = 'vigilante.local',
    namespace = 'default',
    clusterName = 'vigilante-dev',
    certPath = null,
    keyPath = null,
    options = {},
    onLog = null
  }) {
    const mod = this.get(moduleId);
    if (!mod) {
      throw new Error(`Module '${moduleId}' is not registered.`);
    }

    if (onLog) {
      onLog(`[registry] Resetting module '${mod.name}' (${moduleId}) in namespace '${namespace}'...`);
      onLog(`[registry] Phase 1/2: Uninstalling existing resources...`);
    }

    // Phase 1: Clean uninstall (preserving namespace)
    await mod.uninstall({
      clusterName,
      namespace,
      deleteNamespace: false,
      onLog
    });

    if (onLog) {
      onLog(`[registry] Phase 2/2: Reinstalling clean instance of '${mod.name}'...`);
    }

    // Phase 2: Fresh install
    await mod.install({
      domain,
      certPath,
      keyPath,
      clusterName,
      namespace,
      onLog,
      options
    });

    return {
      success: true,
      moduleId,
      name: mod.name,
      namespace,
      clusterName,
      reset: true
    };
  }
}

export const globalModuleRegistry = new ModuleRegistry();
