import { VigilSOCModule } from './vigil-soc/index.js';

export class ModuleRegistry {
  constructor() {
    this.modules = new Map();
    this.registerDefaultModules();
  }

  registerDefaultModules() {
    this.register(new VigilSOCModule());
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
}

export const globalModuleRegistry = new ModuleRegistry();
