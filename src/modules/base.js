/**
 * BaseModule represents the contract that all Vigilante modular packages must implement.
 */
export class BaseModule {
  /**
   * @param {Object} metadata
   * @param {string} metadata.id - Unique identifier for the module
   * @param {string} metadata.name - Human-readable display name
   * @param {string} metadata.description - Description of package capabilities
   * @param {string} [metadata.category='general'] - Category (e.g. 'siem', 'ids', 'telemetry', 'analytics')
   * @param {string} [metadata.version='1.0.0'] - Module version
   * @param {string[]} [metadata.dependencies=[]] - IDs of dependent modules
   * @param {boolean} [metadata.defaultEnabled=true] - Whether pre-selected by default
   */
  constructor({
    id,
    name,
    description,
    category = 'general',
    version = '1.0.0',
    dependencies = [],
    defaultEnabled = true
  }) {
    if (!id || !name) {
      throw new Error('BaseModule must be initialized with at least an id and name.');
    }
    this.id = id;
    this.name = name;
    this.description = description;
    this.category = category;
    this.version = version;
    this.dependencies = dependencies;
    this.defaultEnabled = defaultEnabled;
  }

  /**
   * Install the package onto the k3d cluster
   * @param {Object} context
   * @param {string} context.domain - Local domain (e.g. 'vigilante.local')
   * @param {string} context.certPath - Absolute path to domain TLS cert
   * @param {string} context.keyPath - Absolute path to domain TLS key
   * @param {string} [context.clusterName] - Target k3d cluster name
   * @param {Function} [context.onLog] - Real-time progress logger callback
   * @param {Object} [context.options] - Custom package options
   */
  async install(context) {
    throw new Error(`Module ${this.id} must implement the install() method.`);
  }

  /**
   * Uninstall the package and clean up cluster resources
   * @param {Object} context
   * @param {string} context.domain
   * @param {string} [context.clusterName]
   * @param {Function} [context.onLog]
   */
  async uninstall(context) {
    throw new Error(`Module ${this.id} must implement the uninstall() method.`);
  }

  /**
   * Check installation and health status of the module
   * @param {Object} context
   * @returns {Promise<{ installed: boolean, status: string, details?: any }>}
   */
  async status(context) {
    return {
      id: this.id,
      name: this.name,
      installed: false,
      status: 'unknown'
    };
  }

  /**
   * Get list of accessible web / API endpoints for this module
   * @param {Object} context
   * @param {string} context.domain
   * @returns {Promise<Array<{ name: string, url: string, description: string }>>}
   */
  async getEndpoints(context) {
    return [];
  }
}
