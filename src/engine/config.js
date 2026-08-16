import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import { logger } from '../utils/logger.js';

/**
 * Get the XDG_CONFIG_HOME base directory
 * @returns {string}
 */
export function getXdgConfigHome() {
  return process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
}

/**
 * Get the Vigilante config directory within XDG_CONFIG_HOME
 * @returns {string}
 */
export function getVigilanteConfigDir() {
  return path.join(getXdgConfigHome(), 'vigilante');
}

/**
 * Get the full path to config.yaml
 * @returns {string}
 */
export function getVigilanteConfigFile() {
  return path.join(getVigilanteConfigDir(), 'config.yaml');
}

/**
 * Get the default values override directory within XDG_CONFIG_HOME
 * @returns {string}
 */
export function getVigilanteValuesDir() {
  return path.join(getVigilanteConfigDir(), 'values');
}

/**
 * Get the nmaps directory within XDG_CONFIG_HOME for saved scan results
 * @returns {string}
 */
export function getVigilanteNmapsDir() {
  return path.join(getVigilanteConfigDir(), 'nmaps');
}

/**
 * Get the evidence directory within XDG_CONFIG_HOME for incident response artifacts
 * @returns {string}
 */
export function getVigilanteEvidenceDir() {
  return path.join(getVigilanteConfigDir(), 'evidence');
}

/**
 * Sanitize a string for safe directory path component
 * @param {string} str
 * @returns {string}
 */
export function sanitizePathComponent(str) {
  if (!str) return 'unknown';
  return String(str).trim().replace(/\//g, '_').replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Get the specific evidence directory for a network and host
 * Structure: $XDG_CONFIG_HOME/vigilante/evidence/<network_cidr>/<host_ip>/
 * @param {string} networkCidr
 * @param {string} hostIp
 * @returns {string}
 */
export function getHostEvidenceDir(networkCidr, hostIp) {
  const netDir = sanitizePathComponent(networkCidr || 'local_network');
  const hostDir = sanitizePathComponent(hostIp || '127.0.0.1');
  return path.join(getVigilanteEvidenceDir(), netDir, hostDir);
}

/**
 * Default Vigilante Configuration Object
 */
export const DEFAULT_CONFIG = {
  theme: {
    name: 'default',
    colors: {
      primary: 'cyan',
      secondary: 'magenta',
      accent: 'yellow',
      success: 'green',
      warning: 'yellow',
      error: 'red',
      info: 'blue',
      muted: 'gray',
      border: 'cyan',
      text: 'white',
      header: 'cyan',
      selectedBg: 'gray',
      selectedText: 'yellow',
      banner: 'magenta'
    }
  },
  defaults: {
    domain: 'vigilante.local',
    clusterName: 'vigilante-dev',
    ip: '127.0.0.1',
    valuesDir: ''
  },
  hostr: {
    enabled: true,
    autoSyncOnUp: true,
    autoCleanOnDown: true
  },
  gpg: {
    enabled: false,
    keyId: '',
    autoSign: true,
    detached: true,
    armor: true,
    gnupgHome: ''
  },
  behavior: {
    autoWatchPods: true,
    podsPollIntervalMs: 2000
  }
};

/**
 * Default config.yaml template content with comments
 */
const DEFAULT_CONFIG_YAML = `# ==============================================================================
# Vigilante Configuration & Theming
# Location: $XDG_CONFIG_HOME/vigilante/config.yaml
# ==============================================================================

# Active Theme Configuration
# Predefined themes: default, cyberpunk, dracula, nord, matrix, monokai
theme:
  name: "default"
  
  # Custom color overrides (ANSI color names: cyan, magenta, yellow, green, red, blue, gray, white)
  colors:
    primary: "cyan"
    secondary: "magenta"
    accent: "yellow"
    success: "green"
    warning: "yellow"
    error: "red"
    info: "blue"
    muted: "gray"
    border: "cyan"
    text: "white"
    header: "cyan"
    selectedBg: "gray"
    selectedText: "yellow"
    banner: "magenta"

# Default CLI & Cluster Settings
defaults:
  domain: "vigilante.local"
  clusterName: "vigilante-dev"
  ip: "127.0.0.1"
  # Optional custom values directory (defaults to $XDG_CONFIG_HOME/vigilante/values)
  valuesDir: ""

# Host Resolution (hostr) Settings
# Controls automatic /etc/hosts management during cluster up/down workflows.
# Note: Even when disabled, manual 'vigilante hostr' or pressing [h] remains available.
hostr:
  enabled: true         # Set to false to disable all automatic /etc/hosts modifications
  autoSyncOnUp: true    # Automatically sync local domain mappings on 'vigilante up'
  autoCleanOnDown: true # Automatically clean up domain mappings on 'vigilante down'

# GPG Digital Signature & Evidence Integrity
# Signs evidence artifacts, scans, and reports at creation time for non-repudiation
gpg:
  enabled: false        # Set to true to enable cryptographic signing
  keyId: ""             # GPG Key ID, fingerprint, or email (e.g., security@vigilante.local)
  autoSign: true        # Automatically sign files upon creation
  detached: true        # Generate detached ASCII-armored signatures (.asc)
  gnupgHome: ""         # Optional custom GNUPGHOME directory path

# Runtime Monitor Behavior
behavior:
  autoWatchPods: true
  podsPollIntervalMs: 2000
`;

/**
 * Ensure the XDG config directories and default config.yaml exist
 * @returns {Promise<{ configDir: string, valuesDir: string, nmapsDir: string, configFile: string, created: boolean }>}
 */
export async function ensureVigilanteConfig() {
  const configDir = getVigilanteConfigDir();
  const valuesDir = getVigilanteValuesDir();
  const nmapsDir = getVigilanteNmapsDir();
  const evidenceDir = getVigilanteEvidenceDir();
  const configFile = getVigilanteConfigFile();
  let created = false;

  try {
    await fs.mkdir(valuesDir, { recursive: true });
    await fs.mkdir(nmapsDir, { recursive: true });
    await fs.mkdir(evidenceDir, { recursive: true });
    try {
      await fs.access(configFile);
    } catch {
      await fs.writeFile(configFile, DEFAULT_CONFIG_YAML, 'utf8');
      created = true;
      logger.info('CONFIG', `Initialized default config.yaml at ${configFile}`);
    }
  } catch (err) {
    logger.warn('CONFIG', `Failed to ensure config directories: ${err.message}`);
  }

  return { configDir, valuesDir, nmapsDir, evidenceDir, configFile, created };
}

/**
 * Synchronously ensure config directories exist (useful during startup/theme load)
 */
export function ensureVigilanteConfigSync() {
  const configDir = getVigilanteConfigDir();
  const valuesDir = getVigilanteValuesDir();
  const nmapsDir = getVigilanteNmapsDir();
  const evidenceDir = getVigilanteEvidenceDir();
  const configFile = getVigilanteConfigFile();

  try {
    if (!fsSync.existsSync(valuesDir)) {
      fsSync.mkdirSync(valuesDir, { recursive: true });
    }
    if (!fsSync.existsSync(nmapsDir)) {
      fsSync.mkdirSync(nmapsDir, { recursive: true });
    }
    if (!fsSync.existsSync(evidenceDir)) {
      fsSync.mkdirSync(evidenceDir, { recursive: true });
    }
    if (!fsSync.existsSync(configFile)) {
      fsSync.writeFileSync(configFile, DEFAULT_CONFIG_YAML, 'utf8');
    }
  } catch (err) {
    // Ignore sync fallback error
  }

  return { configDir, valuesDir, nmapsDir, evidenceDir, configFile };
}

/**
 * Load and parse the configuration from $XDG_CONFIG_HOME/vigilante/config.yaml
 * @returns {Object} Merged configuration object
 */
export function loadConfig() {
  ensureVigilanteConfigSync();
  const configFile = getVigilanteConfigFile();

  try {
    if (fsSync.existsSync(configFile)) {
      const raw = fsSync.readFileSync(configFile, 'utf8');
      const parsed = yamlLoad(raw);
      if (parsed && typeof parsed === 'object') {
        return {
          ...DEFAULT_CONFIG,
          ...parsed,
          theme: {
            name: parsed.theme?.name || DEFAULT_CONFIG.theme.name,
            colors: {
              ...(parsed.theme?.colors || {})
            }
          },
          defaults: {
            ...DEFAULT_CONFIG.defaults,
            ...(parsed.defaults || {})
          },
          hostr: {
            ...DEFAULT_CONFIG.hostr,
            ...(parsed.hostr || {})
          },
          gpg: {
            ...DEFAULT_CONFIG.gpg,
            ...(parsed.gpg || {})
          },
          behavior: {
            ...DEFAULT_CONFIG.behavior,
            ...(parsed.behavior || {})
          }
        };
      }
    }
  } catch (err) {
    logger.warn('CONFIG', `Could not parse ${configFile}: ${err.message}. Using defaults.`);
  }

  return { ...DEFAULT_CONFIG };
}

/**
 * Save configuration object to $XDG_CONFIG_HOME/vigilante/config.yaml
 * @param {Object} config
 */
export async function saveConfig(config) {
  const configFile = getVigilanteConfigFile();
  const dir = getVigilanteConfigDir();
  await fs.mkdir(dir, { recursive: true });
  const yamlStr = yamlDump(config, { indent: 2 });
  await fs.writeFile(configFile, yamlStr, 'utf8');
  logger.info('CONFIG', `Saved configuration to ${configFile}`);
}
