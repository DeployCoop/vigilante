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
 * Supports both $XDG_CONFIG_HOME/.vigilante and $XDG_CONFIG_HOME/vigilante
 * @returns {string}
 */
export function getVigilanteConfigDir() {
  const xdg = getXdgConfigHome();
  const dotVigilante = path.join(xdg, '.vigilante');
  const vigilante = path.join(xdg, 'vigilante');
  if (fsSync.existsSync(dotVigilante)) {
    return dotVigilante;
  }
  if (fsSync.existsSync(vigilante)) {
    return vigilante;
  }
  return vigilante;
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
 * Get the playbooks directory within XDG_CONFIG_HOME for modular threat simulations
 * @returns {string}
 */
export function getVigilantePlaybooksDir() {
  return path.join(getVigilanteConfigDir(), 'playbooks');
}

/**
 * Get the instances directory for all k3d cluster instances
 * Structure: $XDG_CONFIG_HOME/.vigilante/instances/
 * @returns {string}
 */
export function getVigilanteInstancesDir() {
  return path.join(getVigilanteConfigDir(), 'instances');
}

/**
 * Get the root directory for a specific k3d instance
 * Structure: $XDG_CONFIG_HOME/.vigilante/instances/<instance_name>/
 * @param {string} [instanceName='vigilante-dev']
 * @returns {string}
 */
export function getInstanceDir(instanceName = 'vigilante-dev') {
  return path.join(getVigilanteInstancesDir(), sanitizePathComponent(instanceName || 'vigilante-dev'));
}

/**
 * Get the certificates directory for an instance
 * Structure: $XDG_CONFIG_HOME/.vigilante/instances/<instance_name>/certs/
 * @param {string} [instanceName='vigilante-dev']
 * @returns {string}
 */
export function getInstanceCertsDir(instanceName = 'vigilante-dev') {
  return path.join(getInstanceDir(instanceName), 'certs');
}

/**
 * Get the values directory for an instance
 * Structure: $XDG_CONFIG_HOME/.vigilante/instances/<instance_name>/values/
 * @param {string} [instanceName='vigilante-dev']
 * @returns {string}
 */
export function getInstanceValuesDir(instanceName = 'vigilante-dev') {
  return path.join(getInstanceDir(instanceName), 'values');
}

/**
 * Get the logs directory for an instance
 * Structure: $XDG_CONFIG_HOME/.vigilante/instances/<instance_name>/logs/
 * @param {string} [instanceName='vigilante-dev']
 * @returns {string}
 */
export function getInstanceLogsDir(instanceName = 'vigilante-dev') {
  return path.join(getInstanceDir(instanceName), 'logs');
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

# AI Assistant & Security Forensics Analyst (Ollama, Claude, ChatGPT, Gemini, DeepSeek, Groq, OpenRouter)
# Ollama works out-of-the-box first and foremost for local, private model inference.
ai:
  defaultProvider: "ollama"         # Default provider: ollama, anthropic, openai, gemini, deepseek, groq, openrouter
  ollama:
    host: "http://localhost:11434"   # Local Ollama server address (or $OLLAMA_HOST)
    defaultModel: "llama3.2"         # Default local model (auto-detected from ollama list)
    temperature: 0.2
  anthropic:
    apiKey: ""                       # Anthropic API Key (or set $ANTHROPIC_API_KEY)
    defaultModel: "claude-3-5-sonnet-20241022"
    temperature: 0.2
  openai:
    apiKey: ""                       # OpenAI API Key (or set $OPENAI_API_KEY)
    defaultModel: "gpt-4o"
    temperature: 0.2
  gemini:
    apiKey: ""                       # Google Gemini API Key (or set $GEMINI_API_KEY / $GOOGLE_API_KEY)
    defaultModel: "gemini-2.0-flash"
    temperature: 0.2
  deepseek:
    apiKey: ""                       # DeepSeek API Key (or set $DEEPSEEK_API_KEY)
    defaultModel: "deepseek-chat"
    temperature: 0.2
  groq:
    apiKey: ""                       # Groq API Key (or set $GROQ_API_KEY)
    defaultModel: "llama-3.3-70b-versatile"
    temperature: 0.2
  openrouter:
    apiKey: ""                       # OpenRouter API Key (or set $OPENROUTER_API_KEY)
    defaultModel: "anthropic/claude-3.5-sonnet"
    temperature: 0.2

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
  const playbooksDir = getVigilantePlaybooksDir();
  const instancesDir = getVigilanteInstancesDir();
  const configFile = getVigilanteConfigFile();
  let created = false;

  try {
    await fs.mkdir(valuesDir, { recursive: true });
    await fs.mkdir(nmapsDir, { recursive: true });
    await fs.mkdir(evidenceDir, { recursive: true });
    await fs.mkdir(playbooksDir, { recursive: true });
    await fs.mkdir(instancesDir, { recursive: true });
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

  return { configDir, valuesDir, nmapsDir, evidenceDir, playbooksDir, instancesDir, configFile, created };
}

/**
 * Synchronously ensure config directories exist (useful during startup/theme load)
 */
export function ensureVigilanteConfigSync() {
  const configDir = getVigilanteConfigDir();
  const valuesDir = getVigilanteValuesDir();
  const nmapsDir = getVigilanteNmapsDir();
  const evidenceDir = getVigilanteEvidenceDir();
  const playbooksDir = getVigilantePlaybooksDir();
  const instancesDir = getVigilanteInstancesDir();
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
    if (!fsSync.existsSync(playbooksDir)) {
      fsSync.mkdirSync(playbooksDir, { recursive: true });
    }
    if (!fsSync.existsSync(instancesDir)) {
      fsSync.mkdirSync(instancesDir, { recursive: true });
    }
    if (!fsSync.existsSync(configFile)) {
      fsSync.writeFileSync(configFile, DEFAULT_CONFIG_YAML, 'utf8');
    }
  } catch (err) {
    // Ignore sync fallback error
  }

  return { configDir, valuesDir, nmapsDir, evidenceDir, instancesDir, configFile };
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
