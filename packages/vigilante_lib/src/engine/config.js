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
  const dotExists = fsSync.existsSync(dotVigilante);
  const plainExists = fsSync.existsSync(vigilante);
  if (dotExists && plainExists) {
    // Both trees exist: the one holding a config.yaml is the live one.
    // The previous existence-only precedence let an empty '.vigilante'
    // directory appearing (another tool, a stray mkdir) silently orphan
    // a working 'vigilante' tree and all its state.
    const dotHasConfig = fsSync.existsSync(path.join(dotVigilante, 'config.yaml'));
    const plainHasConfig = fsSync.existsSync(path.join(vigilante, 'config.yaml'));
    if (plainHasConfig && !dotHasConfig) return vigilante;
    return dotVigilante;
  }
  if (dotExists) {
    return dotVigilante;
  }
  if (plainExists) {
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
 * Get the oobscans directory within XDG_CONFIG_HOME for saved out-of-band management scans
 * @returns {string}
 */
export function getVigilanteOobscansDir() {
  return path.join(getVigilanteConfigDir(), 'oobscans');
}

/**
 * Get the recon directory within XDG_CONFIG_HOME for fast network discovery scans (naabu/httpx)
 * @returns {string}
 */
export function getVigilanteReconDir() {
  return path.join(getVigilanteConfigDir(), 'recon');
}

/**
 * Get the nuclei directory within XDG_CONFIG_HOME for template-based CVE/vulnerability scans
 * @returns {string}
 */
export function getVigilanteNucleiDir() {
  return path.join(getVigilanteConfigDir(), 'nuclei');
}

/**
 * Get the trivy directory within XDG_CONFIG_HOME for container/k8s vulnerability audits
 * @returns {string}
 */
export function getVigilanteTrivyDir() {
  return path.join(getVigilanteConfigDir(), 'trivy');
}

/**
 * Get the kubeaudit directory within XDG_CONFIG_HOME for kube-bench and kube-hunter audits
 * @returns {string}
 */
export function getVigilanteKubeAuditDir() {
  return path.join(getVigilanteConfigDir(), 'kubeaudit');
}

/**
 * Get the netexec directory within XDG_CONFIG_HOME for protocol/credential audits
 * @returns {string}
 */
export function getVigilanteNetexecDir() {
  return path.join(getVigilanteConfigDir(), 'netexec');
}

/**
 * Get the zap directory within XDG_CONFIG_HOME for DAST web security audits
 * @returns {string}
 */
export function getVigilanteZapDir() {
  return path.join(getVigilanteConfigDir(), 'zap');
}

/**
 * Get the pcap dropzone/replay directory within XDG_CONFIG_HOME
 * @returns {string}
 */
export function getVigilantePcapDir() {
  return path.join(getVigilanteConfigDir(), 'pcap');
}

/**
 * Get the dossiers directory within XDG_CONFIG_HOME for Unified Host Dossiers
 * @returns {string}
 */
export function getVigilanteDossiersDir() {
  return path.join(getVigilanteConfigDir(), 'dossiers');
}

/**
 * Get the bloodhound directory within XDG_CONFIG_HOME for identity graph data
 * @returns {string}
 */
export function getVigilanteBloodhoundDir() {
  return path.join(getVigilanteConfigDir(), 'bloodhound');
}

/**
 * Get the containments directory within XDG_CONFIG_HOME for active SOAR isolation records
 * @returns {string}
 */
export function getVigilanteContainmentsDir() {
  return path.join(getVigilanteConfigDir(), 'containments');
}

/**
 * Get the cti directory within XDG_CONFIG_HOME for threat intelligence feeds and caches
 * @returns {string}
 */
export function getVigilanteCtiDir() {
  return path.join(getVigilanteConfigDir(), 'cti');
}

/**
 * Get the canary directory within XDG_CONFIG_HOME for honeytokens and deception assets
 * @returns {string}
 */
export function getVigilanteCanaryDir() {
  return path.join(getVigilanteConfigDir(), 'canary');
}

/**
 * Get the carved directory within XDG_CONFIG_HOME for files extracted from PCAPs
 * @returns {string}
 */
export function getVigilanteCarveDir() {
  return path.join(getVigilanteConfigDir(), 'carved');
}

/**
 * Get the datalake directory within XDG_CONFIG_HOME for embedded DuckDB analytics
 * @returns {string}
 */
export function getVigilanteDatalakeDir() {
  return path.join(getVigilanteConfigDir(), 'datalake');
}

/**
 * Get the wasm plugins directory within XDG_CONFIG_HOME for sandboxed extensions
 * @returns {string}
 */
export function getVigilanteWasmDir() {
  return path.join(getVigilanteConfigDir(), 'wasm');
}

/**
 * Get the purpleteam directory within XDG_CONFIG_HOME for adversarial wargame records
 * @returns {string}
 */
export function getVigilantePurpleDir() {
  return path.join(getVigilanteConfigDir(), 'purpleteam');
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
 * Get the user scenarios directory within XDG_CONFIG_HOME
 * @returns {string}
 */
export function getVigilanteScenariosDir() {
  return path.join(getVigilanteConfigDir(), 'scenarios');
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
  const cleaned = String(str).trim().replace(/\//g, '_').replace(/[^a-zA-Z0-9._-]/g, '_');
  // '.' and '..' are not valid single path components: they resolve to the
  // parent directory itself or its parent, escaping the intended base dir.
  if (!cleaned || cleaned === '.' || cleaned === '..') return 'unknown';
  return cleaned;
}

/**
 * Resolve path segments against a base directory, guaranteeing the result
 * stays inside that directory. Absolute segments are accepted only when
 * they already point inside the base. Throws on any escape attempt.
 * @param {string} baseDir
 * @param {...string} segments
 * @returns {string} Absolute path inside baseDir
 */
/**
 * Quote a value as a single POSIX shell word. Single quotes preserve every
 * character literally except the single quote itself, which is escaped as
 * '\'' — so $(...), backticks, semicolons, and spaces in the value can
 * never be interpreted by a shell. Use this whenever a value must appear
 * inside a shell string; prefer argv-array execution (execa/execFile)
 * wherever one is available instead.
 */
export function shQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

/**
 * Escape a value for embedding inside a double-quoted shell string:
 * backslash, the quote itself, `$`, and backtick are backslash-escaped, so
 * command substitution and parameter expansion cannot fire. Prefer shQuote
 * (single quotes) for new code; this exists for generated scripts whose
 * format depends on double quoting.
 */
export function shDoubleQuoteEscape(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/`/g, '\\`');
}

const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Kubernetes-style DNS label (lowercase alphanumerics and interior dashes). */
export function isValidDnsLabel(value) {
  return typeof value === 'string' && DNS_LABEL_PATTERN.test(value);
}

export function assertDnsLabel(value, label = 'value') {
  if (!isValidDnsLabel(value)) {
    throw new Error(`Invalid ${label} '${value}': expected a DNS label (lowercase letters, digits, and interior dashes, 1-63 chars)`);
  }
  return value;
}

const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

/** Dotted hostname (letters, digits, hyphens, dots; no empty labels). */
export function isValidHostname(value) {
  return typeof value === 'string' && HOSTNAME_PATTERN.test(value);
}

/**
 * Guard for values passed as positional arguments to CLI tools. Argv-array
 * execution already neutralizes shell metacharacters, but a value starting
 * with '-' is parsed as a flag by the receiving binary (flag injection:
 * dig -f, mkcert options, nmap -iL, ...), and whitespace/control characters
 * have no legitimate place in a target, name, or image reference.
 */
export function assertCliTarget(value, label = 'target') {
  const v = String(value ?? '');
  if (!v || v.startsWith('-') || /[\s\u0000-\u001f\u007f]/.test(v)) {
    throw new Error(`Invalid ${label} '${value}': must be non-empty, must not start with '-', and must not contain whitespace or control characters`);
  }
  return v;
}

export function resolvePathInside(baseDir, ...segments) {
  const base = path.resolve(baseDir);
  const target = path.resolve(base, ...segments);
  if (target !== base && !target.startsWith(base + path.sep)) {
    throw new Error(`Path '${segments.join('/')}' escapes its base directory '${base}'`);
  }
  return target;
}

/**
 * Assert that a resolved target path lies strictly inside a base directory
 * (used before recursive deletes, where targeting the base itself is never
 * legitimate). Throws when the target is the base or outside it.
 * @param {string} baseDir
 * @param {string} targetPath
 * @returns {string} The resolved target path
 */
export function assertPathStrictlyInside(baseDir, targetPath) {
  const base = path.resolve(baseDir);
  const target = path.resolve(targetPath);
  if (!target.startsWith(base + path.sep)) {
    throw new Error(`Refusing to operate on '${target}': not strictly inside '${base}'`);
  }
  return target;
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
/**
 * Get the file used to persist the CTF sandbox registry across processes
 * (the CLI, the Ink UI and the MCP server are separate processes)
 * @returns {string}
 */
export function getCtfSandboxesFile() {
  return path.join(getVigilanteConfigDir(), 'ctf-sandboxes.json');
}

/**
 * Resolve the HMAC secret used to derive and verify per-team CTF flags.
 * Order: explicit argument, the VIGILANTE_CTF_SECRET environment variable,
 * then `ctf.flagSecret` in config.yaml. Returns null when no secret is
 * configured — there is deliberately no built-in default, because a shipped
 * default secret makes every flag publicly derivable.
 * @param {string} [explicitSecret]
 * @returns {string|null}
 */
export function resolveCtfFlagSecret(explicitSecret) {
  if (explicitSecret) return explicitSecret;
  if (process.env.VIGILANTE_CTF_SECRET) return process.env.VIGILANTE_CTF_SECRET;
  try {
    const cfg = loadConfig();
    if (cfg && cfg.ctf && cfg.ctf.flagSecret) return cfg.ctf.flagSecret;
  } catch {
    // Config unreadable — treat the secret as unconfigured.
  }
  return null;
}

/**
 * Like resolveCtfFlagSecret, but fail closed: deriving or verifying a flag
 * without an operator-configured secret is refused outright.
 * @param {string} [explicitSecret]
 * @returns {string}
 */
export function requireCtfFlagSecret(explicitSecret) {
  const secret = resolveCtfFlagSecret(explicitSecret);
  if (!secret) {
    throw new Error(
      'CTF flag secret is not configured: set the VIGILANTE_CTF_SECRET environment variable or ctf.flagSecret in config.yaml. Flags are never derived from a built-in default.'
    );
  }
  return secret;
}

/**
 * Shared resolver for operator-provisioned signing keys. Order: explicit
 * argument, environment variable, then a config.yaml section key. Returns
 * null when unconfigured — cryptographic material is never defaulted to a
 * value shipped in the source tree, because anyone can read the source.
 */
function resolveProvisionedKey(explicitKey, envName, configSection, configKey) {
  if (explicitKey) return explicitKey;
  if (process.env[envName]) return process.env[envName];
  try {
    const cfg = loadConfig();
    if (cfg && cfg[configSection] && cfg[configSection][configKey]) {
      return cfg[configSection][configKey];
    }
  } catch {
    // Config unreadable — treat the key as unconfigured.
  }
  return null;
}

function requireProvisionedKey(explicitKey, envName, configSection, configKey, label) {
  const key = resolveProvisionedKey(explicitKey, envName, configSection, configKey);
  if (!key) {
    throw new Error(
      `${label} is not configured: set the ${envName} environment variable or ${configSection}.${configKey} in config.yaml. Signing keys are never taken from a built-in default.`
    );
  }
  return key;
}

/** HMAC key for the audit ledger (engine/ledger.js). */
export function resolveLedgerSigningSecret(explicitSecret) {
  return resolveProvisionedKey(explicitSecret, 'VIGILANTE_LEDGER_SECRET', 'ledger', 'signingSecret');
}

export function requireLedgerSigningSecret(explicitSecret) {
  return requireProvisionedKey(explicitSecret, 'VIGILANTE_LEDGER_SECRET', 'ledger', 'signingSecret', 'Ledger signing secret');
}

/** HMAC key for the RFC 3161 time-stamp authority (engine/evidencepack.js). */
export function resolveTsaKey(explicitKey) {
  return resolveProvisionedKey(explicitKey, 'VIGILANTE_TSA_KEY', 'evidencepack', 'tsaKey');
}

export function requireTsaKey(explicitKey) {
  return requireProvisionedKey(explicitKey, 'VIGILANTE_TSA_KEY', 'evidencepack', 'tsaKey', 'RFC 3161 TSA key');
}

/** HMAC key sealing forensic snapshots (engine/snapshot.js). */
export function resolveSnapshotSealingKey(explicitKey) {
  return resolveProvisionedKey(explicitKey, 'VIGILANTE_SNAPSHOT_KEY', 'snapshot', 'sealingKey');
}

export function requireSnapshotSealingKey(explicitKey) {
  return requireProvisionedKey(explicitKey, 'VIGILANTE_SNAPSHOT_KEY', 'snapshot', 'sealingKey', 'Snapshot sealing key');
}

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
    httpPort: 80,
    httpsPort: 443,
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
  modules: {
    vigilLocal: {
      chartPath: ''
    },
    kctf: {
      enabled: false,
      challengePortRange: '30000-32767',
      powDifficulty: 0
    },
    openvas: {
      enabled: false,
      feedRelease: '24.10',
      defaultProfile: 'full-and-fast'
    },
    wazuh: {
      enabled: false,
      version: '4.14.7'
    },
    flamingo: {
      enabled: false,
      protocols: 'ssh,snmp,ldap,http,dns,ftp'
    },
    oobscan: {
      enabled: true,
      defaultProfile: 'standard',
      disableLogins: false,
      linkLocalWait: '3s'
    },
    nuclei: {
      enabled: true,
      concurrency: 25,
      rateLimit: 150,
      severity: 'critical,high,medium'
    },
    recon: {
      enabled: true,
      naabuRate: 1000
    },
    trivy: {
      enabled: true,
      severity: 'CRITICAL,HIGH,MEDIUM'
    },
    kubeaudit: {
      enabled: true
    },
    netexec: {
      enabled: true
    },
    falco: {
      enabled: false
    },
    suricata: {
      enabled: false
    },
    zeek: {
      enabled: false
    },
    zap: {
      enabled: false
    },
    bloodhound: {
      enabled: false
    }
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
  # Host ports bound to the cluster ingress (per instance; change these
  # to run multiple instances side by side without port collisions)
  httpPort: 80
  httpsPort: 443
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

# Modular Package Configuration & Local Repositories
modules:
  vigilLocal:
    # Path to local checkout of Vigil SOC repository helm chart
    chartPath: ""
  flamingo:
    enabled: false
    protocols: "ssh,snmp,ldap,http,dns,ftp"
  falco:
    enabled: false
  suricata:
    enabled: false
  zeek:
    enabled: false
  zap:
    enabled: false
  bloodhound:
    enabled: false
  nuclei:
    enabled: true
    concurrency: 25
    rateLimit: 150
  trivy:
    enabled: true
    severity: "CRITICAL,HIGH,MEDIUM"
  recon:
    enabled: true

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
  const oobscansDir = getVigilanteOobscansDir();
  const reconDir = getVigilanteReconDir();
  const nucleiDir = getVigilanteNucleiDir();
  const trivyDir = getVigilanteTrivyDir();
  const kubeauditDir = getVigilanteKubeAuditDir();
  const netexecDir = getVigilanteNetexecDir();
  const zapDir = getVigilanteZapDir();
  const pcapDir = getVigilantePcapDir();
  const dossiersDir = getVigilanteDossiersDir();
  const bloodhoundDir = getVigilanteBloodhoundDir();
  const containmentsDir = getVigilanteContainmentsDir();
  const ctiDir = getVigilanteCtiDir();
  const canaryDir = getVigilanteCanaryDir();
  const carveDir = getVigilanteCarveDir();
  const datalakeDir = getVigilanteDatalakeDir();
  const wasmDir = getVigilanteWasmDir();
  const purpleDir = getVigilantePurpleDir();
  const evidenceDir = getVigilanteEvidenceDir();
  const playbooksDir = getVigilantePlaybooksDir();
  const scenariosDir = getVigilanteScenariosDir();
  const instancesDir = getVigilanteInstancesDir();
  const configFile = getVigilanteConfigFile();

  let created = false;

  try {
    await fs.mkdir(valuesDir, { recursive: true });
    await fs.mkdir(nmapsDir, { recursive: true });
    await fs.mkdir(oobscansDir, { recursive: true });
    await fs.mkdir(reconDir, { recursive: true });
    await fs.mkdir(nucleiDir, { recursive: true });
    await fs.mkdir(trivyDir, { recursive: true });
    await fs.mkdir(kubeauditDir, { recursive: true });
    await fs.mkdir(netexecDir, { recursive: true });
    await fs.mkdir(zapDir, { recursive: true });
    await fs.mkdir(pcapDir, { recursive: true });
    await fs.mkdir(dossiersDir, { recursive: true });
    await fs.mkdir(bloodhoundDir, { recursive: true });
    await fs.mkdir(containmentsDir, { recursive: true });
    await fs.mkdir(ctiDir, { recursive: true });
    await fs.mkdir(canaryDir, { recursive: true });
    await fs.mkdir(carveDir, { recursive: true });
    await fs.mkdir(datalakeDir, { recursive: true });
    await fs.mkdir(wasmDir, { recursive: true });
    await fs.mkdir(purpleDir, { recursive: true });
    await fs.mkdir(evidenceDir, { recursive: true });
    await fs.mkdir(playbooksDir, { recursive: true });
    await fs.mkdir(scenariosDir, { recursive: true });
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

  return {
    configDir,
    valuesDir,
    nmapsDir,
    oobscansDir,
    reconDir,
    nucleiDir,
    trivyDir,
    kubeauditDir,
    netexecDir,
    zapDir,
    pcapDir,
    dossiersDir,
    bloodhoundDir,
    containmentsDir,
    ctiDir,
    canaryDir,
    carveDir,
    datalakeDir,
    wasmDir,
    purpleDir,
    evidenceDir,
    playbooksDir,
    scenariosDir,
    instancesDir,
    configFile,
    created
  };
}

/**
 * Synchronously ensure config directories exist (useful during startup/theme load)
 */
export function ensureVigilanteConfigSync() {
  const configDir = getVigilanteConfigDir();
  const valuesDir = getVigilanteValuesDir();
  const nmapsDir = getVigilanteNmapsDir();
  const oobscansDir = getVigilanteOobscansDir();
  const reconDir = getVigilanteReconDir();
  const nucleiDir = getVigilanteNucleiDir();
  const trivyDir = getVigilanteTrivyDir();
  const kubeauditDir = getVigilanteKubeAuditDir();
  const netexecDir = getVigilanteNetexecDir();
  const zapDir = getVigilanteZapDir();
  const pcapDir = getVigilantePcapDir();
  const dossiersDir = getVigilanteDossiersDir();
  const bloodhoundDir = getVigilanteBloodhoundDir();
  const containmentsDir = getVigilanteContainmentsDir();
  const ctiDir = getVigilanteCtiDir();
  const canaryDir = getVigilanteCanaryDir();
  const carveDir = getVigilanteCarveDir();
  const datalakeDir = getVigilanteDatalakeDir();
  const wasmDir = getVigilanteWasmDir();
  const purpleDir = getVigilantePurpleDir();
  const evidenceDir = getVigilanteEvidenceDir();
  const playbooksDir = getVigilantePlaybooksDir();
  const scenariosDir = getVigilanteScenariosDir();
  const instancesDir = getVigilanteInstancesDir();
  const configFile = getVigilanteConfigFile();

  try {
    if (!fsSync.existsSync(valuesDir)) {
      fsSync.mkdirSync(valuesDir, { recursive: true });
    }
    if (!fsSync.existsSync(nmapsDir)) {
      fsSync.mkdirSync(nmapsDir, { recursive: true });
    }
    if (!fsSync.existsSync(oobscansDir)) {
      fsSync.mkdirSync(oobscansDir, { recursive: true });
    }
    if (!fsSync.existsSync(reconDir)) {
      fsSync.mkdirSync(reconDir, { recursive: true });
    }
    if (!fsSync.existsSync(nucleiDir)) {
      fsSync.mkdirSync(nucleiDir, { recursive: true });
    }
    if (!fsSync.existsSync(trivyDir)) {
      fsSync.mkdirSync(trivyDir, { recursive: true });
    }
    if (!fsSync.existsSync(kubeauditDir)) {
      fsSync.mkdirSync(kubeauditDir, { recursive: true });
    }
    if (!fsSync.existsSync(netexecDir)) {
      fsSync.mkdirSync(netexecDir, { recursive: true });
    }
    if (!fsSync.existsSync(zapDir)) {
      fsSync.mkdirSync(zapDir, { recursive: true });
    }
    if (!fsSync.existsSync(pcapDir)) {
      fsSync.mkdirSync(pcapDir, { recursive: true });
    }
    if (!fsSync.existsSync(dossiersDir)) {
      fsSync.mkdirSync(dossiersDir, { recursive: true });
    }
    if (!fsSync.existsSync(bloodhoundDir)) {
      fsSync.mkdirSync(bloodhoundDir, { recursive: true });
    }
    if (!fsSync.existsSync(containmentsDir)) {
      fsSync.mkdirSync(containmentsDir, { recursive: true });
    }
    if (!fsSync.existsSync(ctiDir)) {
      fsSync.mkdirSync(ctiDir, { recursive: true });
    }
    if (!fsSync.existsSync(canaryDir)) {
      fsSync.mkdirSync(canaryDir, { recursive: true });
    }
    if (!fsSync.existsSync(carveDir)) {
      fsSync.mkdirSync(carveDir, { recursive: true });
    }
    if (!fsSync.existsSync(datalakeDir)) {
      fsSync.mkdirSync(datalakeDir, { recursive: true });
    }
    if (!fsSync.existsSync(wasmDir)) {
      fsSync.mkdirSync(wasmDir, { recursive: true });
    }
    if (!fsSync.existsSync(purpleDir)) {
      fsSync.mkdirSync(purpleDir, { recursive: true });
    }
    if (!fsSync.existsSync(evidenceDir)) {
      fsSync.mkdirSync(evidenceDir, { recursive: true });
    }
    if (!fsSync.existsSync(playbooksDir)) {
      fsSync.mkdirSync(playbooksDir, { recursive: true });
    }
    if (!fsSync.existsSync(scenariosDir)) {
      fsSync.mkdirSync(scenariosDir, { recursive: true });
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

  return { configDir, valuesDir, nmapsDir, oobscansDir, evidenceDir, scenariosDir, instancesDir, configFile };
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
              // Deliberately NOT pre-merged over DEFAULT_CONFIG colors:
              // resolveTheme (the only consumer) merges these overrides
              // over the NAMED theme's palette — pre-merging here would
              // poison that fallback with the default palette.
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
          modules: {
            ...DEFAULT_CONFIG.modules,
            ...(parsed.modules || {}),
            vigilLocal: {
              ...DEFAULT_CONFIG.modules?.vigilLocal,
              ...(parsed.modules?.vigilLocal || {})
            },
            kctf: {
              ...DEFAULT_CONFIG.modules?.kctf,
              ...(parsed.modules?.kctf || {})
            },
            openvas: {
              ...DEFAULT_CONFIG.modules?.openvas,
              ...(parsed.modules?.openvas || {})
            },
            wazuh: {
              ...DEFAULT_CONFIG.modules?.wazuh,
              ...(parsed.modules?.wazuh || {})
            }
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
