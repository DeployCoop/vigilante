import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { execa } from 'execa';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import {
  assertDnsLabel,
  getRedAiRangeBridgeFile,
  requireCtfFlagSecret,
  resolvePathInside
} from './config.js';
import { deriveTeamHmacFlag } from './kctf.js';
import { getClusterContextArgs, getKubeExecutionEnv } from './k8s.js';

export const AI_CTF_CATEGORY = {
  id: 'ai-redteam',
  name: 'AI Red Teaming (RedAiRange)',
  icon: '🤖',
  color: 'rose',
  description: 'Adversarial ML, prompt injection, model tampering, evasion & privacy attacks powered by RedAiRange'
};

export const REDAIRANGE_SCENARIOS = [
  {
    id: 'gen-ai-target',
    stackDir: 'gen_ai_target',
    name: 'Gen AI Target',
    kind: 'target',
    difficulty: 'Easy',
    port: 11001,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM01: Prompt Injection', 'LLM06: Sensitive Information Disclosure'],
    mitreAtlas: ['AML.T0051', 'AML.T0054'],
    description: 'Intentionally vulnerable Generative AI & LLM application target for practicing direct/indirect prompt injection, system prompt extraction, and guardrail bypass.',
    hints: [
      'Probe system-prompt boundaries with role-override and delimiter-breaking payloads.',
      'Inspect tool-calling or context-retrieval outputs for leaked internal tokens.'
    ],
    recommendedFalcoRules: ['Sensitive File Read in Container', 'Outbound Connection to Suspicious C2 Port'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'adversarial-playground',
    stackDir: 'adversarial_playground',
    name: 'Adversarial Playground',
    kind: 'target',
    difficulty: 'Easy',
    port: 11000,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM01: Prompt Injection', 'LLM03: Supply Chain'],
    mitreAtlas: ['AML.T0043', 'AML.T0048'],
    description: 'Interactive Jupyter-backed adversarial ML workbench for crafting perturbations, inspecting model confidence gradients, and testing classifier robustness.',
    hints: [
      'Open the Jupyter lab notebook on port 11000 and inspect the target classifier decision boundary.',
      'Try FGSM or PGD perturbations to shift classification confidence above the threshold.'
    ],
    recommendedFalcoRules: ['Terminal Shell in Container'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'evasion-attacks',
    stackDir: 'evasion_attacks',
    name: 'Evasion Attacks Lab',
    kind: 'target',
    difficulty: 'Medium',
    port: 11002,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM01: Prompt Injection', 'LLM02: Insecure Output Handling'],
    mitreAtlas: ['AML.T0015', 'AML.T0043'],
    description: 'Inference-time evasion scenario challenging operators to craft adversarial inputs that bypass ML security filters without modifying underlying weights.',
    hints: [
      'Measure sensitivity of the inference endpoint to small feature/token mutations.',
      'Chain encoding or homoglyph perturbations to evade the input classifier.'
    ],
    recommendedFalcoRules: ['Outbound Connection to Suspicious C2 Port'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'model-tampering',
    stackDir: 'model_tampering',
    name: 'Model Tampering & Poisoning',
    kind: 'target',
    difficulty: 'Hard',
    port: 11003,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM03: Supply Chain', 'LLM04: Data and Model Poisoning'],
    mitreAtlas: ['AML.T0018', 'AML.T0020'],
    description: 'ML supply-chain integrity lab demonstrating serialized weight tampering, pickle/safetensors backdoors, and trojan trigger activation.',
    hints: [
      'Audit model artifact integrity hashes and inspect serialization headers before loading.',
      'Trigger the hidden backdoor token sequence to expose the tampered output path.'
    ],
    recommendedFalcoRules: ['Write Below Binary Dir', 'Container Escape via Host Socket Mount'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'privacy-attacks',
    stackDir: 'privacy_attacks',
    name: 'Privacy & Data Extraction Attacks',
    kind: 'target',
    difficulty: 'Medium',
    port: 11004,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM06: Sensitive Information Disclosure'],
    mitreAtlas: ['AML.T0024', 'AML.T0025'],
    description: 'Privacy leakage lab targeting membership inference, model inversion, and memorized training-record extraction from exposed ML APIs.',
    hints: [
      'Compare prediction confidence distributions between member and non-member samples.',
      'Query high-entropy completion prefixes to surface memorized training secrets.'
    ],
    recommendedFalcoRules: ['Sensitive File Read in Container', 'Outbound Connection to Suspicious C2 Port'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'defense-ai-target',
    stackDir: 'defense_ai_target',
    name: 'Defense AI Target',
    kind: 'target',
    difficulty: 'Hard',
    port: 11005,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM01: Prompt Injection', 'LLM09: Overreliance'],
    mitreAtlas: ['AML.T0054', 'AML.T0051'],
    description: 'Blue-team defensive validation target equipped with input/output guardrails, prompt-firewall filters, and policy enforcement for purple-team testing.',
    hints: [
      'Map which policy rules fire on direct payloads vs multi-turn context smuggling.',
      'Verify whether defensive telemetry correlates with Falco / SIEM alerts.'
    ],
    recommendedFalcoRules: ['Terminal Shell in Container', 'Sensitive File Read in Container'],
    image: 'erdemozgen/redairange:1'
  },
  {
    id: 'blackcart-arsenal',
    stackDir: 'blackcart_arsenal',
    name: 'Blackcart Red Team Arsenal',
    kind: 'arsenal',
    difficulty: 'Medium',
    port: 11006,
    protocol: 'TCP',
    serviceType: 'HTTP',
    owaspLlm: ['LLM01: Prompt Injection', 'LLM07: System Prompt Leakage'],
    mitreAtlas: ['AML.T0040', 'AML.T0043'],
    description: 'Continuous Automated Red Teaming (CART) offensive toolkit container bundled for launching systematic probes against RedAiRange AI targets.',
    hints: [
      'Point Blackcart probes strictly at isolated target containers inside the DinD network.',
      'Export repeatable findings as JSON/Markdown evidence for Vigilante dossiers.'
    ],
    recommendedFalcoRules: ['Terminal Shell in Container'],
    image: 'erdemozgen/redairange:1'
  }
];

const SCENARIO_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

/**
 * Validate a RedAiRange scenario ID or stack directory slug.
 */
export function assertSafeScenarioId(scenarioId) {
  if (typeof scenarioId !== 'string' || !SCENARIO_ID_PATTERN.test(scenarioId)) {
    throw new Error(
      `Invalid RedAiRange scenario ID '${scenarioId}': expected lowercase alphanumerics, '-' or '_' (1-63 chars).`
    );
  }
  return scenarioId;
}

/**
 * Resolve a scenario stack directory strictly within stacksRoot (Rule 3 path containment).
 */
export function resolveSafeStackPath(stacksRoot, scenarioId) {
  const safeId = assertSafeScenarioId(scenarioId);
  return resolvePathInside(stacksRoot, safeId);
}

/**
 * Look up a built-in scenario by id or stackDir.
 */
export function getRedAiRangeScenario(scenarioId) {
  if (!scenarioId || typeof scenarioId !== 'string') return null;
  const normalized = scenarioId.trim().toLowerCase();
  return REDAIRANGE_SCENARIOS.find(
    (s) => s.id === normalized || s.stackDir === normalized
  ) || null;
}

/**
 * List RedAiRange scenarios with optional filters.
 */
export function listRedAiRangeScenarios({ kind = null, difficulty = null, search = null } = {}) {
  let list = [...REDAIRANGE_SCENARIOS];
  if (kind && kind !== 'all') {
    list = list.filter((s) => s.kind.toLowerCase() === String(kind).toLowerCase());
  }
  if (difficulty && difficulty !== 'all') {
    list = list.filter((s) => s.difficulty.toLowerCase() === String(difficulty).toLowerCase());
  }
  if (search) {
    const q = String(search).toLowerCase();
    list = list.filter(
      (s) =>
        s.id.includes(q) ||
        s.name.toLowerCase().includes(q) ||
        s.description.toLowerCase().includes(q) ||
        s.owaspLlm.some((o) => o.toLowerCase().includes(q)) ||
        s.mitreAtlas.some((m) => m.toLowerCase().includes(q))
    );
  }
  return list;
}

const FORBIDDEN_HOST_MOUNTS = [
  '/var/run/docker.sock',
  '/run/docker.sock',
  '/etc/shadow',
  '/etc/rancher',
  '/proc/sysrq-trigger',
  '/'
];

/**
 * Validate a RedAiRange scenario compose.yaml against Vigilante isolation guardrails.
 * Rejects host docker.sock mounts, host root mounts, and host PID/network escape configs.
 */
export function validateStackComposeYaml(rawYaml) {
  const errors = [];
  const warnings = [];

  if (typeof rawYaml !== 'string' || !rawYaml.trim()) {
    return { valid: false, errors: ['Compose YAML must be a non-empty string'], warnings, services: [] };
  }

  let doc;
  try {
    doc = yamlLoad(rawYaml);
  } catch (err) {
    return { valid: false, errors: [`Invalid YAML syntax: ${err.message}`], warnings, services: [] };
  }

  if (!doc || typeof doc !== 'object' || !doc.services || typeof doc.services !== 'object') {
    return { valid: false, errors: ['Compose manifest must define a top-level "services" map'], warnings, services: [] };
  }

  const serviceNames = Object.keys(doc.services);
  if (serviceNames.length === 0) {
    errors.push('Compose manifest must declare at least one service');
  }

  for (const svcName of serviceNames) {
    const svc = doc.services[svcName];
    if (!svc || typeof svc !== 'object') {
      errors.push(`Service '${svcName}' must be an object`);
      continue;
    }

    if (!svc.image && !svc.build) {
      errors.push(`Service '${svcName}' must define an "image" or "build" directive`);
    }

    if (svc.privileged === true) {
      errors.push(`Service '${svcName}' sets privileged: true, which is disallowed inside RedAiRange scenario stacks`);
    }

    if (svc.network_mode === 'host') {
      errors.push(`Service '${svcName}' uses network_mode: host, which violates DinD network isolation`);
    }

    if (svc.pid === 'host' || svc.ipc === 'host') {
      errors.push(`Service '${svcName}' shares host namespace (pid/ipc: host), which is disallowed`);
    }

    const volumes = Array.isArray(svc.volumes) ? svc.volumes : [];
    for (const vol of volumes) {
      const source = typeof vol === 'string' ? vol.split(':')[0]?.trim() : vol?.source;
      if (!source) continue;
      const normalizedSource = path.posix.normalize(source);
      if (
        FORBIDDEN_HOST_MOUNTS.includes(normalizedSource) ||
        normalizedSource.endsWith('docker.sock') ||
        normalizedSource === '/etc' ||
        normalizedSource === '/root'
      ) {
        errors.push(`Service '${svcName}' mounts forbidden host path '${source}'`);
      }
      if (source.includes('..')) {
        errors.push(`Service '${svcName}' volume source '${source}' contains path traversal ('..')`);
      }
    }

    if (typeof svc.image === 'string' && !svc.image.includes(':') && !svc.image.includes('@sha256:')) {
      warnings.push(`Service '${svcName}' image '${svc.image}' does not pin a tag or digest`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    services: serviceNames
  };
}

/**
 * Generate a hardened starter compose.yaml for a RedAiRange scenario stack.
 * When ctfFlag is supplied (AI-CTF bridge), injects it into the scenario container env.
 */
export function generateScenarioComposeYaml(scenarioId, {
  teamId = null,
  ctfFlag = null,
  port = null
} = {}) {
  const scenario = getRedAiRangeScenario(scenarioId);
  if (!scenario) {
    throw new Error(`Unknown RedAiRange scenario '${scenarioId}'`);
  }

  const targetPort = Number(port || scenario.port);
  if (!Number.isInteger(targetPort) || targetPort < 1024 || targetPort > 65535) {
    throw new Error(`Invalid scenario port '${port}': expected integer 1024-65535`);
  }

  const env = [
    `REDAIRANGE_SCENARIO=${scenario.id}`,
    `REDAIRANGE_KIND=${scenario.kind}`,
    `REDAIRANGE_OWASP=${scenario.owaspLlm.join(',')}`,
    `REDAIRANGE_MITRE_ATLAS=${scenario.mitreAtlas.join(',')}`
  ];

  if (teamId) {
    env.push(`VIGILANTE_TEAM_ID=${String(teamId).replace(/[^a-zA-Z0-9_-]/g, '')}`);
  }
  if (ctfFlag) {
    env.push(`VIGILANTE_CTF_FLAG=${ctfFlag}`);
  }

  const composeObj = {
    services: {
      [scenario.stackDir]: {
        image: 'python:3.11-slim',
        container_name: `rar-${scenario.id}`,
        restart: 'unless-stopped',
        ports: [`127.0.0.1:${targetPort}:8000`],
        environment: env,
        read_only: false,
        security_opt: ['no-new-privileges:true'],
        labels: {
          'vigilante.redairange.scenario': scenario.id,
          'vigilante.redairange.kind': scenario.kind,
          'vigilante.redairange.managed': 'true'
        },
        command: [
          'python3',
          '-m',
          'http.server',
          '8000'
        ]
      }
    },
    networks: {
      default: {
        name: 'redairange_isolated'
      }
    }
  };

  return yamlDump(composeObj, { lineWidth: 120, noRefs: true });
}

/**
 * Derive a per-team HMAC dynamic flag for a RedAiRange AI-CTF challenge.
 * Fails closed when VIGILANTE_CTF_SECRET (or explicit secretKey) is missing (Rule 2).
 */
export function deriveAiCtfFlag({ teamId = '', scenarioId = '', secretKey = null } = {}) {
  if (!teamId || typeof teamId !== 'string') {
    throw new Error('teamId is required to derive an AI-CTF flag');
  }
  const scenario = getRedAiRangeScenario(scenarioId);
  const cleanId = scenario ? scenario.id : assertSafeScenarioId(scenarioId);
  const challengeId = cleanId.startsWith('ai-') ? cleanId : `ai-${cleanId}`;
  requireCtfFlagSecret(secretKey);
  return deriveTeamHmacFlag({ teamId, challengeId, secretKey });
}

/**
 * Constant-time verification of a submitted flag for a bridged RedAiRange AI-CTF challenge.
 * Fails closed if no secret is configured or if the flag does not match the team's HMAC flag.
 */
export function verifyAiCtfFlag({ teamId = '', scenarioId = '', submittedFlag = '', secretKey = null } = {}) {
  if (!submittedFlag || typeof submittedFlag !== 'string') {
    return { valid: false, reason: 'Flag submission is required' };
  }
  const expected = deriveAiCtfFlag({ teamId, scenarioId, secretKey });
  const a = Buffer.from(submittedFlag.trim(), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    return { valid: false, reason: 'Flag does not match expected team HMAC digest' };
  }
  const ok = crypto.timingSafeEqual(a, b);
  return ok
    ? { valid: true, reason: 'Verified via fail-closed HMAC-SHA256' }
    : { valid: false, reason: 'Flag does not match expected team HMAC digest' };
}

/**
 * Redact flag and flag-bearing compose manifests before returning records over API/MCP.
 */
export function redactAiCtfRecord(record) {
  if (!record || typeof record !== 'object') return record;
  const { flag, composeYaml, ...safe } = record;
  return safe;
}

/**
 * Build CTF challenge templates derived from RedAiRange target scenarios for the Tournament Engine.
 */
export function buildAiCtfChallengeCatalog({ domain = 'vigilante.local', namespace = 'redairange' } = {}) {
  const isStandardNs = namespace === 'default' || namespace === 'redairange';
  const uiHost = isStandardNs ? `redairange.${domain}` : `${namespace}-redairange.${domain}`;

  return REDAIRANGE_SCENARIOS
    .filter((s) => s.kind === 'target')
    .map((s) => ({
      id: `ai-${s.id}`,
      scenarioId: s.id,
      stackDir: s.stackDir,
      name: `AI RedTeam: ${s.name}`,
      category: AI_CTF_CATEGORY.id,
      difficulty: s.difficulty,
      port: s.port,
      protocol: s.protocol,
      serviceType: s.serviceType,
      isDynamicFlag: true,
      source: 'redairange',
      owaspLlm: s.owaspLlm,
      mitreAtlas: s.mitreAtlas,
      description: s.description,
      hints: s.hints,
      rangeUiUrl: `https://${uiHost}`,
      recommendedFalcoRules: s.recommendedFalcoRules
    }));
}

/**
 * Load persisted bridged AI-CTF challenge records from XDG config dir.
 */
async function readBridgeStore() {
  const file = getRedAiRangeBridgeFile();
  try {
    if (!fsSync.existsSync(file)) return [];
    const raw = await fs.readFile(file, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeBridgeStore(records) {
  const file = getRedAiRangeBridgeFile();
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(records, null, 2), 'utf8');
  await fs.rename(tmp, file);
}

/**
 * Provision a RedAiRange scenario as a live or simulated AI-CTF challenge instance.
 * - Requires VIGILANTE_CTF_SECRET (Rule 2 fail-closed).
 * - In live mode (mock: false), seeds compose.yaml into the RedAiRange pod's /opt/stacks via kubectl exec (array argv).
 * - In mock/offline mode (mock: true), explicitly sets synthetic: true and runner: 'none' (Rule 4 D19 invariant).
 */
export async function provisionAiCtfChallenge({
  scenarioId = '',
  teamId = 'team-alpha',
  domain = 'vigilante.local',
  namespace = 'redairange',
  clusterName = 'vigilante-dev',
  provider = null,
  secretKey = null,
  mock = false
} = {}) {
  const scenario = getRedAiRangeScenario(scenarioId);
  if (!scenario) {
    throw new Error(`Unknown RedAiRange scenario '${scenarioId}'`);
  }
  assertDnsLabel(namespace, 'namespace');

  const cleanTeam = String(teamId || 'team-alpha').trim().replace(/[^a-zA-Z0-9_-]/g, '');
  if (!cleanTeam) {
    throw new Error('Invalid teamId for AI-CTF bridge');
  }

  // Fail-closed secret check & per-team HMAC flag derivation
  const flag = deriveAiCtfFlag({ teamId: cleanTeam, scenarioId: scenario.id, secretKey });
  const challengeId = `ai-${scenario.id}`;
  const bridgeId = `rar-${scenario.id}-${cleanTeam}-${crypto.randomBytes(3).toString('hex')}`;
  const stackSubdir = `${scenario.stackDir}_${cleanTeam}`;
  const stackPath = resolveSafeStackPath('/opt/stacks', stackSubdir);
  const composeYaml = generateScenarioComposeYaml(scenario.id, {
    teamId: cleanTeam,
    ctfFlag: flag,
    port: scenario.port
  });

  const validation = validateStackComposeYaml(composeYaml);
  if (!validation.valid) {
    throw new Error(`Generated scenario stack failed security validation: ${validation.errors.join('; ')}`);
  }

  const isStandardNs = namespace === 'default' || namespace === 'redairange';
  const uiUrl = isStandardNs ? `https://redairange.${domain}` : `https://${namespace}-redairange.${domain}`;

  let synthetic = Boolean(mock);
  let runner = mock ? 'none' : 'kubectl-exec';
  let status = mock ? 'simulated' : 'provisioned';

  if (!mock) {
    const kubeEnv = getKubeExecutionEnv();
    const ctxArgs = await getClusterContextArgs(clusterName, provider);
    try {
      const { stdout: podNameRaw } = await execa(
        'kubectl',
        [
          'get', 'pods',
          '-n', namespace,
          '-l', 'app.kubernetes.io/name=redairange',
          '-o', 'jsonpath={.items[0].metadata.name}',
          '--request-timeout=5s',
          ...ctxArgs
        ],
        { env: kubeEnv }
      );
      const podName = podNameRaw.trim();
      if (!podName) {
        throw new Error(`No running RedAiRange pod found in namespace '${namespace}'`);
      }

      const targetFile = `${stackPath}/compose.yaml`;
      // Write compose.yaml cleanly via stdin into the isolated RedAiRange pod container
      await execa(
        'kubectl',
        [
          'exec', '-i', podName,
          '-n', namespace,
          '-c', 'redairange',
          ...ctxArgs,
          '--',
          'sh', '-c', 'mkdir -p "$1" && cat > "$2"', '_', stackPath, targetFile
        ],
        { input: composeYaml, env: kubeEnv }
      );
    } catch (err) {
      throw new Error(`RedAiRange AI-CTF provisioning failed in cluster '${clusterName}': ${err.message}`);
    }
  }

  const record = {
    id: bridgeId,
    challengeId,
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    kind: scenario.kind,
    teamId: cleanTeam,
    namespace,
    clusterName,
    stackDir: stackSubdir,
    stackPath,
    port: scenario.port,
    rangeUiUrl: uiUrl,
    scenarioEndpoint: `http://127.0.0.1:${scenario.port}`,
    owaspLlm: scenario.owaspLlm,
    mitreAtlas: scenario.mitreAtlas,
    status,
    synthetic,
    runner,
    flag,
    composeYaml,
    createdAt: new Date().toISOString()
  };

  const existing = await readBridgeStore();
  existing.push(record);
  await writeBridgeStore(existing);

  return record;
}

/**
 * List bridged RedAiRange AI-CTF challenges (redacted by default).
 */
export async function listBridgedAiChallenges({ teamId = null, includeSecrets = false } = {}) {
  let records = await readBridgeStore();
  if (teamId) {
    records = records.filter((r) => r.teamId === teamId);
  }
  return includeSecrets ? records : records.map(redactAiCtfRecord);
}

/**
 * Tear down a bridged AI-CTF challenge from the registry (and pod stack directory when live).
 */
export async function teardownBridgedAiChallenge({
  bridgeId = '',
  clusterName = 'vigilante-dev',
  provider = null,
  mock = false
} = {}) {
  if (!bridgeId || typeof bridgeId !== 'string') {
    throw new Error('bridgeId is required');
  }
  const records = await readBridgeStore();
  const idx = records.findIndex((r) => r.id === bridgeId);
  if (idx === -1) {
    return { success: false, removed: false, error: `Bridged AI-CTF record '${bridgeId}' not found` };
  }

  const target = records[idx];
  if (!mock && !target.synthetic) {
    try {
      const kubeEnv = getKubeExecutionEnv();
      const ctxArgs = await getClusterContextArgs(target.clusterName || clusterName, provider);
      const { stdout: podNameRaw } = await execa(
        'kubectl',
        [
          'get', 'pods',
          '-n', target.namespace || 'redairange',
          '-l', 'app.kubernetes.io/name=redairange',
          '-o', 'jsonpath={.items[0].metadata.name}',
          '--request-timeout=5s',
          ...ctxArgs
        ],
        { env: kubeEnv }
      );
      const podName = podNameRaw.trim();
      if (podName && target.stackDir) {
        const safePath = resolveSafeStackPath('/opt/stacks', target.stackDir);
        await execa(
          'kubectl',
          [
            'exec', podName,
            '-n', target.namespace || 'redairange',
            '-c', 'redairange',
            ...ctxArgs,
            '--',
            'rm', '-rf', '--', safePath
          ],
          { env: kubeEnv }
        );
      }
    } catch {
      // Best-effort cleanup if pod is already gone
    }
  }

  records.splice(idx, 1);
  await writeBridgeStore(records);

  return {
    success: true,
    removed: true,
    bridgeId,
    scenarioId: target.scenarioId,
    teamId: target.teamId
  };
}

/**
 * Map a RedAiRange attack scenario to Vigilante Purple-Team / Falco eBPF telemetry & SOAR recommendations.
 */
export function evaluateAiAttackTelemetry(scenarioId) {
  const scenario = getRedAiRangeScenario(scenarioId);
  if (!scenario) {
    throw new Error(`Unknown RedAiRange scenario '${scenarioId}'`);
  }

  const telemetryMap = {
    'gen-ai-target': {
      falcoScenario: 'sensitive-file-read',
      suricataSignature: 'ET POLICY Suspicious LLM Prompt Exfiltration Pattern',
      recommendedSoar: 'ALERT_ONLY',
      purpleObjective: 'Verify prompt-injection leakage triggers egress DLP and SIEM correlation'
    },
    'adversarial-playground': {
      falcoScenario: 'shell-spawn',
      suricataSignature: 'ET INFO Jupyter Notebook Interactive Kernel Session',
      recommendedSoar: 'ALERT_ONLY',
      purpleObjective: 'Audit notebook container drift and unexpected child process execution'
    },
    'evasion-attacks': {
      falcoScenario: 'c2-connection',
      suricataSignature: 'ET POLICY High-Entropy Adversarial Inference Burst',
      recommendedSoar: 'BLOCK_IP',
      purpleObjective: 'Detect automated model querying and inference-evasion probing rates'
    },
    'model-tampering': {
      falcoScenario: 'container-escape',
      suricataSignature: 'ET MALWARE Suspicious Pickle/Model Weight Overwrite Activity',
      recommendedSoar: 'ISOLATE_POD',
      purpleObjective: 'Trigger Falco integrity alert on unauthorized writes to model artifact paths'
    },
    'privacy-attacks': {
      falcoScenario: 'sensitive-file-read',
      suricataSignature: 'ET POLICY Bulk Model Inversion / Training Data Extraction',
      recommendedSoar: 'ISOLATE_POD',
      purpleObjective: 'Detect high-volume membership inference queries and anomalous response sizes'
    },
    'defense-ai-target': {
      falcoScenario: 'shell-spawn',
      suricataSignature: 'ET POLICY Guardrail Bypass & Policy Engine Evasion Probe',
      recommendedSoar: 'ALERT_ONLY',
      purpleObjective: 'Validate defensive guardrail telemetry ingestion into OpenSearch / Vigil SOC'
    },
    'blackcart-arsenal': {
      falcoScenario: 'shell-spawn',
      suricataSignature: 'ET SCAN Automated AI Red-Team Tooling (Blackcart) Traffic',
      recommendedSoar: 'ALERT_ONLY',
      purpleObjective: 'Ensure automated red-team scans stay contained within isolated DinD network'
    }
  };

  const mapping = telemetryMap[scenario.id] || {
    falcoScenario: 'shell-spawn',
    suricataSignature: 'ET INFO AI Red Team Lab Traffic',
    recommendedSoar: 'ALERT_ONLY',
    purpleObjective: 'Correlate AI range activity with SOC telemetry'
  };

  return {
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    kind: scenario.kind,
    owaspLlm: scenario.owaspLlm,
    mitreAtlas: scenario.mitreAtlas,
    recommendedFalcoRules: scenario.recommendedFalcoRules,
    ...mapping
  };
}
