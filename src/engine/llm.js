import fs from 'node:fs/promises';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { loadConfig, getVigilanteConfigDir, getVigilanteEvidenceDir } from './config.js';
import { listSavedXmlScans, readXmlScan } from './nmap-xml.js';
import { listEvidenceVault, listHostEvidence } from './evidence.js';
import { getPodsWide } from './pods.js';
import { listInstances } from './instances.js';
import { signFile } from './gpg.js';
import { globalModuleRegistry } from '../modules/registry.js';
import { listNistIncidents, NIST_ATTACK_VECTORS, NIST_LIFECYCLE_PHASES } from './nist.js';

/**
 * System prompt definition for the Vigilante AI Security Analyst (NIST SP 800-61 Rev. 2 Compliant)
 */
export const DEFAULT_SYSTEM_PROMPT = `You are Vigilante AI, an elite cybersecurity incident response handler, digital forensics investigator, and SOC defense engineer operating strictly within the NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide) framework.
You have direct access to real-time local network topology, Nmap XML scans, cryptographic Evidence Vault triage dumps (RFC 3227 Order of Volatility), and Kubernetes cluster telemetry provided by Vigilante.

Your core objectives:
1. Identify Precursors vs Indicators of compromise across network sweeps, open ports, service banners, and NSE script outputs.
2. Classify security incidents according to official NIST SP 800-61 Table 3-1 Attack Vectors (Web Application, Impersonation/MITM, Attrition, Improper Usage, etc.).
3. Calculate 3-Dimensional NIST Incident Prioritization (Functional Impact, Information Impact, Recoverability Effort) and determine containment urgency.
4. Review volatile forensic evidence (ARP tables, ICMP jitter, MTR route loss, X.509 certificate chains, HTTP response headers) with cryptographic chain-of-custody.
5. Provide prioritized containment, eradication, and recovery playbooks with executable commands (e.g. iptables, NetworkPolicy, openssl, kubectl, nmap).

Format your analysis clearly using Markdown with structured sections, bullet points, severity tags ([CRITICAL], [HIGH], [MEDIUM], [LOW]), MITRE ATT&CK technique IDs, and code blocks.`;

/**
 * Authoritative registry of all supported AI providers and their models
 */
export const SUPPORTED_PROVIDERS = [
  {
    id: 'ollama',
    name: 'Ollama',
    label: 'Ollama (Local & Offline)',
    icon: '🟢',
    type: 'local',
    envKey: 'OLLAMA_HOST',
    defaultModel: 'llama3.2',
    models: ['llama3.2', 'llama3.3', 'mistral', 'deepseek-r1', 'qwen2.5-coder', 'phi3']
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    label: 'Anthropic (Claude)',
    icon: '☁️',
    type: 'cloud',
    envKey: 'ANTHROPIC_API_KEY',
    defaultModel: 'claude-3-5-sonnet-20241022',
    models: [
      'claude-3-5-sonnet-20241022',
      'claude-3-5-haiku-20241022',
      'claude-3-7-sonnet',
      'claude-3-opus-20240229'
    ]
  },
  {
    id: 'openai',
    name: 'OpenAI',
    label: 'OpenAI (ChatGPT)',
    icon: '☁️',
    type: 'cloud',
    envKey: 'OPENAI_API_KEY',
    defaultModel: 'gpt-4o',
    models: [
      'gpt-4o',
      'gpt-4o-mini',
      'o3-mini',
      'o1',
      'gpt-4-turbo'
    ]
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    label: 'Google Gemini',
    icon: '☁️',
    type: 'cloud',
    envKey: 'GEMINI_API_KEY',
    defaultModel: 'gemini-2.0-flash',
    models: [
      'gemini-2.0-flash',
      'gemini-1.5-pro',
      'gemini-1.5-flash',
      'gemini-2.0-pro-exp-02-05'
    ]
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    label: 'DeepSeek AI',
    icon: '☁️',
    type: 'cloud',
    envKey: 'DEEPSEEK_API_KEY',
    defaultModel: 'deepseek-chat',
    models: [
      'deepseek-chat',
      'deepseek-reasoner'
    ]
  },
  {
    id: 'groq',
    name: 'Groq',
    label: 'Groq (Fast Cloud)',
    icon: '⚡',
    type: 'cloud',
    envKey: 'GROQ_API_KEY',
    defaultModel: 'llama-3.3-70b-versatile',
    models: [
      'llama-3.3-70b-versatile',
      'deepseek-r1-distill-llama-70b',
      'llama-3.1-8b-instant'
    ]
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    label: 'OpenRouter (Multi-Model)',
    icon: '🌐',
    type: 'cloud',
    envKey: 'OPENROUTER_API_KEY',
    defaultModel: 'anthropic/claude-3.5-sonnet',
    models: [
      'anthropic/claude-3.5-sonnet',
      'openai/gpt-4o',
      'deepseek/deepseek-r1',
      'meta-llama/llama-3.3-70b-instruct'
    ]
  }
];

/**
 * Inspect configured status for an AI provider
 * @param {string} providerId
 * @param {Object} [customCfg]
 * @returns {Object}
 */
export function getProviderStatus(providerId, customCfg = null) {
  const cfg = customCfg || loadConfig();
  const provider = SUPPORTED_PROVIDERS.find(p => p.id === providerId);
  if (!provider) return { id: providerId, isConfigured: false, statusText: 'Unknown Provider' };

  if (provider.id === 'ollama') {
    const host = getOllamaHost(cfg);
    return {
      ...provider,
      isConfigured: true,
      configuredKey: host,
      statusText: 'Local Offline'
    };
  }

  const keyFromEnv = provider.envKey ? process.env[provider.envKey] : null;
  const keyFromCfg = cfg.ai?.[provider.id]?.apiKey;
  const isConfigured = Boolean(keyFromEnv || keyFromCfg);

  return {
    ...provider,
    isConfigured,
    configuredKey: keyFromEnv ? `$${provider.envKey}` : keyFromCfg ? 'config.yaml' : null,
    statusText: isConfigured ? 'Ready (Key Configured)' : `Missing ($${provider.envKey})`
  };
}

// -------------------------------------------------------------
// 1. Ollama Provider (First-Class Local Engine)
// -------------------------------------------------------------

/**
 * Get normalized Ollama host URL
 * @param {Object} [config]
 * @returns {string}
 */
export function getOllamaHost(config = null) {
  let host = config?.ai?.ollama?.host || process.env.OLLAMA_HOST;
  if (!host) {
    const cfg = loadConfig();
    host = cfg.ai?.ollama?.host || 'http://localhost:11434';
  }
  if (!host.startsWith('http://') && !host.startsWith('https://')) {
    host = `http://${host}`;
  }
  return host.replace(/\/+$/, '');
}

/**
 * Check if local Ollama daemon is reachable
 * @param {string} [host]
 * @returns {Promise<{ ok: boolean, version?: string, error?: string }>}
 */
export async function checkOllamaHealth(host = null) {
  const targetHost = host || getOllamaHost();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(`${targetHost}/api/version`, {
      method: 'GET',
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { ok: true, version: data.version || 'unknown' };
    }
    return { ok: false, error: `HTTP ${res.status}: ${res.statusText}` };
  } catch (err) {
    return {
      ok: false,
      error: err.name === 'AbortError' ? 'Connection timed out' : err.message
    };
  }
}

/**
 * List all models installed in local Ollama
 * @param {string} [host]
 * @returns {Promise<Array<{ name: string, model: string, size: string, modifiedAt: string }>>}
 */
export async function listOllamaModels(host = null) {
  const targetHost = host || getOllamaHost();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`${targetHost}/api/tags`, {
      method: 'GET',
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`Ollama returned status ${res.status}`);
    }

    const data = await res.json();
    const rawModels = data.models || [];

    return rawModels.map((m) => {
      const sizeBytes = m.size || 0;
      const sizeGb = (sizeBytes / (1024 * 1024 * 1024)).toFixed(1);
      const sizeStr = sizeBytes > 0 ? `${sizeGb} GB` : '';
      const baseName = m.name?.split(':')[0] || m.name;

      return {
        name: m.name,
        model: baseName,
        size: sizeStr,
        modifiedAt: m.modified_at || ''
      };
    });
  } catch (err) {
    logger.debug('LLM:OLLAMA:LIST', `Failed to query Ollama models: ${err.message}`);
    return [];
  }
}

/**
 * Execute chat completion against Ollama
 * @param {Object} options
 * @param {string} [options.host]
 * @param {string} options.model
 * @param {Array<{ role: string, content: string }>} options.messages
 * @param {number} [options.temperature=0.2]
 * @param {Function} [options.onChunk]
 * @returns {Promise<string>}
 */
export async function chatOllama({
  host = null,
  model = 'llama3.2',
  messages = [],
  temperature = 0.2,
  onChunk = null,
  signal = null
}) {
  const targetHost = host || getOllamaHost();
  const isStreaming = typeof onChunk === 'function';

  logger.info('LLM:OLLAMA:CHAT', `Sending request to Ollama (${model}) at ${targetHost} (stream=${isStreaming})`);

  const response = await fetch(`${targetHost}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal,
    body: JSON.stringify({
      model,
      messages,
      stream: isStreaming,
      options: {
        temperature
      }
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Ollama API error (${response.status}): ${errBody || response.statusText}`);
  }

  if (!isStreaming) {
    const data = await response.json();
    if (data.error) {
      throw new Error(`Ollama error: ${data.error}`);
    }
    const content = data.message?.content || '';
    if (!content || !content.trim()) {
      throw new Error(`Empty response received from Ollama (${model}). The model produced no output (check VRAM or context length).`);
    }
    return content;
  }

  // Handle streaming reader
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf8');
  let fullContent = '';
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line);
        if (parsed.error) {
          throw new Error(`Ollama streaming error: ${parsed.error}`);
        }
        const chunk = parsed.message?.content || '';
        if (chunk) {
          fullContent += chunk;
          onChunk(chunk, fullContent);
        }
      } catch (err) {
        if (err.message && err.message.startsWith('Ollama streaming error:')) {
          throw err;
        }
        // Ignore incomplete JSON chunks in buffer
      }
    }
  }

  // Flush remaining buffer if any
  if (buffer.trim()) {
    try {
      const parsed = JSON.parse(buffer);
      if (parsed.error) {
        throw new Error(`Ollama streaming error: ${parsed.error}`);
      }
      const chunk = parsed.message?.content || '';
      if (chunk) {
        fullContent += chunk;
        onChunk(chunk, fullContent);
      }
    } catch (err) {
      if (err.message && err.message.startsWith('Ollama streaming error:')) {
        throw err;
      }
    }
  }

  if (!fullContent || !fullContent.trim()) {
    throw new Error(`Empty response stream received from Ollama (${model}). The model terminated without producing any text (possible VRAM exhaustion, model crash, or prompt limit).`);
  }

  return fullContent;
}

// -------------------------------------------------------------
// 2. Anthropic (Claude) Provider
// -------------------------------------------------------------

/**
 * Execute chat completion against Anthropic API
 * @param {Object} options
 * @returns {Promise<string>}
 */
export async function chatAnthropic({
  apiKey = null,
  model = 'claude-3-5-sonnet-20241022',
  messages = [],
  system = DEFAULT_SYSTEM_PROMPT,
  temperature = 0.2,
  onChunk = null,
  signal = null
}) {
  const cfg = loadConfig();
  const key = apiKey || process.env.ANTHROPIC_API_KEY || cfg.ai?.anthropic?.apiKey;

  if (!key) {
    throw new Error('Anthropic API key missing. Set $ANTHROPIC_API_KEY or configure in config.yaml');
  }

  // Filter messages to only user and assistant (system goes to top-level parameter)
  const filteredMessages = messages.filter(m => m.role === 'user' || m.role === 'assistant');

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model,
      max_tokens: 4096,
      system,
      messages: filteredMessages,
      temperature
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Anthropic API error (${response.status}): ${errBody}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(`Anthropic error: ${data.error?.message || JSON.stringify(data.error)}`);
  }

  const content = data.content?.[0]?.text || '';
  if (!content || !content.trim()) {
    throw new Error(`Empty response received from Anthropic (${model}). The model returned no text content.`);
  }

  if (onChunk) onChunk(content, content);
  return content;
}

// -------------------------------------------------------------
// 3. OpenAI (ChatGPT) Provider
// -------------------------------------------------------------

/**
 * Execute chat completion against OpenAI API
 * @param {Object} options
 * @returns {Promise<string>}
 */
export async function chatOpenAI({
  apiKey = null,
  model = 'gpt-4o',
  messages = [],
  temperature = 0.2,
  onChunk = null,
  signal = null
}) {
  const cfg = loadConfig();
  const key = apiKey || process.env.OPENAI_API_KEY || cfg.ai?.openai?.apiKey;

  if (!key) {
    throw new Error('OpenAI API key missing. Set $OPENAI_API_KEY or configure in config.yaml');
  }

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`
    },
    body: JSON.stringify({
      model,
      messages,
      temperature
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`OpenAI API error (${response.status}): ${errBody}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(`OpenAI error: ${data.error?.message || JSON.stringify(data.error)}`);
  }

  const content = data.choices?.[0]?.message?.content || '';
  if (!content || !content.trim()) {
    throw new Error(`Empty response received from OpenAI (${model}). The model returned no text content.`);
  }

  if (onChunk) onChunk(content, content);
  return content;
}

// -------------------------------------------------------------
// 4. Google (Gemini) Provider
// -------------------------------------------------------------

/**
 * Execute chat completion against Google Gemini API
 * @param {Object} options
 * @returns {Promise<string>}
 */
export async function chatGemini({
  apiKey = null,
  model = 'gemini-2.0-flash',
  messages = [],
  temperature = 0.2,
  onChunk = null,
  signal = null
}) {
  const cfg = loadConfig();
  const key = apiKey || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || cfg.ai?.gemini?.apiKey;

  if (!key) {
    throw new Error('Gemini API key missing. Set $GEMINI_API_KEY / $GOOGLE_API_KEY or configure in config.yaml');
  }

  // Format messages into Gemini contents
  const contents = messages
    .filter(m => m.role !== 'system')
    .map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    }));

  const systemMsg = messages.find(m => m.role === 'system');

  const payload = {
    contents,
    generationConfig: {
      temperature
    }
  };

  if (systemMsg) {
    payload.systemInstruction = {
      parts: [{ text: systemMsg.content }]
    };
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
  const response = await fetch(url, {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Gemini API error (${response.status}): ${errBody}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(`Gemini error: ${data.error?.message || JSON.stringify(data.error)}`);
  }

  const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (!content || !content.trim()) {
    const finishReason = data.candidates?.[0]?.finishReason;
    throw new Error(`Empty response received from Google Gemini (${model})${finishReason ? ` (Finish reason: ${finishReason})` : ''}.`);
  }

  if (onChunk) onChunk(content, content);
  return content;
}

// -------------------------------------------------------------
// 5. OpenAI-Compatible Generic Provider (DeepSeek, Groq, OpenRouter, Custom)
// -------------------------------------------------------------

/**
 * Generic OpenAI-compatible chat completion caller
 * @param {Object} options
 * @returns {Promise<string>}
 */
export async function chatOpenAICompatible({
  baseUrl,
  apiKey = null,
  envKey = null,
  providerName = 'API',
  model,
  messages = [],
  temperature = 0.2,
  onChunk = null,
  signal = null
}) {
  const cfg = loadConfig();
  const providerLower = providerName.toLowerCase();
  const key = apiKey || (envKey ? process.env[envKey] : null) || cfg.ai?.[providerLower]?.apiKey;

  if (!key) {
    throw new Error(`${providerName} API key missing. Set $${envKey || 'API_KEY'} or configure in config.yaml under ai.${providerLower}.apiKey`);
  }

  const cleanUrl = baseUrl.endsWith('/') ? `${baseUrl}chat/completions` : `${baseUrl}/chat/completions`;

  const response = await fetch(cleanUrl, {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`
    },
    body: JSON.stringify({
      model,
      messages,
      temperature
    })
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`${providerName} API error (${response.status}): ${errBody}`);
  }

  const data = await response.json();
  if (data.error) {
    throw new Error(`${providerName} error: ${data.error?.message || JSON.stringify(data.error)}`);
  }

  const content = data.choices?.[0]?.message?.content || '';
  if (!content || !content.trim()) {
    throw new Error(`Empty response received from ${providerName} (${model}). The model returned no text content.`);
  }

  if (onChunk) onChunk(content, content);
  return content;
}

/**
 * Execute chat completion against DeepSeek API
 */
export async function chatDeepSeek(opts) {
  return chatOpenAICompatible({
    baseUrl: 'https://api.deepseek.com',
    envKey: 'DEEPSEEK_API_KEY',
    providerName: 'DeepSeek',
    model: opts.model || 'deepseek-chat',
    ...opts
  });
}

/**
 * Execute chat completion against Groq Cloud API
 */
export async function chatGroq(opts) {
  return chatOpenAICompatible({
    baseUrl: 'https://api.groq.com/openai/v1',
    envKey: 'GROQ_API_KEY',
    providerName: 'Groq',
    model: opts.model || 'llama-3.3-70b-versatile',
    ...opts
  });
}

/**
 * Execute chat completion against OpenRouter API
 */
export async function chatOpenRouter(opts) {
  return chatOpenAICompatible({
    baseUrl: 'https://openrouter.ai/api/v1',
    envKey: 'OPENROUTER_API_KEY',
    providerName: 'OpenRouter',
    model: opts.model || 'anthropic/claude-3.5-sonnet',
    ...opts
  });
}

// -------------------------------------------------------------
// 6. MCP Telemetry Context Compiler
// -------------------------------------------------------------

/**
 * Compile real-time host, topology, evidence, and Kubernetes telemetry from MCP sources
 * @returns {Promise<string>} Formatted Markdown context block
 */
export async function compileMcpSecurityContext() {
  const sections = [];

  // A. Discovered Hosts & Open Ports from Nmap XML
  try {
    const xmlScans = await listSavedXmlScans();
    const hostMap = new Map();

    for (const scan of xmlScans) {
      try {
        const report = await readXmlScan(scan.filePath);
        for (const host of report.hosts) {
          if (!hostMap.has(host.ip) || (host.ports && host.ports.length > 0)) {
            hostMap.set(host.ip, {
              ...host,
              scanName: scan.filename,
              targetNet: report.summary?.target
            });
          }
        }
      } catch {
        // Ignore individual scan errors
      }
    }

    const hosts = Array.from(hostMap.values());
    if (hosts.length > 0) {
      let hostTable = '### Discovered Network Hosts & Ports (Nmap)\n';
      hostTable += '| IP Address | Hostname | OS Match | Open Ports & Services | Vulnerabilities / CVE Scripts |\n';
      hostTable += '|---|---|---|---|---|\n';

      for (const h of hosts) {
        const hostname = h.hostnames?.[0] || '<none>';
        const osMatch = h.osMatches?.[0]?.name || 'Unknown OS';
        const openPorts = (h.ports || [])
          .filter(p => p.state === 'open')
          .map(p => `${p.portId}/${p.protocol} (${p.service || 'unknown'}${p.version ? ` ${p.version}` : ''})`)
          .join(', ') || 'None open';

        const scripts = (h.ports || [])
          .flatMap(p => p.scripts || [])
          .map(s => `[${s.id}] ${s.output?.slice(0, 80)}...`)
          .join('; ') || 'None';

        hostTable += `| \`${h.ip}\` | \`${hostname}\` | ${osMatch} | ${openPorts} | ${scripts} |\n`;
      }
      sections.push(hostTable);
    } else {
      sections.push('### Discovered Network Hosts: (No XML scans saved yet. Run `vigilante scan` to discover hosts).');
    }
  } catch (err) {
    sections.push(`### Network Reconnaissance: Unavailable (${err.message})`);
  }

  // B. Incident Response Evidence Vault
  try {
    const vault = await listEvidenceVault();
    const networks = Array.isArray(vault) ? vault : [];
    if (networks.length > 0) {
      let evSection = '### Incident Response Evidence Vault Hierarchy (`net/host/data.ext`)\n';
      for (const net of networks) {
        evSection += `- **Network**: \`${net.network || net.dirName}\` (${net.hosts?.length || 0} hosts archived)\n`;
        for (const host of net.hosts || []) {
          const artifactNames = (host.artifacts || []).map(a => `${a.name}${a.isSigned ? ' (🔏 signed)' : ''}`).join(', ');
          evSection += `  - Host \`${host.ip}\`: ${artifactNames || 'No artifacts'}\n`;
        }
      }
      sections.push(evSection);
    } else {
      sections.push('### Evidence Vault: Empty (no active triage captures yet).');
    }
  } catch (err) {
    sections.push(`### Evidence Vault: Unavailable (${err.message})`);
  }

  // C. Active NIST SP 800-61 Rev. 2 Incident Manifests
  try {
    const nistIncidents = await listNistIncidents();
    if (nistIncidents.length > 0) {
      let nistSection = '### Active NIST SP 800-61 Rev. 2 Incident Records\n';
      nistSection += '| Incident ID | Target Host | Attack Vector | Severity | Functional | Information | SLA |\n';
      nistSection += '|---|---|---|---|---|---|---|\n';
      for (const inc of nistIncidents.slice(0, 10)) {
        const vec = inc.classification?.attackVector?.name || 'Unknown';
        const p = inc.prioritization || {};
        nistSection += `| \`${inc.incidentId}\` | \`${inc.target?.host}\` | ${vec} | **[${p.severity || 'UNKNOWN'}]** | ${p.functionalImpact || 'N/A'} | ${p.informationImpact || 'N/A'} | ${p.slaTargetMinutes || 60}m |\n`;
      }
      sections.push(nistSection);
    }
  } catch {
    // Ignore
  }

  // D. Live Kubernetes Infrastructure & Pod States
  try {
    const pods = await getPodsWide();
    if (pods.length > 0) {
      let podSection = '### Kubernetes Cluster Infrastructure (`kubectl get pods -A -o wide`)\n';
      podSection += '| Namespace | Pod Name | Ready | Status | Restarts | IP | Node |\n';
      podSection += '|---|---|---|---|---|---|---|\n';

      for (const p of pods.slice(0, 25)) {
        podSection += `| \`${p.namespace}\` | \`${p.name}\` | ${p.ready} | **${p.status}** | ${p.restarts} | \`${p.ip}\` | ${p.node} |\n`;
      }
      if (pods.length > 25) {
        podSection += `*(+ ${pods.length - 25} more pods in cluster)*\n`;
      }
      sections.push(podSection);
    }
  } catch (err) {
    // Cluster may not be running currently
  }

  // E. Vigilante Security Modules & Services
  try {
    const cfg = loadConfig();
    const domain = cfg.defaults?.domain || 'vigilante.local';
    const allModules = globalModuleRegistry.getAll();
    let modSection = '### Deployed Security Modules & Ingress Endpoints\n';
    for (const m of allModules) {
      const endpoints = await m.getEndpoints({ domain, namespace: 'default' });
      const epStr = endpoints.map(e => `\`${e.url}\` (${e.name})`).join(', ') || 'No web UI';
      modSection += `- **${m.name}** (\`${m.id}\`): ${epStr}\n`;
    }
    sections.push(modSection);
  } catch {
    // Ignore
  }

  return `=== VIGILANTE LIVE TELEMETRY & MCP CONTEXT ===\n\n${sections.join('\n\n')}\n\n=============================================`;
}

// -------------------------------------------------------------
// 6. Unified Inference Dispatcher
// -------------------------------------------------------------

/**
 * Execute unified security analyst query with live MCP context
 * @param {Object} options
 * @param {string} [options.provider] - 'ollama' | 'anthropic' | 'openai' | 'gemini'
 * @param {string} [options.model]
 * @param {Array<{ role: string, content: string }>} [options.messages]
 * @param {string} [options.prompt]
 * @param {string} [options.customContext]
 * @param {Function} [options.onChunk]
 * @returns {Promise<{ content: string, provider: string, model: string, timestamp: string }>}
 */
export async function runAnalystInference({
  provider = null,
  model = null,
  messages = [],
  prompt = null,
  customContext = null,
  onChunk = null,
  onStatusUpdate = null,
  signal = null
}) {
  const cfg = loadConfig();
  const effectiveProvider = provider || cfg.ai?.defaultProvider || 'ollama';

  // Report status
  onStatusUpdate?.('Compiling live MCP security context (hosts, subnets, pods, evidence vault)...');

  // Gather and compile live context
  const telemetryContext = customContext || await compileMcpSecurityContext();
  const systemContent = `${DEFAULT_SYSTEM_PROMPT}\n\n${telemetryContext}`;

  // Build full message thread
  const conversationMessages = [
    { role: 'system', content: systemContent }
  ];

  for (const msg of messages) {
    if (msg.role !== 'system') {
      conversationMessages.push(msg);
    }
  }

  if (prompt) {
    conversationMessages.push({ role: 'user', content: prompt });
  }

  let effectiveModel = model;
  let responseText = '';

  switch (effectiveProvider) {
    case 'ollama': {
      effectiveModel = model || cfg.ai?.ollama?.defaultModel || 'llama3.2';
      const host = getOllamaHost(cfg);
      onStatusUpdate?.(`Connecting to Ollama (${effectiveModel}) at ${host}...`);
      responseText = await chatOllama({
        host,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.ollama?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with Ollama (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'anthropic': {
      effectiveModel = model || cfg.ai?.anthropic?.defaultModel || 'claude-3-5-sonnet-20241022';
      onStatusUpdate?.(`Sending request to Anthropic (${effectiveModel})...`);
      responseText = await chatAnthropic({
        apiKey: cfg.ai?.anthropic?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        system: systemContent,
        temperature: cfg.ai?.anthropic?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with Claude (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'openai': {
      effectiveModel = model || cfg.ai?.openai?.defaultModel || 'gpt-4o';
      onStatusUpdate?.(`Sending request to OpenAI (${effectiveModel})...`);
      responseText = await chatOpenAI({
        apiKey: cfg.ai?.openai?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.openai?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with OpenAI (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'gemini': {
      effectiveModel = model || cfg.ai?.gemini?.defaultModel || 'gemini-2.0-flash';
      onStatusUpdate?.(`Sending request to Google Gemini (${effectiveModel})...`);
      responseText = await chatGemini({
        apiKey: cfg.ai?.gemini?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.gemini?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with Gemini (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'deepseek': {
      effectiveModel = model || cfg.ai?.deepseek?.defaultModel || 'deepseek-chat';
      onStatusUpdate?.(`Sending request to DeepSeek AI (${effectiveModel})...`);
      responseText = await chatDeepSeek({
        apiKey: cfg.ai?.deepseek?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.deepseek?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with DeepSeek (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'groq': {
      effectiveModel = model || cfg.ai?.groq?.defaultModel || 'llama-3.3-70b-versatile';
      onStatusUpdate?.(`Sending request to Groq (${effectiveModel})...`);
      responseText = await chatGroq({
        apiKey: cfg.ai?.groq?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.groq?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with Groq (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    case 'openrouter': {
      effectiveModel = model || cfg.ai?.openrouter?.defaultModel || 'anthropic/claude-3.5-sonnet';
      onStatusUpdate?.(`Sending request to OpenRouter (${effectiveModel})...`);
      responseText = await chatOpenRouter({
        apiKey: cfg.ai?.openrouter?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.openrouter?.temperature || 0.2,
        onChunk: (chunk, full) => {
          onStatusUpdate?.(`Generating response with OpenRouter (${effectiveModel})...`);
          if (onChunk) onChunk(chunk, full);
        },
        signal
      });
      break;
    }
    default:
      throw new Error(`Unsupported AI provider: '${effectiveProvider}'. Supported: ollama, anthropic, openai, gemini, deepseek, groq, openrouter`);
  }

  return {
    content: responseText,
    provider: effectiveProvider,
    model: effectiveModel,
    timestamp: new Date().toISOString()
  };
}

// -------------------------------------------------------------
// 7. Security Analysis Report Exporter
// -------------------------------------------------------------

/**
 * Save AI analysis report to the Evidence Vault and optionally sign with GPG
 * @param {string} topic
 * @param {string} content
 * @param {Object} [meta]
 * @returns {Promise<{ filePath: string, signaturePath?: string, isSigned: boolean }>}
 */
export async function saveAnalysisReport(topic, content, meta = {}) {
  const evidenceDir = getVigilanteEvidenceDir();
  const reportsDir = path.join(evidenceDir, 'ai_reports');
  await fs.mkdir(reportsDir, { recursive: true });

  const safeTopic = (topic || 'analysis').toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 30);
  const filename = `report-${Date.now()}-${safeTopic}.md`;
  const filePath = path.join(reportsDir, filename);

  const header = `# 🛡️ Vigilante Security & Forensics Analysis Report
**Topic**: ${topic}
**Date**: ${new Date().toUTCString()}
**Generated by**: ${meta.provider || 'AI'} (${meta.model || 'model'})
**Context Source**: Vigilante MCP Telemetry Engine

---

`;

  const fullReport = header + content;
  await fs.writeFile(filePath, fullReport, 'utf8');
  logger.info('LLM:REPORT:SAVE', `Saved AI analysis report to ${filePath}`);

  // Attempt GPG signature if configured
  const cfg = loadConfig();
  let signaturePath = null;
  let isSigned = false;

  if (cfg.gpg?.enabled) {
    try {
      const sigRes = await signFile(filePath, { keyId: cfg.gpg.keyId });
      signaturePath = sigRes.signaturePath;
      isSigned = true;
    } catch (err) {
      logger.warn('LLM:REPORT:GPG', `Failed to sign analysis report: ${err.message}`);
    }
  }

  return { filePath, signaturePath, isSigned, filename };
}
