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

/**
 * System prompt definition for the Vigilante AI Security Analyst
 */
export const DEFAULT_SYSTEM_PROMPT = `You are Vigilante AI, an expert cybersecurity incident responder, network defense engineer, and SOC forensic analyst.
You have direct access to the local infrastructure, network reconnaissance scans, Evidence Vault triage dumps, and Kubernetes telemetry provided by Vigilante.

Your role:
1. Analyze network topology, open ports, banners, and CVE script outputs.
2. Identify anomalous host behaviors, security risks, misconfigurations, and attack surfaces.
3. Review forensic evidence (ping jitter, MTR route loss, TLS certificate chains, HTTP headers, ARP neighbor caches).
4. Inspect Kubernetes pods and workloads for health issues, CrashLoopBackOff states, and cluster anomalies.
5. Provide concise, prioritized, and actionable defense and remediation advice with practical commands (e.g. iptables, openssl, kubectl, nmap).

Format your analysis clearly using Markdown with sections, bullet points, severity tags ([CRITICAL], [HIGH], [MEDIUM], [LOW]), and code blocks.`;

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
  onChunk = null
}) {
  const targetHost = host || getOllamaHost();
  const isStreaming = typeof onChunk === 'function';

  logger.info('LLM:OLLAMA:CHAT', `Sending request to Ollama (${model}) at ${targetHost} (stream=${isStreaming})`);

  const response = await fetch(`${targetHost}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
    return data.message?.content || '';
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
        const chunk = parsed.message?.content || '';
        if (chunk) {
          fullContent += chunk;
          onChunk(chunk, fullContent);
        }
      } catch {
        // Ignore incomplete JSON chunks in buffer
      }
    }
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
  onChunk = null
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
  const content = data.content?.[0]?.text || '';
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
  onChunk = null
}) {
  const cfg = loadConfig();
  const key = apiKey || process.env.OPENAI_API_KEY || cfg.ai?.openai?.apiKey;

  if (!key) {
    throw new Error('OpenAI API key missing. Set $OPENAI_API_KEY or configure in config.yaml');
  }

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
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
  const content = data.choices?.[0]?.message?.content || '';
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
  onChunk = null
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
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Gemini API error (${response.status}): ${errBody}`);
  }

  const data = await response.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (onChunk) onChunk(content, content);
  return content;
}

// -------------------------------------------------------------
// 5. MCP Telemetry Context Compiler
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

  // C. Live Kubernetes Infrastructure & Pod States
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

  // D. Vigilante Security Modules & Services
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
  onChunk = null
}) {
  const cfg = loadConfig();
  const effectiveProvider = provider || cfg.ai?.defaultProvider || 'ollama';

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
      responseText = await chatOllama({
        host,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.ollama?.temperature || 0.2,
        onChunk
      });
      break;
    }
    case 'anthropic': {
      effectiveModel = model || cfg.ai?.anthropic?.defaultModel || 'claude-3-5-sonnet-20241022';
      responseText = await chatAnthropic({
        apiKey: cfg.ai?.anthropic?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        system: systemContent,
        temperature: cfg.ai?.anthropic?.temperature || 0.2,
        onChunk
      });
      break;
    }
    case 'openai': {
      effectiveModel = model || cfg.ai?.openai?.defaultModel || 'gpt-4o';
      responseText = await chatOpenAI({
        apiKey: cfg.ai?.openai?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.openai?.temperature || 0.2,
        onChunk
      });
      break;
    }
    case 'gemini': {
      effectiveModel = model || cfg.ai?.gemini?.defaultModel || 'gemini-2.0-flash';
      responseText = await chatGemini({
        apiKey: cfg.ai?.gemini?.apiKey,
        model: effectiveModel,
        messages: conversationMessages,
        temperature: cfg.ai?.gemini?.temperature || 0.2,
        onChunk
      });
      break;
    }
    default:
      throw new Error(`Unsupported AI provider: '${effectiveProvider}'. Supported: ollama, anthropic, openai, gemini`);
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
