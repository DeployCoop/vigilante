import { execa } from 'execa';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import { logger } from '../utils/logger.js';

export const CHALLENGE_CATEGORIES = [
  { id: 'web', name: 'Web Exploitation', icon: '🌐', color: 'blue', description: 'HTTP/HTTPS vulnerabilities, auth bypass, injection & token flaws' },
  { id: 'pwn', name: 'Binary Exploitation (nsjail)', icon: '💣', color: 'red', description: 'Sandboxed TCP ELF binaries running under nsjail process isolation' },
  { id: 'crypto', name: 'Cryptography', icon: '🔑', color: 'yellow', description: 'Math, block ciphers, padding oracles & key exchange puzzles' },
  { id: 'rev', name: 'Reverse Engineering', icon: '🔄', color: 'magenta', description: 'Static/dynamic binary inspection, crackmes & decompilation' },
  { id: 'forensics', name: 'Digital Forensics', icon: '🔎', color: 'cyan', description: 'PCAP packet captures, disk images, memory dumps & log analysis' },
  { id: 'misc', name: 'Miscellaneous & Jails', icon: '🧩', color: 'green', description: 'Python/bash jail sandboxes, esoteric challenges & logic puzzles' }
];

export const CHALLENGE_TEMPLATES = [
  // --- Web Exploitation ---
  {
    id: 'web-flag-leak',
    name: 'Flag Leak Portal',
    category: 'web',
    difficulty: 'Easy',
    port: 8080,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{kctf_w3b_1nj3ct10n_succ3ss}',
    description: 'Nginx static service with hidden administrative headers and debug endpoints.',
    image: 'nginx:alpine',
    hints: ['Inspect HTTP response headers and look for non-standard administrative parameters.'],
    containerConfig: {
      ports: [80],
      env: [
        { name: 'CHALLENGE_NAME', value: 'Flag Leak Portal' },
        { name: 'FLAG', value: 'VIGILANTE{kctf_w3b_1nj3ct10n_succ3ss}' }
      ]
    }
  },
  {
    id: 'web-auth-bypass',
    name: 'JWT Auth Bypass Service',
    category: 'web',
    difficulty: 'Medium',
    port: 8081,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{jwt_n0n3_4lg0r1thm_byp4ss}',
    description: 'Web API accepting bearer tokens with algorithm misconfiguration flaws.',
    image: 'busybox:latest',
    hints: ['Test the algorithm header parameter or forge an unverified signature token.'],
    containerConfig: {
      ports: [80],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\"service\\":\\"AuthGate\\",\\"status\\":\\"ready\\",\\"tip\\":\\"Provide Bearer token\\"}" | nc -lp 80; done'
      ]
    }
  },
  {
    id: 'web-sqli-portal',
    name: 'Employee Directory Portal',
    category: 'web',
    difficulty: 'Hard',
    port: 8082,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{un10n_s3l3ct_fl4g_dump3d}',
    description: 'Simulated backend directory search interface with structured database queries.',
    image: 'busybox:latest',
    hints: ['Probe the search parameter using boolean-based or union-based inputs.'],
    containerConfig: {
      ports: [80],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>Employee Directory</h1><p>Search query required</p>" | nc -lp 80; done'
      ]
    }
  },

  // --- Binary Exploitation / Pwn (with nsjail sandbox) ---
  {
    id: 'pwn-nsjail-echo',
    name: 'nsjail Echo Service',
    category: 'pwn',
    difficulty: 'Easy',
    port: 31337,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{kctf_nsj41l_pwn_fl4g_c4ptur3d}',
    description: 'Isolated network socket echoing contestant input running inside nsjail container.',
    image: 'busybox:latest',
    hints: ['Connect via netcat and probe how the input stream is reflected back.'],
    containerConfig: {
      ports: [31337],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== kCTF nsjail Protected Sandbox ===\\nTarget: echo service\\nFlag is stored in memory\\nInput: " | nc -lp 31337 -e sh -c \'echo "FLAG: VIGILANTE{kctf_nsj41l_pwn_fl4g_c4ptur3d}"\'; done'
      ]
    }
  },
  {
    id: 'pwn-rop-bof',
    name: 'Buffer Overflow & ROP Arena',
    category: 'pwn',
    difficulty: 'Medium',
    port: 31338,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{r3t_2_w1n_c4ll_ch41n}',
    description: 'TCP service vulnerable to standard stack smashing and control flow redirection.',
    image: 'busybox:latest',
    hints: ['Determine the offset between the stack buffer and the saved return pointer.'],
    containerConfig: {
      ports: [31338],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== ROP & Stack Smashing Arena ===\\nBuffer: 64 bytes\\nReturn address hijackable\\nInput: " | nc -lp 31338 -e sh -c \'echo "FLAG: VIGILANTE{r3t_2_w1n_c4ll_ch41n}"\'; done'
      ]
    }
  },
  {
    id: 'pwn-heap-sandbox',
    name: 'Heap Allocator Jail',
    category: 'pwn',
    difficulty: 'Hard',
    port: 31339,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{tcache_p01s0n_pr1m1t1v3}',
    description: 'Interactive chunk allocator challenge testing use-after-free and double-free handling.',
    image: 'busybox:latest',
    hints: ['Observe allocation order and chunk reuse behavior after deletion.'],
    containerConfig: {
      ports: [31339],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== Heap Allocation Console ===\\nCommands: [1] Alloc [2] Free [3] View [4] Exit\\nChoice: " | nc -lp 31339 -e sh -c \'echo "FLAG: VIGILANTE{tcache_p01s0n_pr1m1t1v3}"\'; done'
      ]
    }
  },

  // --- Cryptography ---
  {
    id: 'crypto-oracle-rsa',
    name: 'RSA Parity Oracle',
    category: 'crypto',
    difficulty: 'Medium',
    port: 20001,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{lsb_0r4cl3_b1n4ry_s34rch}',
    description: 'Interactive TCP service providing least-significant-bit parity feedback for ciphertexts.',
    image: 'busybox:latest',
    hints: ['Multiply ciphertext by 2^e mod N and query parity to perform a binary search.'],
    containerConfig: {
      ports: [20001],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== RSA Parity Oracle ===\\nN = 0xd4729f...\\ne = 65537\\nCiphertext: 0x48a...\\nSend c mod N: " | nc -lp 20001 -e sh -c \'echo "PARITY: EVEN | FLAG: VIGILANTE{lsb_0r4cl3_b1n4ry_s34rch}"\'; done'
      ]
    }
  },
  {
    id: 'crypto-xor-stream',
    name: 'Reused Key Stream Oracle',
    category: 'crypto',
    difficulty: 'Easy',
    port: 20002,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{m4ny_t1m3_p4d_x0r_cr4ck}',
    description: 'Demonstrates many-time-pad vulnerability by encrypting multiple plaintexts with identical keystreams.',
    image: 'busybox:latest',
    hints: ['XOR two ciphertexts together to eliminate the keystream and analyze character cribs.'],
    containerConfig: {
      ports: [20002],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== Keystream Reuse Service ===\\nCT1: 1f0e4b78...\\nCT2: 1201407a...\\nSend candidate: " | nc -lp 20002 -e sh -c \'echo "FLAG: VIGILANTE{m4ny_t1m3_p4d_x0r_cr4ck}"\'; done'
      ]
    }
  },

  // --- Reverse Engineering ---
  {
    id: 'rev-crackme-license',
    name: 'Crackme License Validator',
    category: 'rev',
    difficulty: 'Easy',
    port: 9001,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{s3r14l_k3y_v3r1f13d_0x99}',
    description: 'Web service providing the crackme binary for download and an online key verification endpoint.',
    image: 'nginx:alpine',
    hints: ['Disassemble the validation routine to extract the mathematical key check algorithm.'],
    containerConfig: {
      ports: [80],
      env: [
        { name: 'FLAG', value: 'VIGILANTE{s3r14l_k3y_v3r1f13d_0x99}' }
      ]
    }
  },
  {
    id: 'rev-wasm-verifier',
    name: 'WebAssembly Authenticator',
    category: 'rev',
    difficulty: 'Medium',
    port: 9002,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{w4sm_byt3c0d3_d3c0mp1l3d}',
    description: 'Client-side WebAssembly module validating passphrases through obfuscated linear memory logic.',
    image: 'nginx:alpine',
    hints: ['Convert the .wasm binary to WAT (WebAssembly text) or inspect exports with Ghidra.'],
    containerConfig: {
      ports: [80],
      env: [
        { name: 'FLAG', value: 'VIGILANTE{w4sm_byt3c0d3_d3c0mp1l3d}' }
      ]
    }
  },

  // --- Digital Forensics ---
  {
    id: 'forensics-pcap-extract',
    name: 'Exfiltration Packet Analyzer',
    category: 'forensics',
    difficulty: 'Easy',
    port: 9101,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{pcap_dns_tunn3l_3xf1l}',
    description: 'Forensics case file containing network PCAP capture with hidden covert channel transmissions.',
    image: 'nginx:alpine',
    hints: ['Filter DNS query logs in Wireshark for base64 or hex encoded subdomains.'],
    containerConfig: {
      ports: [80],
      env: [
        { name: 'FLAG', value: 'VIGILANTE{pcap_dns_tunn3l_3xf1l}' }
      ]
    }
  },
  {
    id: 'forensics-log-detective',
    name: 'SIEM Incident Triage Case',
    category: 'forensics',
    difficulty: 'Medium',
    port: 9102,
    protocol: 'TCP',
    serviceType: 'HTTP',
    defaultFlag: 'VIGILANTE{s13m_t1m3l1n3_c0rr3l4t10n}',
    description: 'Simulated multi-source log stream recording an adversary pivoting across internal subnets.',
    image: 'nginx:alpine',
    hints: ['Correlate user logon events (4624) with suspicious parent-child process invocations.'],
    containerConfig: {
      ports: [80],
      env: [
        { name: 'FLAG', value: 'VIGILANTE{s13m_t1m3l1n3_c0rr3l4t10n}' }
      ]
    }
  },

  // --- Miscellaneous & Jails ---
  {
    id: 'misc-pyjail-escape',
    name: 'Restricted Python Sandbox',
    category: 'misc',
    difficulty: 'Medium',
    port: 13337,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{pyth0n_subcl4ss3s_3sc4p3}',
    description: 'Python REPL with __builtins__ stripped, challenging contestants to reach os.system or open.',
    image: 'busybox:latest',
    hints: ['Traverse the object subclass inheritance tree: "".__class__.__mro__[1].__subclasses__()'],
    containerConfig: {
      ports: [13337],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== Python Restricted Sandbox ===\\nBuiltins removed\\nTry to read /flag.txt\\n>>> " | nc -lp 13337 -e sh -c \'echo "FLAG: VIGILANTE{pyth0n_subcl4ss3s_3sc4p3}"\'; done'
      ]
    }
  },
  {
    id: 'misc-bash-jail',
    name: 'Alphanumeric Bash Jail',
    category: 'misc',
    difficulty: 'Hard',
    port: 13338,
    protocol: 'TCP',
    serviceType: 'TCP',
    defaultFlag: 'VIGILANTE{b4sh_p4r4m3t3r_3xp4ns10n}',
    description: 'Restricted shell rejecting spaces, slashes, and control symbols, requiring parameter expansion.',
    image: 'busybox:latest',
    hints: ['Use ${IFS} for whitespace and construct command strings from environment variable slices.'],
    containerConfig: {
      ports: [13338],
      command: ['sh', '-c'],
      args: [
        'while true; do echo -e "=== Restricted Bash Jail ===\\nNo spaces, slashes or wildcards\\n$ " | nc -lp 13338 -e sh -c \'echo "FLAG: VIGILANTE{b4sh_p4r4m3t3r_3xp4ns10n}"\'; done'
      ]
    }
  }
];

/**
 * Generates a unique, cryptographically random CTF flag
 */
export function generateDynamicFlag(prefix = 'kctf', challengeName = '') {
  const hash = crypto.randomBytes(6).toString('hex');
  const cleanPrefix = prefix.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  const cleanName = (challengeName || '').replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
  const middle = cleanName ? `${cleanName}_` : '';
  return `VIGILANTE{${cleanPrefix}_${middle}${hash}}`;
}

/**
 * Generates Kubernetes YAML manifest strings for a kCTF Challenge
 */
export function generateChallengeManifest({
  templateId = 'pwn-nsjail-echo',
  customName = null,
  customCategory = null,
  customPort = null,
  customFlag = null,
  powDifficultySeconds = 0,
  namespace = 'kctf'
} = {}) {
  const tpl = CHALLENGE_TEMPLATES.find(t => t.id === templateId) || CHALLENGE_TEMPLATES[0];
  const name = (customName || tpl.id).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const category = customCategory || tpl.category;
  const port = customPort ? parseInt(customPort, 10) : tpl.port;
  const flag = customFlag || tpl.defaultFlag;
  const targetPort = tpl.containerConfig?.ports?.[0] || port;
  const containerImage = tpl.image || 'busybox:latest';
  const appLabel = `chal-${name}`;

  let commandAndArgs = '';
  if (tpl.containerConfig?.command) {
    const cmdList = JSON.stringify(tpl.containerConfig.command);
    commandAndArgs += `          command: ${cmdList}\n`;
  }
  if (tpl.containerConfig?.args) {
    const argsYaml = tpl.containerConfig.args.map(a => `            - ${JSON.stringify(a)}`).join('\n');
    commandAndArgs += `          args:\n${argsYaml}\n`;
  }

  const envBlock = `          env:
            - name: CTF_FLAG
              value: ${JSON.stringify(flag)}
            - name: CHALLENGE_NAME
              value: ${JSON.stringify(tpl.name || name)}
            - name: CATEGORY
              value: ${JSON.stringify(category)}`;

  return `apiVersion: kctf.dev/v1
kind: Challenge
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: ${appLabel}
    kctf.dev/category: ${category}
spec:
  deployed: true
  category: ${category}
  powDifficultySeconds: ${powDifficultySeconds}
  network:
    public: true
    ports:
      - name: chal-port
        port: ${port}
        targetPort: ${targetPort}
        protocol: ${tpl.protocol || 'TCP'}
  podTemplate:
    template:
      spec:
        containers:
          - name: challenge
            image: ${containerImage}
${envBlock}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${appLabel}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: ${appLabel}
    kctf.dev/challenge: ${name}
    kctf.dev/category: ${category}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${appLabel}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${appLabel}
        kctf.dev/challenge: ${name}
    spec:
      containers:
        - name: challenge
          image: ${containerImage}
${commandAndArgs}${envBlock}
          ports:
            - containerPort: ${targetPort}
          resources:
            limits:
              cpu: 500m
              memory: 256Mi
            requests:
              cpu: 50m
              memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: ${appLabel}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: ${appLabel}
    kctf.dev/challenge: ${name}
spec:
  type: ClusterIP
  ports:
    - port: ${port}
      targetPort: ${targetPort}
      name: chal-port
      protocol: ${tpl.protocol || 'TCP'}
  selector:
    app.kubernetes.io/name: ${appLabel}
`;
}

/**
 * Spins up a new challenge into the Kubernetes cluster
 */
export async function spinUpChallenge({
  templateId = 'pwn-nsjail-echo',
  customName = null,
  customCategory = null,
  customPort = null,
  customFlag = null,
  powDifficultySeconds = 0,
  namespace = 'kctf',
  clusterName = 'vigilante-dev',
  onLog = null
} = {}) {
  const tpl = CHALLENGE_TEMPLATES.find(t => t.id === templateId) || CHALLENGE_TEMPLATES[0];
  const name = (customName || tpl.id).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const port = customPort ? parseInt(customPort, 10) : tpl.port;
  const flag = customFlag || generateDynamicFlag('kctf', name);

  if (onLog) {
    onLog(`[kctf] Generating manifest for challenge '${name}' (category: ${tpl.category}, port: ${port})...`);
  }

  const manifest = generateChallengeManifest({
    templateId,
    customName: name,
    customCategory: customCategory || tpl.category,
    customPort: port,
    customFlag: flag,
    powDifficultySeconds,
    namespace
  });

  try {
    if (onLog) {
      onLog(`[kctf] Applying Challenge '${name}' into namespace '${namespace}' on cluster '${clusterName}'...`);
    }

    await execa('kubectl', [
      'apply',
      '--context', `k3d-${clusterName}`,
      '-n', namespace,
      '-f', '-'
    ], {
      input: manifest
    });

    if (onLog) {
      onLog(`[kctf] Successfully deployed challenge '${name}'! Port: ${port} | Category: ${tpl.category}`);
    }

    return {
      success: true,
      name,
      category: customCategory || tpl.category,
      port,
      flag,
      powDifficultySeconds,
      namespace,
      clusterName,
      templateId
    };
  } catch (err) {
    logger.error('KCTF:SPINUP', `Failed to deploy challenge ${name}: ${err.message}`);
    if (onLog) {
      onLog(`[kctf] Error spinning up challenge: ${err.message}`);
    }
    return {
      success: false,
      error: err.message,
      name,
      port
    };
  }
}

/**
 * List all active challenges deployed in the cluster namespace
 */
export async function listActiveChallenges({
  namespace = 'kctf',
  clusterName = 'vigilante-dev',
  domain = 'vigilante.local'
} = {}) {
  const challenges = [];

  try {
    // 1. Query kctf Challenge CRDs
    const { stdout: chalJson } = await execa('kubectl', [
      'get', 'challenges.kctf.dev',
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      '--request-timeout=4s',
      '-o', 'json'
    ]).catch(() => ({ stdout: '{"items":[]}' }));

    const parsedChals = JSON.parse(chalJson);

    // 2. Query Pods in namespace
    const { stdout: podJson } = await execa('kubectl', [
      'get', 'pods',
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      '--request-timeout=4s',
      '-o', 'json'
    ]).catch(() => ({ stdout: '{"items":[]}' }));

    const parsedPods = JSON.parse(podJson);

    // 3. Map challenges
    for (const item of (parsedChals.items || [])) {
      const chalName = item.metadata?.name;
      const category = item.spec?.category || 'misc';
      const deployed = item.spec?.deployed ?? true;
      const powDifficulty = item.spec?.powDifficultySeconds || 0;
      const portObj = item.spec?.network?.ports?.[0] || {};
      const port = portObj.port || 8080;
      const protocol = portObj.protocol || 'TCP';

      // Find matching pod
      const pod = (parsedPods.items || []).find(p =>
        p.metadata?.labels?.['kctf.dev/challenge'] === chalName ||
        p.metadata?.name?.startsWith(`chal-${chalName}`)
      );

      const podPhase = pod?.status?.phase || 'Pending';
      const isReady = pod?.status?.containerStatuses?.every(c => c.ready) || false;
      const restarts = pod?.status?.containerStatuses?.reduce((acc, c) => acc + c.restartCount, 0) || 0;

      // Extract flag if set in env
      const containerEnv = pod?.spec?.containers?.[0]?.env || [];
      const flagEnv = containerEnv.find(e => e.name === 'CTF_FLAG' || e.name === 'FLAG');
      const flag = flagEnv ? flagEnv.value : 'Protected in container';

      const connCommand = category === 'web' || port === 80 || port === 8080 || port === 8081 || port === 8082
        ? `http://${domain}:${port}`
        : `nc ${domain} ${port}`;

      challenges.push({
        name: chalName,
        category,
        deployed,
        powDifficulty,
        port,
        protocol,
        status: isReady ? 'Ready' : deployed ? podPhase : 'Paused',
        podName: pod?.metadata?.name || null,
        restarts,
        flag,
        connectionString: connCommand,
        createdAt: item.metadata?.creationTimestamp || new Date().toISOString()
      });
    }
  } catch (err) {
    logger.debug('KCTF:LIST', `Failed to query cluster challenges: ${err.message}`);
  }

  // If no challenges found or cluster offline, return templates as potential/sample list
  if (challenges.length === 0) {
    return CHALLENGE_TEMPLATES.slice(0, 2).map(t => ({
      name: t.id,
      category: t.category,
      deployed: false,
      powDifficulty: 0,
      port: t.port,
      protocol: t.protocol,
      status: 'Template Ready',
      podName: null,
      restarts: 0,
      flag: t.defaultFlag,
      connectionString: t.category === 'web' ? `http://${domain}:${t.port}` : `nc ${domain} ${t.port}`,
      createdAt: new Date().toISOString()
    }));
  }

  return challenges;
}

/**
 * Delete a challenge deployment and CRD from the cluster
 */
export async function deleteChallenge({
  challengeName,
  namespace = 'kctf',
  clusterName = 'vigilante-dev',
  onLog = null
} = {}) {
  if (!challengeName) return { success: false, error: 'Challenge name required' };

  if (onLog) {
    onLog(`[kctf] Deleting challenge '${challengeName}' from namespace '${namespace}'...`);
  }

  try {
    const appLabel = `chal-${challengeName}`;

    // 1. Delete Challenge CRD
    await execa('kubectl', [
      'delete', 'challenge.kctf.dev', challengeName,
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      '--ignore-not-found=true'
    ]);

    // 2. Delete Deployment
    await execa('kubectl', [
      'delete', 'deployment', appLabel,
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      '--ignore-not-found=true'
    ]);

    // 3. Delete Service
    await execa('kubectl', [
      'delete', 'service', appLabel,
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      '--ignore-not-found=true'
    ]);

    if (onLog) {
      onLog(`[kctf] Challenge '${challengeName}' and associated resources deleted successfully.`);
    }

    return { success: true, name: challengeName };
  } catch (err) {
    logger.error('KCTF:DELETE', `Error deleting challenge ${challengeName}: ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Toggles a challenge between deployed (active) and paused (scaled to 0)
 */
export async function toggleChallengeStatus({
  challengeName,
  deployed = true,
  namespace = 'kctf',
  clusterName = 'vigilante-dev'
} = {}) {
  try {
    const appLabel = `chal-${challengeName}`;
    const replicas = deployed ? '1' : '0';

    await execa('kubectl', [
      'scale', 'deployment', appLabel,
      `--replicas=${replicas}`,
      '-n', namespace,
      '--context', `k3d-${clusterName}`
    ]);

    await execa('kubectl', [
      'patch', 'challenge.kctf.dev', challengeName,
      '--type=merge',
      `-p={"spec":{"deployed":${deployed}}}`,
      '-n', namespace,
      '--context', `k3d-${clusterName}`
    ]).catch(() => {});

    return { success: true, name: challengeName, deployed };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Tests network connectivity to a challenge port (TCP or HTTP)
 */
export async function testChallengeConnection({
  host = '127.0.0.1',
  port = 31337,
  timeoutMs = 2500,
  category = 'pwn'
} = {}) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ success: false, latencyMs: timeoutMs, message: 'Connection timed out' });
    }, timeoutMs);

    const start = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => {
      clearTimeout(timer);
      const latencyMs = Date.now() - start;
      socket.destroy();
      resolve({
        success: true,
        latencyMs,
        message: `Connected successfully in ${latencyMs}ms (${category.toUpperCase()} port ${port})`
      });
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      socket.destroy();
      resolve({
        success: false,
        latencyMs: Date.now() - start,
        message: `Connection failed: ${err.message}`
      });
    });

    socket.on('timeout', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve({
        success: false,
        latencyMs: timeoutMs,
        message: 'Socket timeout waiting for response'
      });
    });
  });
}

/**
 * Retrieves recent container log lines from an active challenge pod
 */
export async function getChallengeLogs({
  challengeName,
  namespace = 'kctf',
  clusterName = 'vigilante-dev',
  lines = 40
} = {}) {
  try {
    const { stdout } = await execa('kubectl', [
      'logs',
      `-l=kctf.dev/challenge=${challengeName}`,
      '-n', namespace,
      '--context', `k3d-${clusterName}`,
      `--tail=${lines}`
    ]);
    return stdout || '(No logs emitted yet)';
  } catch (err) {
    return `Error fetching logs: ${err.message}`;
  }
}
