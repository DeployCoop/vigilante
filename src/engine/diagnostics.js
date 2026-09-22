import { execa } from 'execa';
import { saveTriageBundle } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Check if a command binary is available in PATH
 * @param {string} binary
 * @returns {Promise<boolean>}
 */
export async function isBinaryAvailable(binary) {
  try {
    await execa('which', [binary]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Execute ICMP Ping against a host
 * @param {string} host
 * @param {number} [count=4]
 * @returns {Promise<{ success: boolean, output: string, error?: string }>}
 */
export async function runPing(host, count = 4) {
  const target = (host || '127.0.0.1').trim();
  logger.info('DIAG:PING', `Executing ping -c ${count} ${target}`);

  try {
    const { stdout, stderr } = await execa('ping', ['-c', String(count), '-W', '2', target]);
    return {
      success: true,
      command: `ping -c ${count} ${target}`,
      output: stdout || stderr
    };
  } catch (err) {
    logger.warn('DIAG:PING:ERROR', err.message);
    return {
      success: false,
      command: `ping -c ${count} ${target}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Execute HTTP Benchmark using ApacheBench (ab) or curl fallback
 * @param {string} host
 * @param {Object} [options]
 * @param {number} [options.port]
 * @param {boolean} [options.isHttps=false]
 * @param {number} [options.requests=50]
 * @param {number} [options.concurrency=5]
 * @returns {Promise<{ success: boolean, output: string, tool: string }>}
 */
export async function runBenchmark(host, {
  port = null,
  isHttps = false,
  requests = 50,
  concurrency = 5
} = {}) {
  const target = (host || '127.0.0.1').trim();
  const protocol = isHttps || port === 443 ? 'https' : 'http';
  const targetPort = port ? `:${port}` : (isHttps ? ':443' : ':80');
  const targetUrl = `${protocol}://${target}${targetPort}/`;

  const hasAb = await isBinaryAvailable('ab');

  if (hasAb) {
    logger.info('DIAG:AB', `Executing ab -n ${requests} -c ${concurrency} ${targetUrl}`);
    try {
      const { stdout } = await execa('ab', ['-n', String(requests), '-c', String(concurrency), '-k', targetUrl]);
      return {
        success: true,
        tool: 'ab (ApacheBench)',
        command: `ab -n ${requests} -c ${concurrency} -k ${targetUrl}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'ab (ApacheBench)',
        command: `ab -n ${requests} -c ${concurrency} -k ${targetUrl}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  // Fallback to multiple parallel curl requests
  logger.info('DIAG:BENCH_CURL', `Executing curl benchmark loop against ${targetUrl}`);
  try {
    const startTime = Date.now();
    const curlPromises = [];
    for (let i = 0; i < 10; i++) {
      curlPromises.push(execa('curl', [
        '-s',
        '-o', '/dev/null',
        '-w', 'HTTP %{http_code} | Connect: %{time_connect}s | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n',
        '--connect-timeout', '2',
        targetUrl
      ]));
    }
    const results = await Promise.allSettled(curlPromises);
    const totalTimeMs = Date.now() - startTime;
    const lines = [
      `=== HTTP Benchmark Fallback (curl) for ${targetUrl} ===`,
      `Executed 10 concurrent HTTP probes in ${(totalTimeMs / 1000).toFixed(3)}s`,
      '',
      ...results.map((r, i) => r.status === 'fulfilled' ? `[Req #${i + 1}] ${r.value.stdout.trim()}` : `[Req #${i + 1}] Failed: ${r.reason.message}`),
      '',
      `Tip: Install 'apache2-utils' (or 'httpd-tools') for full ApacheBench (ab) metrics.`
    ];

    return {
      success: true,
      tool: 'curl benchmark fallback',
      command: `curl concurrent benchmark against ${targetUrl}`,
      output: lines.join('\n')
    };
  } catch (err) {
    return {
      success: false,
      tool: 'curl',
      command: `curl ${targetUrl}`,
      output: err.message,
      error: err.message
    };
  }
}

/**
 * Execute MTR (My Traceroute) or traceroute against host
 * @param {string} host
 * @returns {Promise<{ success: boolean, output: string, tool: string }>}
 */
export async function runMtr(host) {
  const target = (host || '127.0.0.1').trim();
  const hasMtr = await isBinaryAvailable('mtr');

  if (hasMtr) {
    logger.info('DIAG:MTR', `Executing mtr --report -c 4 ${target}`);
    try {
      const { stdout } = await execa('mtr', ['--report', '-c', '4', target]);
      return {
        success: true,
        tool: 'mtr',
        command: `mtr --report -c 4 ${target}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'mtr',
        command: `mtr --report -c 4 ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  // Fallback to traceroute or tracepath
  const hasTracepath = await isBinaryAvailable('tracepath');
  if (hasTracepath) {
    logger.info('DIAG:TRACEPATH', `Executing tracepath ${target}`);
    try {
      const { stdout } = await execa('tracepath', ['-m', '15', target]);
      return {
        success: true,
        tool: 'tracepath (mtr fallback)',
        command: `tracepath ${target}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'tracepath',
        command: `tracepath ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  return {
    success: false,
    tool: 'mtr',
    command: `mtr ${target}`,
    output: `Neither 'mtr' nor 'tracepath' found in system PATH. Install via 'sudo apt install mtr' or 'brew install mtr'.`,
    error: 'mtr not installed'
  };
}

/**
 * Execute HTTP Header & TLS Inspector (curl -I)
 * @param {string} host
 * @param {Object} [options]
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function runCurlHeaders(host, { port = null, isHttps = false } = {}) {
  const target = (host || '127.0.0.1').trim();
  const protocol = isHttps || port === 443 ? 'https' : 'http';
  const targetPort = port ? `:${port}` : (isHttps ? ':443' : ':80');
  const targetUrl = `${protocol}://${target}${targetPort}/`;

  logger.info('DIAG:CURL_HEADERS', `Executing curl -I -sS -k ${targetUrl}`);
  try {
    const { stdout, stderr } = await execa('curl', [
      '-I',
      '-sS',
      '-k',
      '--connect-timeout', '3',
      targetUrl
    ]);
    return {
      success: true,
      command: `curl -I -k ${targetUrl}`,
      output: stdout || stderr
    };
  } catch (err) {
    return {
      success: false,
      command: `curl -I -k ${targetUrl}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Execute DNS resolution & reverse lookup (dig / nslookup)
 * @param {string} host
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function runDnsLookup(host) {
  const target = (host || '127.0.0.1').trim();
  const hasDig = await isBinaryAvailable('dig');

  if (hasDig) {
    logger.info('DIAG:DIG', `Executing dig ${target}`);
    try {
      const isIp = /^[\d.]+$/.test(target);
      const digArgs = isIp ? ['-x', target, '+noall', '+answer', '+stats'] : [target, 'ANY', '+noall', '+answer', '+stats'];
      const { stdout } = await execa('dig', digArgs);
      return {
        success: true,
        tool: 'dig',
        command: `dig ${digArgs.join(' ')}`,
        output: stdout || 'No DNS records returned for target.'
      };
    } catch (err) {
      return {
        success: false,
        tool: 'dig',
        command: `dig ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  return {
    success: false,
    tool: 'dig',
    command: `dig ${target}`,
    output: `dig utility not found. Install via 'sudo apt install dnsutils' or 'brew install bind'.`,
    error: 'dig not installed'
  };
}

/**
 * Extract full TLS certificate chain and crypto metadata using OpenSSL s_client
 * @param {string} host
 * @param {number} [port=443]
 * @returns {Promise<{ success: boolean, output: string, command: string }>}
 */
export async function runTlsCertDump(host, port = 443) {
  const target = (host || '127.0.0.1').trim();
  const targetPort = String(port || 443);
  logger.info('DIAG:TLS_CERTS', `Executing openssl s_client -showcerts -connect ${target}:${targetPort}`);

  try {
    const { stdout, stderr } = await execa('openssl', [
      's_client',
      '-showcerts',
      '-connect', `${target}:${targetPort}`,
      '-servername', target
    ], {
      input: 'Q\n',
      timeout: 5000
    });

    return {
      success: true,
      tool: 'OpenSSL TLS Certificate Chain',
      command: `openssl s_client -showcerts -connect ${target}:${targetPort} -servername ${target}`,
      output: stdout || stderr
    };
  } catch (err) {
    return {
      success: false,
      tool: 'OpenSSL TLS Certificate Chain',
      command: `openssl s_client -showcerts -connect ${target}:${targetPort}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Query kernel ARP cache and neighbor table for the host
 * @param {string} host
 * @returns {Promise<{ success: boolean, output: string, command: string, entries: Array<string> }>}
 */
export async function runArpNeighLookup(host) {
  const target = (host || '').trim();
  logger.info('DIAG:ARP_NEIGH', `Checking kernel neighbor table for ${target}`);

  try {
    const hasIp = await isBinaryAvailable('ip');
    let stdout = '';
    let command = '';

    if (hasIp) {
      command = 'ip neigh show';
      const res = await execa('ip', ['neigh', 'show']);
      stdout = res.stdout;
    } else {
      command = 'arp -a';
      const res = await execa('arp', ['-a']);
      stdout = res.stdout;
    }

    const lines = stdout.split('\n').filter(l => l.trim().length > 0);
    const hostMatches = target ? lines.filter(l => l.includes(target)) : lines;

    return {
      success: true,
      tool: 'Kernel ARP & Neighbor Table',
      command,
      output: hostMatches.length > 0
        ? `=== ARP / Neighbor Records for ${target} ===\n` + hostMatches.join('\n')
        : `No direct neighbor/ARP entry cached for ${target}.\n\nFull ARP Table:\n` + stdout,
      entries: hostMatches
    };
  } catch (err) {
    return {
      success: false,
      tool: 'ARP & Neighbor Table',
      command: 'ip neigh show',
      output: err.message,
      error: err.message,
      entries: []
    };
  }
}

/**
 * Run a full forensic Incident Response Triage Bundle for a host and persist to evidence vault
 * @param {string} host
 * @param {Object} [options]
 * @param {string} [options.networkCidr='local_net']
 * @param {number} [options.port]
 * @param {boolean} [options.isHttps=false]
 * @returns {Promise<{ success: boolean, bundle: Object, saved: Object, durationMs: number }>}
 */
export async function runFullTriageCapture(host, {
  networkCidr = 'local_network',
  port = null,
  isHttps = false
} = {}) {
  const target = (host || '127.0.0.1').trim();
  const startTime = Date.now();
  logger.info('DIAG:TRIAGE_ALL', `Running complete IR triage bundle on ${target} (${networkCidr})`);

  // Run all forensic probes concurrently
  const [pingRes, mtrRes, dnsRes, tlsRes, httpRes, arpRes, benchRes] = await Promise.allSettled([
    runPing(target, 4),
    runMtr(target),
    runDnsLookup(target),
    runTlsCertDump(target, port || 443),
    runCurlHeaders(target, { port, isHttps }),
    runArpNeighLookup(target),
    runBenchmark(target, { port, isHttps, requests: 20, concurrency: 4 })
  ]);

  const bundle = {
    metadata: {
      target,
      networkCidr,
      durationMs: Date.now() - startTime,
      collectedAt: new Date().toISOString()
    },
    ping: pingRes.status === 'fulfilled' ? pingRes.value : { error: pingRes.reason?.message },
    mtr: mtrRes.status === 'fulfilled' ? mtrRes.value : { error: mtrRes.reason?.message },
    dns: dnsRes.status === 'fulfilled' ? dnsRes.value : { error: dnsRes.reason?.message },
    tls: tlsRes.status === 'fulfilled' ? tlsRes.value : { error: tlsRes.reason?.message },
    http: httpRes.status === 'fulfilled' ? httpRes.value : { error: httpRes.reason?.message },
    arp: arpRes.status === 'fulfilled' ? arpRes.value : { error: arpRes.reason?.message },
    benchmark: benchRes.status === 'fulfilled' ? benchRes.value : { error: benchRes.reason?.message }
  };

  const saved = await saveTriageBundle(networkCidr, target, bundle);

  return {
    success: true,
    bundle,
    saved,
    durationMs: Date.now() - startTime
  };
}
