import os from 'node:os';
import { execa } from 'execa';
import detectPort from 'detect-port';

export async function runDoctorChecks() {
  const checks = [];

  // Memory Check
  const totalMemGB = os.totalmem() / (1024 ** 3);
  const isMemSufficient = totalMemGB >= 16;
  checks.push({
    name: 'System Memory (>= 16GB)',
    status: isMemSufficient ? 'PASS' : 'FAIL',
    message: `Detected ${totalMemGB.toFixed(2)}GB`
  });

  // Docker Check
  try {
    await execa('docker', ['info']);
    checks.push({ name: 'Docker daemon', status: 'PASS', message: 'Running and accessible' });
  } catch (err) {
    checks.push({ name: 'Docker daemon', status: 'FAIL', message: 'Not running or accessible' });
  }

  // k3d Check
  try {
    const { stdout } = await execa('k3d', ['version']);
    const version = stdout.split('\n')[0];
    checks.push({ name: 'k3d installed', status: 'PASS', message: version });
  } catch (err) {
    checks.push({ name: 'k3d installed', status: 'FAIL', message: 'Not found in PATH' });
  }

  // kubectl Check
  try {
    const { stdout } = await execa('kubectl', ['version', '--client', '-o', 'json']);
    const v = JSON.parse(stdout).clientVersion.gitVersion;
    checks.push({ name: 'kubectl installed', status: 'PASS', message: v });
  } catch (err) {
    checks.push({ name: 'kubectl installed', status: 'FAIL', message: 'Not found in PATH' });
  }

  // helm Check
  try {
    const { stdout } = await execa('helm', ['version', '--short']);
    checks.push({ name: 'helm installed', status: 'PASS', message: stdout.trim() });
  } catch (err) {
    checks.push({ name: 'helm installed', status: 'FAIL', message: 'Not found in PATH' });
  }

  // Port Checks
  for (const port of [80, 443, 6443]) {
    try {
      const freePort = await detectPort(port);
      if (freePort === port) {
        checks.push({ name: `Port ${port} available`, status: 'PASS', message: 'Free' });
      } else {
        checks.push({ name: `Port ${port} available`, status: 'FAIL', message: `In use, next free port: ${freePort}` });
      }
    } catch (err) {
      checks.push({ name: `Port ${port} available`, status: 'FAIL', message: err.message });
    }
  }

  return checks;
}
