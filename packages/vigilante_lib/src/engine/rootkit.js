/**
 * VIGILANTE Ring-0 Kernel & Syscall Rootkit Hunter Engine
 * Detects kernel hook tampering, syscall table hijacking, hidden LKM modules,
 * kernel taint flags, and user-space/kernel-space rootkit artifacts.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { logger } from '../utils/logger.js';

/**
 * Standard Linux Kernel Taint Flags
 */
export const TAINT_FLAGS = [
  { bit: 0, flag: 'PROPRIETARY_MODULE', char: 'P', desc: 'Proprietary module loaded', severity: 'MEDIUM' },
  { bit: 1, flag: 'FORCED_MODULE', char: 'F', desc: 'Module was forcefully loaded (insmod -f)', severity: 'HIGH' },
  { bit: 2, flag: 'UNSAFE_SMP', char: 'S', desc: 'SMP with non-SMP kernel / SMP unsafe', severity: 'LOW' },
  { bit: 3, flag: 'FORCED_UNLOAD', char: 'R', desc: 'Module was forcefully unloaded (rmmod -f)', severity: 'HIGH' },
  { bit: 4, flag: 'MACHINE_CHECK', char: 'M', desc: 'Hardware Machine Check Exception occurred', severity: 'MEDIUM' },
  { bit: 5, flag: 'BAD_PAGE', char: 'B', desc: 'Corrupted memory page referenced', severity: 'HIGH' },
  { bit: 6, flag: 'USER_REQUEST', char: 'U', desc: 'Taint requested by userspace application', severity: 'LOW' },
  { bit: 7, flag: 'KERNEL_DIED', char: 'D', desc: 'Kernel has died or oopsed previously', severity: 'HIGH' },
  { bit: 8, flag: 'OVERRIDDEN_ACPI', char: 'A', desc: 'ACPI table overridden by user', severity: 'LOW' },
  { bit: 9, flag: 'KERNEL_WARN', char: 'W', desc: 'Kernel warning issued', severity: 'LOW' },
  { bit: 10, flag: 'STAGING_DRIVER', char: 'C', desc: 'Staging driver loaded', severity: 'LOW' },
  { bit: 11, flag: 'FIRMWARE_WORKAROUND', char: 'I', desc: 'Firmware bug workaround applied', severity: 'LOW' },
  { bit: 12, flag: 'OUT_OF_TREE_MODULE', char: 'O', desc: 'Out-of-tree external module loaded', severity: 'MEDIUM' },
  { bit: 13, flag: 'UNSIGNED_MODULE', char: 'E', desc: 'Unsigned kernel module loaded', severity: 'HIGH' },
  { bit: 14, flag: 'SOFTLOCKUP', char: 'L', desc: 'Soft lockup occurred', severity: 'MEDIUM' },
  { bit: 15, flag: 'LIVEPATCH', char: 'K', desc: 'Kernel livepatching applied', severity: 'LOW' }
];

/**
 * Known Linux Rootkit Fingerprints & Prefixes
 */
export const ROOTKIT_SIGNATURES = [
  { name: 'Diamorphine', prefix: 'diamorphine', signal: 64, technique: 'T1014', desc: 'Diamorphine LKM rootkit hook' },
  { name: 'Reptile', prefix: 'reptile', signal: 64, technique: 'T1014', desc: 'Reptile LKM stealth rootkit' },
  { name: 'Adore-ng', prefix: 'adore', signal: 0, technique: 'T1014', desc: 'Adore-ng process/file stealth rootkit' },
  { name: 'KBeast', prefix: 'kbeast', signal: 0, technique: 'T1014', desc: 'Kernel Beast LKM rootkit' },
  { name: 'Vlany', prefix: 'vlany', signal: 0, technique: 'T1574.006', desc: 'Vlany LD_PRELOAD userspace rootkit' },
  { name: 'Suterusu', prefix: 'suterusu', signal: 0, technique: 'T1014', desc: 'Suterusu kernel inline hooking framework' }
];

/**
 * Parse /proc/kallsyms content into structured symbols
 * @param {string} content Content of /proc/kallsyms
 * @returns {Array<Object>}
 */
export function parseKallsyms(content = '') {
  if (!content) return [];
  const lines = content.split(/\r?\n/);
  const symbols = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) continue;

    const [addrStr, type, name, moduleWithBrackets] = parts;
    const isHashed = addrStr === '0000000000000000' || /^0+$/.test(addrStr);
    const module = moduleWithBrackets ? moduleWithBrackets.replace(/^\[|\]$/g, '') : null;

    let numAddress = 0n;
    if (!isHashed) {
      try {
        numAddress = BigInt('0x' + addrStr);
      } catch {
        numAddress = 0n;
      }
    }

    symbols.push({
      address: addrStr,
      numAddress,
      type,
      name,
      module,
      isHashed
    });
  }

  return symbols;
}

/**
 * Detect syscall hooking and address redirection
 * @param {Array<Object>} kallsymsSymbols
 * @param {Object} [baselineMap={}] Expected address / symbol mapping
 * @param {Object} [options={}]
 * @returns {Array<Object>} Discovered syscall anomalies
 */
export function detectSyscallHooking(kallsymsSymbols = [], baselineMap = {}, options = {}) {
  const anomalies = [];
  const symbolList = Array.isArray(kallsymsSymbols) ? kallsymsSymbols : parseKallsyms(kallsymsSymbols);

  // Find kernel text boundaries
  const textSym = symbolList.find(s => s.name === '_text');
  const etextSym = symbolList.find(s => s.name === '_etext');
  const textStart = textSym?.numAddress || 0n;
  const textEnd = etextSym?.numAddress || 0n;

  const criticalSyscalls = [
    'sys_call_table',
    'sys_read',
    'sys_write',
    'sys_open',
    'sys_openat',
    'sys_execve',
    'sys_execveat',
    'sys_getdents',
    'sys_getdents64',
    'sys_kill',
    'sys_ptrace',
    'sys_clone',
    'sys_bpf'
  ];

  for (const name of criticalSyscalls) {
    const matching = symbolList.filter(s => s.name === name || s.name === `__x64_${name}`);
    for (const sym of matching) {
      // 1. Check if symbol resides in an external LKM module rather than core kernel
      if (sym.module && sym.name !== 'sys_call_table') {
        anomalies.push({
          syscall: sym.name,
          address: sym.address,
          hookType: 'LKM_MODULE_HIJACK',
          module: sym.module,
          severity: 'CRITICAL',
          mitreTechnique: 'T1014',
          details: `Syscall '${sym.name}' redirected to external loadable module [${sym.module}] instead of core kernel text.`
        });
      }

      // 2. Check if address falls outside _text -> _etext bounds (if bounds available)
      if (textStart > 0n && textEnd > 0n && sym.numAddress > 0n) {
        if (sym.numAddress < textStart || sym.numAddress > textEnd) {
          anomalies.push({
            syscall: sym.name,
            address: sym.address,
            hookType: 'OUT_OF_BOUNDS_TEXT_HOOK',
            module: sym.module,
            severity: 'CRITICAL',
            mitreTechnique: 'T1014',
            details: `Syscall '${sym.name}' address (0x${sym.address}) is outside kernel text boundaries (0x${textStart.toString(16)} - 0x${textEnd.toString(16)}).`
          });
        }
      }

      // 3. Compare against baseline map if provided
      if (baselineMap[sym.name]) {
        const expected = baselineMap[sym.name];
        if (expected.address && expected.address.toLowerCase() !== sym.address.toLowerCase()) {
          anomalies.push({
            syscall: sym.name,
            address: sym.address,
            expectedAddress: expected.address,
            hookType: 'BASELINE_ADDRESS_MISMATCH',
            severity: 'HIGH',
            mitreTechnique: 'T1014',
            details: `Syscall '${sym.name}' address 0x${sym.address} does not match baseline expected address 0x${expected.address}.`
          });
        }
      }
    }
  }

  // 4. Detect ftrace and kprobe hooks in kernel symbols
  const ftraceHooks = symbolList.filter(s => s.name.includes('__ftrace_invalid') || s.name.includes('kprobe_ftrace_handler'));
  if (ftraceHooks.length > 0) {
    anomalies.push({
      syscall: 'ftrace_hooking',
      hookType: 'FTRACE_TRAMPOLINE_ATTACHED',
      severity: 'MEDIUM',
      mitreTechnique: 'T1014',
      details: `Active ftrace or kprobe hooking trampolines detected in symbol table (${ftraceHooks.length} instances).`
    });
  }

  return anomalies;
}

/**
 * Detect hidden loadable kernel modules (LKMs) by comparing /proc/modules and /sys/module
 * @param {string} procModulesContent Content of /proc/modules
 * @param {Array<string>|string} sysModuleList List or paths of /sys/module/*
 * @returns {{ hiddenModules: Array<Object>, totalProcModules: number, totalSysfsModules: number }}
 */
export function detectHiddenModules(procModulesContent = '', sysModuleList = []) {
  const procModuleSet = new Set();
  const lines = (procModulesContent || '').split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [modName] = trimmed.split(/\s+/);
    if (modName) procModuleSet.add(modName.replace(/-/g, '_'));
  }

  const sysModuleSet = new Set();
  const sysItems = Array.isArray(sysModuleList) 
    ? sysModuleList 
    : (typeof sysModuleList === 'string' ? sysModuleList.split(/\s+/) : []);

  for (const item of sysItems) {
    const name = path.basename(item).replace(/-/g, '_');
    if (name) sysModuleSet.add(name);
  }

  const hiddenModules = [];

  // Module in /sys/module but missing from /proc/modules (Diamorphine / Reptile unlinking)
  for (const mod of sysModuleSet) {
    if (!procModuleSet.has(mod)) {
      // Exclude built-in pseudo-modules that only appear in sysfs
      const isKnownBuiltin = ['kernel', 'tcp_cubic', 'ipv6', 'ext4', 'vfat'].includes(mod);
      if (!isKnownBuiltin) {
        hiddenModules.push({
          name: mod,
          reason: 'PRESENT_IN_SYSFS_BUT_HIDDEN_FROM_PROC_MODULES',
          severity: 'CRITICAL',
          mitreTechnique: 'T1014',
          details: `Module '${mod}' has sysfs entry in /sys/module but is missing from /proc/modules (indicative of linked-list unlinking).`
        });
      }
    }
  }

  return {
    hiddenModules,
    totalProcModules: procModuleSet.size,
    totalSysfsModules: sysModuleSet.size
  };
}

/**
 * Analyze Linux kernel taint bitmask
 * @param {number|string} taintVal Bitmask value (e.g. 0, 4096, "4096")
 * @returns {Object} Decoded taint assessment
 */
export function analyzeKernelTaint(taintVal = 0) {
  const val = typeof taintVal === 'string' ? parseInt(taintVal, 10) || 0 : Number(taintVal) || 0;
  const activeFlags = [];

  for (const item of TAINT_FLAGS) {
    if ((val & (1 << item.bit)) !== 0) {
      activeFlags.push({
        bit: item.bit,
        flag: item.flag,
        char: item.char,
        description: item.desc,
        severity: item.severity
      });
    }
  }

  const hasHigh = activeFlags.some(f => f.severity === 'HIGH');
  const hasMedium = activeFlags.some(f => f.severity === 'MEDIUM');
  const riskAssessment = val === 0 
    ? 'PRISTINE_UNTAINTED' 
    : hasHigh ? 'HIGH_RISK_TAINTED' : hasMedium ? 'ELEVATED_TAINTED' : 'LOW_RISK_TAINTED';

  return {
    taintValue: val,
    isTainted: val !== 0,
    activeFlagsCount: activeFlags.length,
    flags: activeFlags,
    riskAssessment
  };
}

/**
 * Scan filesystem and environment for known Linux rootkit artifacts
 * @param {Object} [options={}]
 * @returns {Array<Object>} Rootkit artifact findings
 */
export function scanRootkitArtifacts(options = {}) {
  const findings = [];
  const testPreloadPath = options.ldPreloadPath || '/etc/ld.so.preload';
  const testEnv = options.env || process.env;
  const fileList = options.fileList || [];

  // 1. Check LD_PRELOAD modifications
  if (testEnv.LD_PRELOAD) {
    findings.push({
      type: 'LD_PRELOAD_ENV_INJECTION',
      severity: 'CRITICAL',
      mitreTechnique: 'T1574.006',
      target: 'LD_PRELOAD',
      details: `Environment variable LD_PRELOAD is active: ${testEnv.LD_PRELOAD}`
    });
  }

  if (fsSync.existsSync(testPreloadPath)) {
    try {
      const content = fsSync.readFileSync(testPreloadPath, 'utf8').trim();
      if (content.length > 0) {
        findings.push({
          type: 'LD_PRELOAD_FILE_MODIFIED',
          severity: 'HIGH',
          mitreTechnique: 'T1574.006',
          target: testPreloadPath,
          details: `/etc/ld.so.preload contains preloaded shared libraries: ${content}`
        });
      }
    } catch (err) {
      // Permission denied or missing
    }
  }

  // 2. Scan file paths for known rootkit prefixes
  for (const filePath of fileList) {
    const base = path.basename(filePath).toLowerCase();
    for (const sig of ROOTKIT_SIGNATURES) {
      if (base.includes(sig.prefix)) {
        findings.push({
          type: 'ROOTKIT_FILE_SIGNATURE_MATCH',
          severity: 'CRITICAL',
          mitreTechnique: sig.technique,
          target: filePath,
          rootkitName: sig.name,
          details: `File path matches signature prefix for rootkit '${sig.name}': ${filePath}`
        });
      }
    }
  }

  return findings;
}

/**
 * Compile a comprehensive rootkit audit report
 * @param {Object} auditComponents
 * @returns {Object} Structured report
 */
export function generateRootkitReport({
  syscallAnomalies = [],
  hiddenModules = [],
  taintAssessment = null,
  artifacts = []
} = {}) {
  const allFindings = [
    ...syscallAnomalies,
    ...hiddenModules,
    ...artifacts
  ];

  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = allFindings.filter(f => f.severity === 'HIGH').length;

  let overallStatus = 'CLEAN';
  if (criticalCount > 0) overallStatus = 'COMPROMISED_CRITICAL';
  else if (highCount > 0) overallStatus = 'SUSPICIOUS_HIGH';
  else if (allFindings.length > 0 || taintAssessment?.isTainted) overallStatus = 'WARNING';

  return {
    timestamp: new Date().toISOString(),
    overallStatus,
    summary: {
      totalFindings: allFindings.length,
      critical: criticalCount,
      high: highCount,
      syscallAnomaliesCount: syscallAnomalies.length,
      hiddenModulesCount: hiddenModules.length,
      artifactsCount: artifacts.length,
      isKernelTainted: taintAssessment?.isTainted || false
    },
    findings: allFindings,
    taintAssessment: taintAssessment || { isTainted: false, taintValue: 0 }
  };
}
