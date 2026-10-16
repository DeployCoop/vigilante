/**
 * VIGILANTE Kernel-Level eBPF LSM Policy Synthesizer & Enforcement Engine
 * Compiles declarative YAML security rules into in-kernel Linux Security Module (BPF-LSM)
 * programs (bprm_check_security, file_open, socket_connect) and user-space evaluation simulation.
 */

import { load as yamlLoad } from 'js-yaml';
import { logger } from '../utils/logger.js';

/**
 * Return code for a denied event. Linux EPERM is errno 1, so an LSM hook
 * denies by returning -1. (The previous value, -13, is -EACCES — a
 * different errno — and the generated C repeated the mislabel.)
 */
export const EPERM = -1;

/**
 * Escape a value for interpolation into a C string literal in generated
 * code. Without this, a `"` or newline in a rule field breaks out of the
 * literal into arbitrary generated C.
 */
function escapeCString(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

/** Escape a value for interpolation into a C `//` comment. */
function escapeCComment(value) {
  return String(value).replace(/[\r\n]+/g, ' ').replace(/\*\//g, '* /');
}

/**
 * Conditions each LSM hook can actually evaluate in the generated C: the
 * hook bodies declare current_comm, parent_comm, and uid for every hook;
 * target_path exists only where a filename is at hand; dst_port only for
 * socket_connect. Rules using anything else are rejected at synthesis
 * time instead of generating C that cannot compile.
 */
const HOOK_CONDITIONS = {
  bprm_check_security: ['comm', 'parentComm', 'path', 'uid'],
  file_open: ['comm', 'parentComm', 'path', 'uid'],
  socket_connect: ['comm', 'parentComm', 'uid', 'port']
};

/**
 * Translates a declarative LSM condition into a C BPF expression
 * @param {Object} rule
 * @returns {string} C expression snippet
 */
export function compileLsmRuleToFilter(rule = {}) {
  const conditions = [];

  if (rule.comm) {
    const comms = Array.isArray(rule.comm) ? rule.comm : [rule.comm];
    const commChecks = comms.map(c => `!bpf_strncmp(current_comm, ${String(c).length}, "${escapeCString(c)}")`).join(' || ');
    conditions.push(`(${commChecks})`);
  }

  if (rule.parentComm) {
    const pcomms = Array.isArray(rule.parentComm) ? rule.parentComm : [rule.parentComm];
    const pChecks = pcomms.map(p => `!bpf_strncmp(parent_comm, ${String(p).length}, "${escapeCString(p)}")`).join(' || ');
    conditions.push(`(${pChecks})`);
  }

  if (rule.path) {
    const paths = Array.isArray(rule.path) ? rule.path : [rule.path];
    const pathChecks = paths.map(p => `vig_str_contains(target_path, "${escapeCString(p)}")`).join(' || ');
    conditions.push(`(${pathChecks})`);
  }

  if (rule.uid !== undefined) {
    conditions.push(`uid == ${Number(rule.uid)}`);
  }

  if (rule.port !== undefined) {
    conditions.push(`dst_port == ${Number(rule.port)}`);
  }

  return conditions.length > 0 ? conditions.join(' && ') : '1';
}

/**
 * Generates an eBPF LSM Policy from YAML/JSON specification
 * @param {string|Object} rulesYamlOrObj
 * @param {Object} options
 * @returns {Object} Compiled LSM policy descriptor
 */
export function generateBpfLsmPolicy(rulesYamlOrObj, options = {}) {
  let parsed;
  if (typeof rulesYamlOrObj === 'string' && rulesYamlOrObj.trim() === '') {
    // js-yaml v5 throws on empty input instead of returning undefined;
    // an empty policy spec is simply an empty policy.
    parsed = {};
  } else if (typeof rulesYamlOrObj === 'string') {
    try {
      parsed = yamlLoad(rulesYamlOrObj);
    } catch {
      parsed = JSON.parse(rulesYamlOrObj);
    }
  } else {
    parsed = rulesYamlOrObj || {};
  }
  // Empty input parses to undefined/null (and a bare scalar parses to a
  // string): normalize instead of dereferencing .name on a non-object.
  if (!parsed || typeof parsed !== 'object') parsed = {};

  const policyName = parsed.name || options.name || `lsm-policy-${Date.now()}`;
  const version = parsed.version || '1.0.0';
  const rawRules = Array.isArray(parsed) ? parsed : (parsed.rules || []);

  const compiledRules = rawRules.map((rule, idx) => {
    const id = rule.id || `rule-${idx + 1}`;
    const hook = rule.hook || 'bprm_check_security'; // 'bprm_check_security', 'file_open', 'socket_connect'
    const action = (rule.action || 'DENY').toUpperCase();

    // Reject what the generated C cannot express: an unknown hook would
    // silently vanish from the C (and never match in simulation), and a
    // condition the hook body doesn't declare made the C uncompilable.
    const supported = HOOK_CONDITIONS[hook];
    if (!supported) {
      throw new Error(`Rule '${id}' uses unsupported LSM hook '${hook}'`);
    }
    const usedConditions = [];
    if (rule.comm) usedConditions.push('comm');
    if (rule.parentComm) usedConditions.push('parentComm');
    if (rule.path) usedConditions.push('path');
    if (rule.uid !== undefined) usedConditions.push('uid');
    if (rule.port !== undefined) usedConditions.push('port');
    for (const condName of usedConditions) {
      if (!supported.includes(condName)) {
        throw new Error(`Rule '${id}' uses condition '${condName}', which hook '${hook}' cannot evaluate in generated C`);
      }
    }

    const filterExpr = compileLsmRuleToFilter(rule);

    return {
      id,
      name: rule.name || id,
      hook,
      action,
      filterExpr,
      conditions: {
        comm: rule.comm || null,
        parentComm: rule.parentComm || null,
        path: rule.path || null,
        uid: rule.uid !== undefined ? rule.uid : null,
        port: rule.port !== undefined ? rule.port : null
      },
      mitreTechnique: rule.mitre || rule.mitreTechnique || null,
      description: rule.description || `BPF-LSM ${hook} enforcement`
    };
  });

  const policy = {
    name: policyName,
    version,
    description: parsed.description || 'Vigilante Synthesized In-Kernel BPF-LSM Enforcement Policy',
    rulesCount: compiledRules.length,
    hooks: Array.from(new Set(compiledRules.map(r => r.hook))),
    rules: compiledRules,
    createdAt: new Date().toISOString()
  };

  policy.cSource = exportLsmCSource(policy);
  logger.info('LSM', `Synthesized BPF-LSM policy '${policyName}' with ${compiledRules.length} rules.`);
  return policy;
}

/**
 * Simulates BPF-LSM in-kernel policy evaluation against an execution or file event
 * @param {Object} policy - Output from generateBpfLsmPolicy
 * @param {Object} event - { hook, comm, parentComm, path, uid, port }
 * @returns {Object} Evaluation verdict
 */
export function simulateLsmPolicyEvaluation(policy, event = {}) {
  const hook = event.hook || (event.path ? 'file_open' : (event.port ? 'socket_connect' : 'bprm_check_security'));
  const matchingRules = (policy.rules || []).filter(r => r.hook === hook);

  for (const rule of matchingRules) {
    let match = true;
    const cond = rule.conditions;

    if (cond.comm) {
      const commList = Array.isArray(cond.comm) ? cond.comm : [cond.comm];
      // Mirror the generated C: bpf_strncmp(current_comm, name, len) is a
      // PREFIX match, so 'bash' also matches 'bash2' in-kernel. The
      // simulator must agree, or it reports ALLOW for events the compiled
      // filter would block.
      if (!commList.some(c => typeof event.comm === 'string' && event.comm.startsWith(String(c)))) match = false;
    }

    if (match && cond.parentComm) {
      const parentList = Array.isArray(cond.parentComm) ? cond.parentComm : [cond.parentComm];
      if (!parentList.some(p => typeof event.parentComm === 'string' && event.parentComm.startsWith(String(p)))) match = false;
    }

    if (match && cond.path) {
      const pathList = Array.isArray(cond.path) ? cond.path : [cond.path];
      if (!event.path || !pathList.some(p => event.path.includes(p))) match = false;
    }

    if (match && cond.uid !== null) {
      if (Number(event.uid) !== Number(cond.uid)) match = false;
    }

    if (match && cond.port !== null) {
      if (Number(event.port) !== Number(cond.port)) match = false;
    }

    if (match) {
      if (rule.action === 'DENY' || rule.action === 'BLOCK') {
        return {
          allowed: false,
          action: 'BLOCK',
          returnCode: EPERM,
          matchedRule: rule.id,
          hook: rule.hook,
          mitreTechnique: rule.mitreTechnique,
          reason: `In-kernel BPF-LSM blocked event by rule '${rule.name}' (${rule.description})`
        };
      }
    }
  }

  return {
    allowed: true,
    action: 'ALLOW',
    returnCode: 0,
    matchedRule: null,
    hook,
    reason: 'Permitted: No matching in-kernel BPF-LSM deny policy'
  };
}

/**
 * Generates compile-ready BPF-LSM C source code
 * @param {Object} policy
 * @returns {string} C source code
 */
export function exportLsmCSource(policy) {
  const bprmRules = (policy.rules || []).filter(r => r.hook === 'bprm_check_security');
  const fileRules = (policy.rules || []).filter(r => r.hook === 'file_open');
  const socketRules = (policy.rules || []).filter(r => r.hook === 'socket_connect');

  // Every hook body declares every variable the filter compiler can
  // reference for that hook (see HOOK_CONDITIONS): previously the socket
  // body declared nothing at all and the others only current_comm, so any
  // non-comm condition produced C that could not compile.
  const commonDecls = `    char current_comm[16];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));

    char parent_comm[16] = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, parent);
    if (parent_task)
        BPF_CORE_READ_STR(parent_comm, sizeof(parent_comm), parent_task, comm);

    __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);`;

  const ruleBlock = (r, message) => `    // Rule: ${escapeCComment(r.name)} (${escapeCComment(r.description)})
    if (${r.filterExpr}) {
        bpf_printk("[VIGILANTE-LSM] DENY ${message} (Rule: ${escapeCString(r.id)})\\n"${message.includes('%s') ? ', current_comm' : ''});
        return -EPERM;
    }`;

  return `// SPDX-License-Identifier: GPL-2.0
// Auto-generated by Vigilante BPF-LSM Synthesizer
// Policy: ${escapeCComment(policy.name)} (v${escapeCComment(policy.version)})
// Created: ${escapeCComment(policy.createdAt || new Date().toISOString())}

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

/* Substring search over a bounded, NUL-terminated path buffer. */
static __always_inline int vig_str_contains(const char *haystack, const char *needle)
{
    if (!needle[0])
        return 1;
    for (int i = 0; i < 192 && haystack[i]; i++) {
        int j = 0;
        while (j < 64 && needle[j] && haystack[i + j] == needle[j])
            j++;
        if (!needle[j])
            return 1;
        if (!haystack[i + j] && needle[j])
            continue;
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

${commonDecls}

    char target_path[256];
    bpf_probe_read_kernel_str(target_path, sizeof(target_path), bprm->filename);

${bprmRules.map(r => ruleBlock(r, 'execve: %s')).join('\n\n')}

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
${commonDecls}

    char target_path[256];
    bpf_d_path(&file->f_path, target_path, sizeof(target_path));

${fileRules.map(r => ruleBlock(r, 'file_open: %s')).join('\n\n')}

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
${commonDecls}

    __u16 dst_port = 0;
    if (address && address->sa_family == 2) /* AF_INET */
        dst_port = bpf_ntohs(((struct sockaddr_in *)address)->sin_port);

${socketRules.map(r => ruleBlock(r, 'socket_connect')).join('\n\n')}

    return 0;
}
`;
}
