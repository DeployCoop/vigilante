/**
 * VIGILANTE Kernel-Level eBPF LSM Policy Synthesizer & Enforcement Engine
 * Compiles declarative YAML security rules into in-kernel Linux Security Module (BPF-LSM)
 * programs (bprm_check_security, file_open, socket_connect) and user-space evaluation simulation.
 */

import { load as yamlLoad } from 'js-yaml';
import { logger } from '../utils/logger.js';

/**
 * Standard Linux errno for permission denied
 */
export const EPERM = -13;

/**
 * Translates a declarative LSM condition into a C BPF expression
 * @param {Object} rule
 * @returns {string} C expression snippet
 */
export function compileLsmRuleToFilter(rule = {}) {
  const conditions = [];

  if (rule.comm) {
    const comms = Array.isArray(rule.comm) ? rule.comm : [rule.comm];
    const commChecks = comms.map(c => `!bpf_strncmp(current_comm, "${c}", ${c.length})`).join(' || ');
    conditions.push(`(${commChecks})`);
  }

  if (rule.parentComm) {
    const pcomms = Array.isArray(rule.parentComm) ? rule.parentComm : [rule.parentComm];
    const pChecks = pcomms.map(p => `!bpf_strncmp(parent_comm, "${p}", ${p.length})`).join(' || ');
    conditions.push(`(${pChecks})`);
  }

  if (rule.path) {
    const paths = Array.isArray(rule.path) ? rule.path : [rule.path];
    const pathChecks = paths.map(p => `bpf_str_contains(target_path, "${p}")`).join(' || ');
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
  if (typeof rulesYamlOrObj === 'string') {
    try {
      parsed = yamlLoad(rulesYamlOrObj);
    } catch {
      parsed = JSON.parse(rulesYamlOrObj);
    }
  } else {
    parsed = rulesYamlOrObj || {};
  }

  const policyName = parsed.name || options.name || `lsm-policy-${Date.now()}`;
  const version = parsed.version || '1.0.0';
  const rawRules = Array.isArray(parsed) ? parsed : (parsed.rules || []);

  const compiledRules = rawRules.map((rule, idx) => {
    const id = rule.id || `rule-${idx + 1}`;
    const hook = rule.hook || 'bprm_check_security'; // 'bprm_check_security', 'file_open', 'socket_connect'
    const action = (rule.action || 'DENY').toUpperCase();
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
      if (!commList.includes(event.comm)) match = false;
    }

    if (match && cond.parentComm) {
      const parentList = Array.isArray(cond.parentComm) ? cond.parentComm : [cond.parentComm];
      if (!parentList.includes(event.parentComm)) match = false;
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

  return `// SPDX-License-Identifier: GPL-2.0
// Auto-generated by Vigilante BPF-LSM Synthesizer
// Policy: ${policy.name} (v${policy.version})
// Created: ${policy.createdAt || new Date().toISOString()}

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 13

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    char current_comm[16];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));

${bprmRules.map(r => `    // Rule: ${r.name} (${r.description})
    if (${r.filterExpr}) {
        bpf_printk("[VIGILANTE-LSM] DENY execve: %s (Rule: ${r.id})\\n", current_comm);
        return -EPERM;
    }`).join('\n\n')}

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    char current_comm[16];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));

${fileRules.map(r => `    // Rule: ${r.name} (${r.description})
    if (${r.filterExpr}) {
        bpf_printk("[VIGILANTE-LSM] DENY file_open: %s (Rule: ${r.id})\\n", current_comm);
        return -EPERM;
    }`).join('\n\n')}

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
${socketRules.map(r => `    // Rule: ${r.name} (${r.description})
    if (${r.filterExpr}) {
        bpf_printk("[VIGILANTE-LSM] DENY socket_connect (Rule: ${r.id})\\n");
        return -EPERM;
    }`).join('\n\n')}

    return 0;
}
`;
}
