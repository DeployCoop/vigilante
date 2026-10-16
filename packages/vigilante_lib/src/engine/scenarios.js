import fs from 'fs/promises';
import path from 'path';
import * as yaml from 'js-yaml';
import { execFileSync } from 'child_process';
import os from 'os';

/**
 * Scenario Engine
 * Loads and runs security scenario playbooks (YAML format).
 */

import { fileURLToPath } from 'url';
import { resolvePathInside, assertDnsLabel } from './config.js';

/**
 * Split a scenario step command into argv words using shell quoting rules
 * (whitespace separation, single quotes literal, double quotes with \"
 * and \\ escapes, backslash escaping). The result is executed WITHOUT a
 * shell, so metacharacters in the command (`;`, `&&`, `$()`, backticks,
 * redirects) become inert literal arguments instead of host commands.
 * Quoting still works for the intended use: everything after a `--` in a
 * kubectl step (e.g. `sh -c '...'`) is passed through as pod argv exactly
 * as written.
 */
export function splitCommandWords(command) {
  const words = [];
  let current = '';
  let hasWord = false;
  let quote = null; // null | "'" | '"'
  const s = String(command);
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else current += ch;
    } else if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === '\\' && (s[i + 1] === '"' || s[i + 1] === '\\')) current += s[++i];
      else current += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      hasWord = true;
    } else if (ch === '\\' && i + 1 < s.length) {
      current += s[++i];
      hasWord = true;
    } else if (/\s/.test(ch)) {
      if (hasWord || current.length > 0) {
        words.push(current);
        current = '';
        hasWord = false;
      }
    } else {
      current += ch;
      hasWord = true;
    }
  }
  if (quote !== null) {
    throw new Error(`Unterminated ${quote} quote in scenario command`);
  }
  if (hasWord || current.length > 0) words.push(current);
  return words;
}

export class ScenarioEngine {
  constructor(options = {}) {
    this.userScenarioDir = options.scenarioDir || path.join(os.homedir(), '.config', 'vigilante', 'scenarios');
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    this.bundledScenarioDir = path.join(currentDir, '..', '..', 'scenarios');
  }

  async listScenarios() {
    const scenarios = [];
    
    for (const dir of [this.bundledScenarioDir, this.userScenarioDir]) {
      try {
        const files = await fs.readdir(dir);
        for (const file of files) {
          if (file.endsWith('.yaml') || file.endsWith('.yml')) {
            const content = await fs.readFile(path.join(dir, file), 'utf8');
            const parsed = yaml.load(content);
            if (parsed && parsed.name) {
              scenarios.push({
                id: path.basename(file, path.extname(file)),
                name: parsed.name,
                description: parsed.description,
              });
            }
          }
        }
      } catch (err) {
        if (err.code !== 'ENOENT') {
          console.error(`Error reading scenarios from ${dir}:`, err);
        }
      }
    }
    
    // Deduplicate by ID
    const uniqueScenarios = Array.from(new Map(scenarios.map(s => [s.id, s])).values());
    return uniqueScenarios;
  }

  async runScenario(scenarioId) {
    // The scenario id must resolve inside the scenario directories — a
    // '../' id would otherwise load (and execute the steps of) any YAML
    // file on disk.
    const filePaths = [];
    for (const dir of [this.userScenarioDir, this.bundledScenarioDir]) {
      for (const ext of ['yaml', 'yml']) {
        try {
          filePaths.push(resolvePathInside(dir, `${scenarioId}.${ext}`));
        } catch {
          // Id escapes this directory: not a candidate.
        }
      }
    }

    let content = null;
    for (const fp of filePaths) {
      try {
        content = await fs.readFile(fp, 'utf8');
        break;
      } catch (e) {
        // ignore and try next
      }
    }

    if (!content) {
      throw new Error(`Scenario ${scenarioId} not found.`);
    }

    const playbook = yaml.load(content);
    console.log(`[+] Starting scenario: ${playbook.name}`);
    console.log(`[i] Description: ${playbook.description}\n`);

    if (playbook.steps && Array.isArray(playbook.steps)) {
      for (const step of playbook.steps) {
        console.log(`[*] Executing step: ${step.name}`);
        if (step.type === 'kubectl') {
          this.executeKubectl(step.command, step.namespace);
        } else if (step.type === 'helm') {
          this.executeHelm(step.command);
        } else if (step.type === 'delay') {
          console.log(`    ...waiting ${step.seconds} seconds...`);
          await new Promise(r => setTimeout(r, step.seconds * 1000));
        } else {
          console.log(`[!] Unknown step type: ${step.type}`);
        }
      }
    }

    console.log(`\n[+] Scenario ${playbook.name} completed.`);
  }

  executeKubectl(command, namespace = 'default') {
    try {
      assertDnsLabel(namespace, 'namespace');
      const args = [...splitCommandWords(command), '-n', namespace];
      console.log(`    > kubectl ${args.join(' ')}`);
      execFileSync('kubectl', args, { stdio: 'inherit' });
    } catch (err) {
      console.error(`[-] Error executing kubectl command: ${err.message}`);
    }
  }

  executeHelm(command) {
    try {
      const args = splitCommandWords(command);
      console.log(`    > helm ${args.join(' ')}`);
      execFileSync('helm', args, { stdio: 'inherit' });
    } catch (err) {
      console.error(`[-] Error executing helm command: ${err.message}`);
    }
  }
}
