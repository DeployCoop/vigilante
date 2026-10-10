import fs from 'fs/promises';
import path from 'path';
import * as yaml from 'js-yaml';
import { execSync } from 'child_process';
import os from 'os';

/**
 * Scenario Engine
 * Loads and runs security scenario playbooks (YAML format).
 */

import { fileURLToPath } from 'url';

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
    const filePaths = [
      path.join(this.userScenarioDir, `${scenarioId}.yaml`),
      path.join(this.userScenarioDir, `${scenarioId}.yml`),
      path.join(this.bundledScenarioDir, `${scenarioId}.yaml`),
      path.join(this.bundledScenarioDir, `${scenarioId}.yml`),
    ];

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
      const fullCmd = `kubectl ${command} -n ${namespace}`;
      console.log(`    > ${fullCmd}`);
      execSync(fullCmd, { stdio: 'inherit' });
    } catch (err) {
      console.error(`[-] Error executing kubectl command: ${err.message}`);
    }
  }

  executeHelm(command) {
    try {
      const fullCmd = `helm ${command}`;
      console.log(`    > ${fullCmd}`);
      execSync(fullCmd, { stdio: 'inherit' });
    } catch (err) {
      console.error(`[-] Error executing helm command: ${err.message}`);
    }
  }
}
