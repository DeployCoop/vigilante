#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import meow from 'meow';
import { App } from '../src/ui/App.js';
import { loadConfig } from '../src/engine/config.js';

const config = loadConfig();

const cli = meow(`
  Usage
    $ vigilante [command] [options]

  Commands
    up          Provision k3d cluster, certificates, and deploy modules
    down        Tear down k3d cluster and clean up resources
    status      Check status of prerequisites, cluster, certificates, and DNS
    modules     List available and installed modules
    pods        Live monitor of Kubernetes pods with -A -o wide details
    nmap/scan   Network reconnaissance & data collection saved to XDG nmaps dir
    xml/netmap  Interactive XML network topology & port matrix visualizer
    threat-sim  Trigger network threat simulation batch against SIEM
    hosts/hostr Sync local domain mappings into /etc/hosts
    values      Manage, list, or export customizable chart values.yaml files
    config      Inspect, initialize, or display $XDG_CONFIG_HOME/vigilante/config.yaml

  Options
    --domain, -d       Local top-level domain (Default: ${config.defaults?.domain || 'vigilante.local'})
    --cluster-name, -c Cluster name (Default: ${config.defaults?.clusterName || 'vigilante-dev'})
    --module, -m       Specific module(s) to install (comma-separated, Default: vigil-soc)
    --values, -f       Path to custom Helm values override file
    --values-dir       Path to directory containing custom values files (Default: ./values or XDG)
    --theme            UI theme (default, cyberpunk, dracula, nord, matrix, monokai)
    --ip               Target IP for hosts mapping (Default: ${config.defaults?.ip || '127.0.0.1'})
    --remove           Remove managed entries from /etc/hosts (for hosts/hostr)
    --check            Check /etc/hosts status without modifying (for hosts/hostr)
    --non-interactive  Run without interactive prompts
    --skip-prereqs     Skip prerequisite verification

  Examples
    $ vigilante up --domain dev.local
    $ vigilante up --theme dracula
    $ vigilante config path
    $ vigilante values export
    $ vigilante hostr
    $ vigilante status
    $ vigilante down
`, {
  importMeta: import.meta,
  flags: {
    domain: {
      type: 'string',
      shortFlag: 'd',
      default: config.defaults?.domain || 'vigilante.local'
    },
    clusterName: {
      type: 'string',
      shortFlag: 'c',
      default: config.defaults?.clusterName || 'vigilante-dev'
    },
    module: {
      type: 'string',
      shortFlag: 'm'
    },
    values: {
      type: 'string',
      shortFlag: 'f'
    },
    valuesDir: {
      type: 'string',
      default: config.defaults?.valuesDir || ''
    },
    theme: {
      type: 'string'
    },
    ip: {
      type: 'string',
      default: config.defaults?.ip || '127.0.0.1'
    },
    remove: {
      type: 'boolean',
      default: false
    },
    check: {
      type: 'boolean',
      default: false
    },
    nonInteractive: {
      type: 'boolean',
      default: false
    },
    skipPrereqs: {
      type: 'boolean',
      default: false
    }
  }
});

const command = cli.input[0] || 'up';
const subCommand = cli.input[1];
const hostsAction = cli.flags.remove ? 'remove' : cli.flags.check ? 'check' : 'sync';

render(
  React.createElement(App, {
    command,
    subCommand,
    domain: cli.flags.domain,
    clusterName: cli.flags.clusterName,
    selectedModules: cli.flags.module ? cli.flags.module.split(',').map(m => m.trim()) : undefined,
    customValuesPath: cli.flags.values,
    customValuesDir: cli.flags.valuesDir || null,
    theme: cli.flags.theme,
    hostsAction,
    ip: cli.flags.ip,
    nonInteractive: cli.flags.nonInteractive,
    skipPrereqs: cli.flags.skipPrereqs
  })
);
