#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import meow from 'meow';
import { App } from '../src/ui/App.js';

const cli = meow(`
  Usage
    $ vigilante [command] [options]

  Commands
    up          Provision k3d cluster, certificates, and deploy modules
    down        Tear down k3d cluster and clean up resources
    status      Check status of prerequisites, cluster, certificates, and DNS
    modules     List available and installed modules
    threat-sim  Trigger network threat simulation batch against SIEM
    hosts/hostr Sync local domain mappings into /etc/hosts

  Options
    --domain, -d       Local top-level domain (Default: vigilante.local)
    --cluster-name, -c Cluster name (Default: vigilante-dev)
    --module, -m       Specific module(s) to install (comma-separated, Default: vigil-soc)
    --ip               Target IP for hosts mapping (Default: 127.0.0.1)
    --remove           Remove managed entries from /etc/hosts (for hosts/hostr)
    --check            Check /etc/hosts status without modifying (for hosts/hostr)
    --non-interactive  Run without interactive prompts
    --skip-prereqs     Skip prerequisite verification

  Examples
    $ vigilante up --domain dev.local
    $ vigilante hostr
    $ vigilante hostr --remove
    $ vigilante status
    $ vigilante down
`, {
  importMeta: import.meta,
  flags: {
    domain: {
      type: 'string',
      shortFlag: 'd',
      default: 'vigilante.local'
    },
    clusterName: {
      type: 'string',
      shortFlag: 'c',
      default: 'vigilante-dev'
    },
    module: {
      type: 'string',
      shortFlag: 'm'
    },
    ip: {
      type: 'string',
      default: '127.0.0.1'
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
const hostsAction = cli.flags.remove ? 'remove' : cli.flags.check ? 'check' : 'sync';

render(
  React.createElement(App, {
    command,
    domain: cli.flags.domain,
    clusterName: cli.flags.clusterName,
    selectedModules: cli.flags.module ? cli.flags.module.split(',').map(m => m.trim()) : undefined,
    hostsAction,
    ip: cli.flags.ip,
    nonInteractive: cli.flags.nonInteractive,
    skipPrereqs: cli.flags.skipPrereqs
  })
);
