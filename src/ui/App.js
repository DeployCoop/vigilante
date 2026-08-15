import React, { useState, useEffect } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import { Header } from './Header.js';
import { TaskRunner } from './TaskRunner.js';
import { SelectModules } from './SelectModules.js';
import { StatusDashboard } from './StatusDashboard.js';
import { ThreatSimView } from './ThreatSimView.js';
import { MenuBar } from './MenuBar.js';
import { ClipboardProvider, ToastBanner, useClipboard } from './ClipboardManager.js';
import { logger } from '../utils/logger.js';

import { checkPrereqs } from '../engine/prereqs.js';
import { setupCertificates, checkCertificates } from '../engine/certs.js';
import { createK3dCluster, deleteK3dCluster, getClusterInfo } from '../engine/cluster.js';
import { checkHosts, syncHosts, removeHosts } from '../engine/hosts.js';
import { exportStarterValues, listChartValues } from '../engine/helm.js';
import { globalModuleRegistry } from '../modules/registry.js';

const AppContent = ({
  command = 'up',
  subCommand = null,
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  selectedModules: cliSelectedModules,
  customValuesPath = null,
  customValuesDir = null,
  hostsAction = 'sync',
  ip = '127.0.0.1',
  nonInteractive = false,
  skipPrereqs = false
}) => {
  const { exit } = useApp();
  const { copiedToast } = useClipboard();
  const [viewState, setViewState] = useState(
    command === 'up' && !cliSelectedModules && !nonInteractive ? 'SELECT_MODULES' : 'RUNNING'
  );
  const [chosenModules, setChosenModules] = useState(
    cliSelectedModules || ['vigil-soc']
  );
  const [tasks, setTasks] = useState([]);
  const [logs, setLogs] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);
  const [fatalError, setFatalError] = useState(null);
  const [isDone, setIsDone] = useState(false);

  // Log application startup
  useEffect(() => {
    logger.info('APP:START', `Mounted App with command=${command}, subCommand=${subCommand}, domain=${domain}, clusterName=${clusterName}, nonInteractive=${nonInteractive}`);
  }, []);

  // Keyboard navigation & interactive menu shortcuts
  useInput((input, key) => {
    if (viewState === 'SELECT_MODULES') return;

    // In-flight active task: only allow exit/abort
    const isRunning = viewState === 'RUNNING' && !isDone;
    logger.debug('UI:KEY', `Key received: input="${input}", isRunning=${isRunning}, viewState=${viewState}, isDone=${isDone}`);

    if (isRunning) {
      if (key.escape || input === 'q' || input === 'Q') {
        logger.info('UI:ABORT', 'User requested abort during running task');
        exit();
      }
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // Trigger Up Workflow
    if (keyChar === 'u') {
      logger.info('UI:ACTION', 'User pressed [u] -> Starting UP workflow');
      setFatalError(null);
      setIsDone(false);
      runUpWorkflow(chosenModules);
      return;
    }

    // Trigger Down (Teardown) Workflow
    if (keyChar === 'd') {
      logger.info('UI:ACTION', 'User pressed [d] -> Starting DOWN workflow');
      setFatalError(null);
      setIsDone(false);
      runDownWorkflow();
      return;
    }

    // Trigger Status Dashboard Workflow
    if (keyChar === 's') {
      logger.info('UI:ACTION', 'User pressed [s] -> Starting STATUS workflow');
      setFatalError(null);
      setIsDone(false);
      runStatusWorkflow();
      return;
    }

    // Trigger Threat Simulation
    if (keyChar === 't') {
      logger.info('UI:ACTION', 'User pressed [t] -> Switching to THREAT_SIM view');
      setFatalError(null);
      setViewState('THREAT_SIM');
      return;
    }

    // Trigger Hosts (DNS) Workflow
    if (keyChar === 'h') {
      logger.info('UI:ACTION', 'User pressed [h] -> Starting HOSTR workflow');
      setFatalError(null);
      setIsDone(false);
      runHostsWorkflow();
      return;
    }

    // Trigger Values (Helm) Workflow
    if (keyChar === 'v') {
      logger.info('UI:ACTION', 'User pressed [v] -> Starting VALUES workflow');
      setFatalError(null);
      setIsDone(false);
      runValuesWorkflow();
      return;
    }

    // Trigger Modules List Workflow
    if (keyChar === 'm') {
      logger.info('UI:ACTION', 'User pressed [m] -> Starting MODULES workflow');
      setFatalError(null);
      setIsDone(false);
      runModulesWorkflow();
      return;
    }

    // Exit / Return to Dashboard
    if (keyChar === 'q' || key.escape || (isDone && key.return)) {
      if (viewState === 'THREAT_SIM' && dashboardData) {
        logger.info('UI:ACTION', 'User pressed [q/Esc] from THREAT_SIM -> Returning to DASHBOARD');
        setViewState('DASHBOARD');
      } else {
        logger.info('UI:ACTION', 'User pressed [q/Esc/Enter] -> Exiting');
        exit();
      }
    }
  });

  // Auto-exit if non-interactive and finished
  useEffect(() => {
    if (nonInteractive && isDone) {
      exit();
    }
  }, [nonInteractive, isDone]);

  const addLog = (message) => {
    const text = typeof message === 'string' ? message : JSON.stringify(message);
    logger.debug('TASK:LOG', text);
    setLogs((prev) => [...prev, text]);
  };

  const updateTask = (id, updates) => {
    logger.debug('TASK:UPDATE', `Task '${id}' -> ${JSON.stringify(updates)}`);
    setTasks((prev) =>
      prev.map((t) => (t.id === id ? { ...t, ...updates } : t))
    );
  };

  // -------------------------------------------------------------
  // Command: UP
  // -------------------------------------------------------------
  const runUpWorkflow = async (modulesToInstall) => {
    logger.info('WORKFLOW:UP', `Starting UP workflow with modules: ${JSON.stringify(modulesToInstall)}`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    const initialTasks = [
      { id: 'prereqs', label: 'Verify system prerequisites (Docker, k3d, mkcert, kubectl, Helm)', status: 'pending' },
      { id: 'certs', label: `Generate local TLS certificates for ${domain} (*.${domain})`, status: 'pending' },
      { id: 'hosts', label: `Sync local domain mappings in /etc/hosts (*.${domain})`, status: 'pending' },
      { id: 'cluster', label: `Orchestrate k3d cluster '${clusterName}' with Ingress bindings`, status: 'pending' },
      ...modulesToInstall.map((mId) => {
        const mod = globalModuleRegistry.get(mId);
        return {
          id: `mod-${mId}`,
          label: `Deploy security package: ${mod ? mod.name : mId}`,
          status: 'pending'
        };
      })
    ];
    setTasks(initialTasks);

    try {
      // Step 1: Prereqs
      if (!skipPrereqs) {
        updateTask('prereqs', { status: 'running' });
        addLog('Checking prerequisites...');
        const prereqResults = await checkPrereqs();
        if (!prereqResults.ready) {
          const missingNames = prereqResults.missing.map(m => m.name).join(', ');
          const errDetail = prereqResults.missing.map(m => `• ${m.name}: ${m.error || m.installHint}`).join('\n');
          updateTask('prereqs', { status: 'error', error: `Missing prerequisites: ${missingNames}` });
          addLog(`\nMissing required tools:\n${errDetail}`);
          throw new Error(`Prerequisites check failed. Please install missing tools and try again.`);
        }
        updateTask('prereqs', { status: 'done' });
      } else {
        updateTask('prereqs', { status: 'done', detail: 'Skipped via flag' });
      }

      // Step 2: Certs
      updateTask('certs', { status: 'running' });
      addLog(`Setting up local CA and generating TLS certificates for *.${domain}...`);
      const certs = await setupCertificates(domain);
      addLog(`Certificates generated:\n  Cert: ${certs.certPath}\n  Key:  ${certs.keyPath}`);
      updateTask('certs', { status: 'done' });

      // Step 3: Local Hosts (hostr)
      updateTask('hosts', { status: 'running' });
      addLog(`Configuring local DNS mappings in /etc/hosts for *.${domain}...`);
      try {
        await syncHosts({
          domain,
          ip,
          onLog: (msg) => addLog(msg)
        });
        updateTask('hosts', { status: 'done' });
      } catch (hostsErr) {
        updateTask('hosts', { status: 'done', detail: 'Warning: skipped (requires sudo)' });
        addLog(`[hostr] Notice: Unable to auto-update /etc/hosts (${hostsErr.message}). Run 'vigilante hostr' or update manually.`);
      }

      // Step 4: Cluster
      updateTask('cluster', { status: 'running' });
      addLog(`Creating k3d cluster '${clusterName}'...`);
      await createK3dCluster(clusterName, {
        onLog: (msg) => addLog(msg)
      });
      updateTask('cluster', { status: 'done' });

      // Step 5: Modules
      const resolvedModules = globalModuleRegistry.resolveModules(modulesToInstall);
      for (const mod of resolvedModules) {
        const taskId = `mod-${mod.id}`;
        updateTask(taskId, { status: 'running' });
        addLog(`Installing module ${mod.name}...`);
        await mod.install({
          domain,
          certPath: certs.certPath,
          keyPath: certs.keyPath,
          clusterName,
          onLog: (msg) => addLog(msg)
        });
        updateTask(taskId, { status: 'done' });
      }

      addLog('All components provisioned successfully! Loading environment status...');
      const prereqs = await checkPrereqs();
      const cluster = await getClusterInfo(clusterName);
      const hosts = await checkHosts({ domain, ip });
      const allModules = globalModuleRegistry.getAll();
      const modulesStatus = await Promise.all(
        allModules.map(async (m) => {
          return await m.status({ domain, clusterName });
        })
      );

      setDashboardData({
        prereqs,
        cluster,
        certs,
        hosts,
        modules: modulesStatus,
        domain
      });

      setIsDone(true);
      setViewState('DASHBOARD');
    } catch (err) {
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: DOWN
  // -------------------------------------------------------------
  const runDownWorkflow = async () => {
    logger.info('WORKFLOW:DOWN', `Starting DOWN teardown workflow for cluster '${clusterName}'`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      { id: 'down', label: `Tearing down k3d cluster '${clusterName}'`, status: 'running' },
      { id: 'hosts', label: `Clean up /etc/hosts domain mappings`, status: 'pending' }
    ]);

    try {
      addLog(`Destroying cluster '${clusterName}'...`);
      const res = await deleteK3dCluster(clusterName, {
        onLog: (msg) => addLog(msg)
      });
      if (res.status === 'not_found') {
        addLog(`Cluster '${clusterName}' was not found.`);
      } else {
        addLog(`Cluster '${clusterName}' destroyed successfully.`);
      }
      updateTask('down', { status: 'done' });

      updateTask('hosts', { status: 'running' });
      addLog(`Cleaning up /etc/hosts managed domain mappings...`);
      try {
        await removeHosts({ onLog: (msg) => addLog(msg) });
        updateTask('hosts', { status: 'done' });
      } catch {
        updateTask('hosts', { status: 'done', detail: 'Skipped' });
      }

      addLog('Environment torn down successfully.');
      setIsDone(true);
    } catch (err) {
      updateTask('down', { status: 'error', error: err.message });
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: STATUS
  // -------------------------------------------------------------
  const runStatusWorkflow = async () => {
    logger.info('WORKFLOW:STATUS', `Starting STATUS workflow for domain '${domain}'`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      { id: 'status', label: 'Inspecting local environment status', status: 'running' }
    ]);

    try {
      addLog('Gathering prerequisite checks, cluster status, and module health...');
      const prereqs = await checkPrereqs();
      const cluster = await getClusterInfo(clusterName);
      const certs = await checkCertificates(domain);
      const hosts = await checkHosts({ domain, ip });

      const allModules = globalModuleRegistry.getAll();
      const modulesStatus = await Promise.all(
        allModules.map(async (mod) => {
          return await mod.status({ domain, clusterName });
        })
      );

      setDashboardData({
        prereqs,
        cluster,
        certs,
        hosts,
        modules: modulesStatus,
        domain
      });

      updateTask('status', { status: 'done' });
      setViewState('DASHBOARD');
      setIsDone(true);
    } catch (err) {
      updateTask('status', { status: 'error', error: err.message });
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: MODULES
  // -------------------------------------------------------------
  const runModulesWorkflow = async () => {
    logger.info('WORKFLOW:MODULES', 'Starting MODULES workflow');
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      { id: 'modules', label: 'Listing available security modules', status: 'running' }
    ]);

    try {
      const allModules = globalModuleRegistry.getAll();
      const modulesStatus = await Promise.all(
        allModules.map(async (mod) => {
          const st = await mod.status({ domain, clusterName });
          const endpoints = await mod.getEndpoints({ domain });
          return { ...st, endpoints };
        })
      );

      setDashboardData({
        modules: modulesStatus,
        domain
      });

      updateTask('modules', { status: 'done' });
      setViewState('MODULES_LIST');
      setIsDone(true);
    } catch (err) {
      updateTask('modules', { status: 'error', error: err.message });
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: HOSTR / HOSTS
  // -------------------------------------------------------------
  const runHostsWorkflow = async () => {
    logger.info('WORKFLOW:HOSTR', `Starting HOSTR workflow (action=${hostsAction}, domain=${domain})`);
    const isCheck = hostsAction === 'check';
    const isRemove = hostsAction === 'remove';

    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      {
        id: 'hosts',
        label: isCheck
          ? `Check /etc/hosts domain resolution status (*.${domain})`
          : isRemove
          ? `Remove local domain mappings (*.${domain}) from /etc/hosts`
          : `Sync local domain mappings (*.${domain}) in /etc/hosts`,
        status: 'running'
      }
    ]);

    try {
      if (isCheck) {
        const info = await checkHosts({ domain, ip });
        if (info.configured) {
          addLog(`✔ All required hostnames are mapped in /etc/hosts:`);
          for (const h of info.configuredHosts) {
            addLog(`  • ${ip} ${h}`);
          }
        } else {
          if (info.configuredHosts.length > 0) {
            addLog(`○ Configured hostnames: ${info.configuredHosts.join(', ')}`);
          }
          addLog(`✖ Missing hostnames: ${info.missingHosts.join(', ')}`);
          addLog(`Run 'vigilante hostr' to synchronize missing entries.`);
        }
      } else if (isRemove) {
        addLog(`Removing Vigilante managed block from /etc/hosts...`);
        const res = await removeHosts({ onLog: (msg) => addLog(msg) });
        if (res.removed) {
          addLog(`✔ Removed managed hosts block from /etc/hosts.`);
        } else {
          addLog(`✔ No managed hosts block found in /etc/hosts.`);
        }
      } else {
        addLog(`Synchronizing domain hosts for *.${domain} in /etc/hosts...`);
        const res = await syncHosts({ domain, ip, onLog: (msg) => addLog(msg) });
        if (res.alreadySynced) {
          addLog(`✔ /etc/hosts already up to date for *.${domain}!`);
        } else {
          addLog(`✔ Synchronized /etc/hosts mappings: ${res.hosts.join(', ')} -> ${ip}`);
        }
      }
      updateTask('hosts', { status: 'done' });
      setIsDone(true);
    } catch (err) {
      updateTask('hosts', { status: 'error', error: err.message });
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: VALUES / CONFIG
  // -------------------------------------------------------------
  const runValuesWorkflow = async () => {
    logger.info('WORKFLOW:VALUES', `Starting VALUES workflow (subCommand=${subCommand})`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      { id: 'values', label: 'Manage customizable Helm chart values.yaml configurations', status: 'running' }
    ]);

    try {
      if (subCommand === 'export' || subCommand === 'dump' || subCommand === 'init') {
        const targetDir = customValuesDir || './values';
        addLog(`Exporting editable starter values.yaml templates to '${targetDir}'...`);
        const exported = await exportStarterValues({
          targetDir,
          onLog: (msg) => addLog(msg)
        });
        addLog(`✔ Successfully exported ${exported.length} starter chart values files!`);
        addLog(`You can now customize these files in '${targetDir}' and run 'vigilante up'.`);
      } else {
        addLog('Customizable Helm chart configurations across Vigilante packages:');
        const items = await listChartValues({ customValuesDir });
        for (const item of items) {
          addLog(`• Module: ${item.moduleId} | Chart: ${item.chartName}`);
          addLog(`    Default template: ${item.defaultPath}`);
          if (item.userOverridePath) {
            addLog(`    ✔ Active user override: ${item.userOverridePath}`);
          } else {
            addLog(`    ○ No user override detected. Run 'vigilante values export' to create custom files.`);
          }
        }
      }
      updateTask('values', { status: 'done' });
      setIsDone(true);
    } catch (err) {
      updateTask('values', { status: 'error', error: err.message });
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // Bootstrap based on command
  useEffect(() => {
    if (command === 'up') {
      if (viewState !== 'SELECT_MODULES') {
        runUpWorkflow(chosenModules);
      }
    } else if (command === 'down') {
      runDownWorkflow();
    } else if (command === 'status') {
      runStatusWorkflow();
    } else if (command === 'modules') {
      runModulesWorkflow();
    } else if (command === 'threat-sim') {
      setViewState('THREAT_SIM');
    } else if (command === 'hosts' || command === 'hostr') {
      runHostsWorkflow();
    } else if (command === 'values' || command === 'config') {
      runValuesWorkflow();
    } else {
      setFatalError(`Unknown command: ${command}`);
      setIsDone(true);
    }
  }, []);

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1 },
    React.createElement(Header, { command, domain }),

    // State 1: Select Modules Screen
    viewState === 'SELECT_MODULES'
      ? React.createElement(SelectModules, {
          modules: globalModuleRegistry.getAll(),
          initialSelected: chosenModules,
          onConfirm: (selected) => {
            if (selected.length === 0) {
              setFatalError('At least one security module must be selected.');
              return;
            }
            setChosenModules(selected);
            runUpWorkflow(selected);
          }
        })
      : null,

    // State 2: Running Tasks
    viewState === 'RUNNING'
      ? React.createElement(TaskRunner, { tasks, logs })
      : null,

    // State 3: Threat Simulation
    viewState === 'THREAT_SIM'
      ? React.createElement(ThreatSimView, { domain, onDone: () => setIsDone(true) })
      : null,

    // State 4: Status Dashboard
    viewState === 'DASHBOARD' && dashboardData
      ? React.createElement(StatusDashboard, dashboardData)
      : null,

    // State 5: Modules List View
    viewState === 'MODULES_LIST' && dashboardData
      ? React.createElement(
          Box,
          { flexDirection: 'column', borderStyle: 'round', borderColor: 'cyan', padding: 1 },
          React.createElement(Text, { bold: true, color: 'cyan' }, '📦 Available Security Packages:'),
          dashboardData.modules.map(mod =>
            React.createElement(
              Box,
              { key: mod.id, flexDirection: 'column', marginY: 1 },
              React.createElement(
                Box,
                null,
                React.createElement(Text, { bold: true, color: 'yellow' }, `• ${mod.name}`),
                React.createElement(
                  Text,
                  { color: mod.installed ? 'green' : 'gray' },
                  ` [${mod.status}]`
                )
              ),
              React.createElement(
                Text,
                { color: 'gray', marginLeft: 2 },
                `Endpoints: ${mod.endpoints?.map(e => e.url).join(', ') || 'None'}`
              )
            )
          )
        )
      : null,

    // State 6: Success View
    viewState === 'SUCCESS'
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginTop: 1, padding: 1, borderStyle: 'round', borderColor: 'green' },
          React.createElement(
            Text,
            { bold: true, color: 'green' },
            '🎉 VIGILANTE ENVIRONMENT READY!'
          ),
          React.createElement(
            Box,
            { marginTop: 1, flexDirection: 'column' },
            React.createElement(
              Text,
              null,
              '• OpenSearch SIEM: ',
              React.createElement(Text, { color: 'cyan', bold: true, underline: true }, `https://siem.${domain}`)
            ),
            React.createElement(
              Text,
              { color: 'gray', marginLeft: 2 },
              'Local TLS secured by mkcert (trusted in system keychain)'
            ),
            React.createElement(
              Text,
              { color: 'yellow', marginLeft: 2 },
              '🔑 Login Credentials: admin / Admin123456! (or admin / admin)'
            ),
            React.createElement(
              Box,
              { marginTop: 1, flexDirection: 'column' },
              React.createElement(
                Text,
                { color: 'yellow', bold: true },
                '⚡ Next Steps:'
              ),
              React.createElement(
                Text,
                { color: 'gray' },
                `  1. Local DNS mapped:        127.0.0.1 siem.${domain} (hostr)`
              ),
              React.createElement(
                Text,
                { color: 'gray' },
                '  2. Simulate network threats: vigilante threat-sim'
              ),
              React.createElement(
                Text,
                { color: 'gray' },
                '  3. Check status anytime:     vigilante status'
              )
            )
          )
        )
      : null,

    // Fatal Error Display
    fatalError
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginTop: 1, padding: 1, borderStyle: 'round', borderColor: 'red' },
          React.createElement(Text, { bold: true, color: 'red' }, '✖ Execution Failed:'),
          React.createElement(Text, { color: 'white' }, fatalError)
        )
      : null,

    // Toast Notification Banner
    React.createElement(ToastBanner, { toast: copiedToast }),

    // Persistent Action Menu Bar (available at all times in interactive mode)
    !nonInteractive
      ? React.createElement(MenuBar, {
          isRunning: viewState === 'RUNNING' && !isDone,
          activeView: viewState
        })
      : null
  );
};

export const App = (props) => {
  return React.createElement(
    ClipboardProvider,
    { isInteractive: !props.nonInteractive },
    React.createElement(AppContent, props)
  );
};
