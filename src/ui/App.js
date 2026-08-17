import React, { useState, useEffect } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import { Header } from './Header.js';
import { TaskRunner } from './TaskRunner.js';
import { SelectModules } from './SelectModules.js';
import { StatusDashboard } from './StatusDashboard.js';
import { ThreatSimView } from './ThreatSimView.js';
import { ValuesView } from './ValuesView.js';
import { ModulesView } from './ModulesView.js';
import { PodsView } from './PodsView.js';
import { DataCollectionView } from './DataCollectionView.js';
import { NmapVisualizerView } from './NmapVisualizerView.js';
import { InstancesView } from './InstancesView.js';
import { MenuBar } from './MenuBar.js';
import { ClipboardProvider, ToastBanner, useClipboard } from './ClipboardManager.js';
import { ThemeProvider } from './theme.js';
import { logger } from '../utils/logger.js';

import { checkPrereqs } from '../engine/prereqs.js';
import { setupCertificates, checkCertificates } from '../engine/certs.js';
import { createK3dCluster, deleteK3dCluster, getClusterInfo } from '../engine/cluster.js';
import { checkHosts, syncHosts, removeHosts } from '../engine/hosts.js';
import { exportStarterValues, listChartValues } from '../engine/helm.js';
import { ensureVigilanteConfig, getVigilanteConfigFile, getVigilanteValuesDir, loadConfig } from '../engine/config.js';
import { saveInstanceMetadata, deleteInstance, recordNamespaceDeployment } from '../engine/instances.js';
import { globalModuleRegistry } from '../modules/registry.js';

const AppContent = ({
  command = 'up',
  subCommand = null,
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  namespace: cliNamespace = null,
  selectedModules: cliSelectedModules,
  customValuesPath = null,
  customValuesDir: cliCustomValuesDir = null,
  hostsAction = 'sync',
  ip = '127.0.0.1',
  nonInteractive = false,
  skipPrereqs = false
}) => {
  const { exit } = useApp();
  const { copiedToast } = useClipboard();
  const [targetNamespace, setTargetNamespace] = useState(cliNamespace || 'default');
  const [viewState, setViewState] = useState(
    command === 'up' && !cliSelectedModules && !nonInteractive ? 'SELECT_MODULES' : 'RUNNING'
  );
  const [chosenModules, setChosenModules] = useState(
    cliSelectedModules || ['vigil-soc']
  );
  const [tasks, setTasks] = useState([]);
  const [logs, setLogs] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);
  const [customValuesDir, setCustomValuesDir] = useState(cliCustomValuesDir);
  const [selectedXmlPath, setSelectedXmlPath] = useState(null);
  const [fatalError, setFatalError] = useState(null);
  const [isDone, setIsDone] = useState(false);

  // Log application startup
  useEffect(() => {
    logger.info('APP:START', `Mounted App with command=${command}, subCommand=${subCommand}, domain=${domain}, clusterName=${clusterName}, namespace=${targetNamespace}, nonInteractive=${nonInteractive}`);
  }, []);

  // Keyboard navigation & interactive menu shortcuts
  useInput((input, key) => {
    if (viewState === 'SELECT_MODULES' || viewState === 'VALUES' || viewState === 'MODULES' || viewState === 'PODS' || viewState === 'NMAP' || viewState === 'XML_VISUALIZER') return;

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
      logger.info('UI:ACTION', 'User pressed [v] -> Switching to VALUES view');
      setFatalError(null);
      setViewState('VALUES');
      return;
    }

    // Trigger Modules List Workflow
    if (keyChar === 'm') {
      logger.info('UI:ACTION', 'User pressed [m] -> Switching to MODULES view');
      setFatalError(null);
      setViewState('MODULES');
      return;
    }

    // Trigger Live Pods Monitor
    if (keyChar === 'p') {
      logger.info('UI:ACTION', 'User pressed [p] -> Switching to PODS view');
      setFatalError(null);
      setViewState('PODS');
      return;
    }

    // Trigger Nmap Data Collection
    if (keyChar === 'n') {
      logger.info('UI:ACTION', 'User pressed [n] -> Switching to NMAP view');
      setFatalError(null);
      setViewState('NMAP');
      return;
    }

    // Trigger Nmap XML Topology Visualizer
    if (keyChar === 'x') {
      logger.info('UI:ACTION', 'User pressed [x] -> Switching to XML_VISUALIZER view');
      setFatalError(null);
      setViewState('XML_VISUALIZER');
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
      addLog(`Setting up local CA and generating TLS certificates for *.${domain} in instance directory...`);
      const certs = await setupCertificates(domain, { clusterName, instanceName: clusterName });
      addLog(`Certificates generated:\n  Cert: ${certs.certPath}\n  Key:  ${certs.keyPath}`);
      updateTask('certs', { status: 'done' });

      // Step 3: Local Hosts (hostr)
      const cfg = loadConfig();
      const hostrSyncEnabled = cfg.hostr?.enabled !== false && cfg.hostr?.autoSyncOnUp !== false;

      updateTask('hosts', { status: 'running' });
      if (hostrSyncEnabled) {
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
      } else {
        updateTask('hosts', { status: 'done', detail: 'Skipped (disabled in config.yaml)' });
        addLog(`[hostr] Automatic /etc/hosts sync is disabled in config.yaml. Press [h] to sync manually anytime.`);
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
        addLog(`Installing module ${mod.name} into namespace '${targetNamespace}'...`);
        await mod.install({
          domain,
          certPath: certs.certPath,
          keyPath: certs.keyPath,
          clusterName,
          namespace: targetNamespace,
          onLog: (msg) => addLog(msg),
          options: {
            customValuesPath,
            customValuesDir
          }
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
          return await m.status({ domain, clusterName, namespace: targetNamespace });
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

      // Save instance & namespace deployment metadata
      await recordNamespaceDeployment(clusterName, targetNamespace, modulesToInstall, {
        domain,
        ip
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

      const cfg = loadConfig();
      const hostrCleanEnabled = cfg.hostr?.enabled !== false && cfg.hostr?.autoCleanOnDown !== false;

      updateTask('hosts', { status: 'running' });
      if (hostrCleanEnabled) {
        addLog(`Cleaning up /etc/hosts managed domain mappings...`);
        try {
          await removeHosts({ onLog: (msg) => addLog(msg) });
          updateTask('hosts', { status: 'done' });
        } catch {
          updateTask('hosts', { status: 'done', detail: 'Skipped' });
        }
      } else {
        updateTask('hosts', { status: 'done', detail: 'Skipped (disabled in config.yaml)' });
        addLog(`[hostr] Automatic /etc/hosts cleanup is disabled in config.yaml.`);
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
      const certs = await checkCertificates(domain, { clusterName, instanceName: clusterName });
      const hosts = await checkHosts({ domain, ip });

      const allModules = globalModuleRegistry.getAll();
      const modulesStatus = await Promise.all(
        allModules.map(async (mod) => {
          return await mod.status({ domain, clusterName, namespace: targetNamespace });
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
  // Command: APPLY MODULES (Incremental Install / Uninstall)
  // -------------------------------------------------------------
  const runApplyModulesWorkflow = async ({ enabledIds, toInstall = [], toUninstall = [] }) => {
    logger.info('WORKFLOW:APPLY_MODULES', `Applying module changes in namespace '${targetNamespace}': toInstall=[${toInstall.join(', ')}], toUninstall=[${toUninstall.join(', ')}]`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);

    const taskList = [];
    for (const id of toUninstall) {
      const mod = globalModuleRegistry.get(id);
      taskList.push({
        id: `uninst-${id}`,
        label: `Uninstall package: ${mod ? mod.name : id}`,
        status: 'pending'
      });
    }
    for (const id of toInstall) {
      const mod = globalModuleRegistry.get(id);
      taskList.push({
        id: `inst-${id}`,
        label: `Deploy package: ${mod ? mod.name : id}`,
        status: 'pending'
      });
    }

    setTasks(taskList);

    try {
      // 1. Uninstall disabled modules
      for (const id of toUninstall) {
        const mod = globalModuleRegistry.get(id);
        if (mod) {
          updateTask(`uninst-${id}`, { status: 'running' });
          addLog(`Uninstalling module '${mod.name}'...`);
          await mod.uninstall({
            clusterName,
            namespace: targetNamespace,
            onLog: (msg) => addLog(msg)
          });
          updateTask(`uninst-${id}`, { status: 'done' });
        }
      }

      // 2. Setup certs if needed for new installs
      let certs = null;
      if (toInstall.length > 0) {
        certs = await setupCertificates(domain, { clusterName, instanceName: clusterName });
      }

      // 3. Install newly enabled modules in dependency order
      const resolved = globalModuleRegistry.resolveModules(toInstall);
      for (const mod of resolved) {
        if (toInstall.includes(mod.id)) {
          const taskId = `inst-${mod.id}`;
          updateTask(taskId, { status: 'running' });
          addLog(`Deploying security module '${mod.name}' into namespace '${targetNamespace}'...`);
          await mod.install({
            domain,
            certPath: certs?.certPath,
            keyPath: certs?.keyPath,
            clusterName,
            namespace: targetNamespace,
            onLog: (msg) => addLog(msg),
            options: {
              customValuesPath,
              customValuesDir
            }
          });
          updateTask(taskId, { status: 'done' });
        }
      }

      setChosenModules(enabledIds);

      // Refresh status dashboard data
      addLog('Refreshing environment status...');
      const allModules = globalModuleRegistry.getAll();
      const modulesStatus = await Promise.all(
        allModules.map(async (m) => {
          const st = await m.status({ domain, clusterName, namespace: targetNamespace });
          const endpoints = await m.getEndpoints({ domain, namespace: targetNamespace });
          return { ...st, endpoints };
        })
      );

      const clusterInfo = await getClusterInfo(clusterName);
      const hostsInfo = await checkHosts({ domain, ip });
      const certsInfo = await checkCertificates(domain, { clusterName, instanceName: clusterName });
      const prereqs = await checkPrereqs();

      setDashboardData({
        cluster: clusterInfo,
        hosts: hostsInfo,
        certs: certsInfo,
        prereqs,
        modules: modulesStatus,
        domain
      });

      // Save namespace deployment state
      await recordNamespaceDeployment(clusterName, targetNamespace, enabledIds, {
        domain,
        ip
      });

      setIsDone(true);
      setViewState('DASHBOARD');
    } catch (err) {
      logger.error('WORKFLOW:APPLY_MODULES:ERROR', err.message, err);
      setFatalError(err.message);
      setIsDone(true);
    }
  };

  // -------------------------------------------------------------
  // Command: MODULES (Non-interactive status report)
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
          const st = await mod.status({ domain, clusterName, namespace: targetNamespace });
          const endpoints = await mod.getEndpoints({ domain, namespace: targetNamespace });
          return { ...st, endpoints };
        })
      );

      setDashboardData({
        modules: modulesStatus,
        domain
      });

      updateTask('modules', { status: 'done' });
      setViewState('MODULES');
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
    logger.info('WORKFLOW:VALUES', `Starting VALUES/CONFIG workflow (command=${command}, subCommand=${subCommand})`);
    setViewState('RUNNING');
    setLogs([]);
    setFatalError(null);
    setIsDone(false);
    setTasks([
      {
        id: 'values',
        label: command === 'config'
          ? 'Manage global XDG configuration & themes'
          : 'Manage customizable Helm chart values.yaml configurations',
        status: 'running'
      }
    ]);

    try {
      await ensureVigilanteConfig();
      const configFile = getVigilanteConfigFile();
      const xdgValuesDir = getVigilanteValuesDir();

      if (command === 'config') {
        if (subCommand === 'path') {
          addLog(configFile);
        } else if (subCommand === 'init') {
          addLog(`✔ Initialized config file: ${configFile}`);
          addLog(`✔ Initialized XDG values directory: ${xdgValuesDir}`);
        } else {
          const cfg = loadConfig();
          addLog(`Vigilante XDG Configuration & Theming:`);
          addLog(`• Config file:        ${configFile}`);
          addLog(`• XDG Values dir:     ${xdgValuesDir}`);
          addLog(`• Active Theme:       ${cfg.theme?.name || 'default'}`);
          addLog(`• Default Domain:     ${cfg.defaults?.domain || 'vigilante.local'}`);
          addLog(`• Default Cluster:    ${cfg.defaults?.clusterName || 'vigilante-dev'}`);
          addLog('');
          addLog(`To edit your config in $EDITOR, launch interactive mode or run:`);
          addLog(`  $EDITOR ${configFile}`);
        }
      } else if (subCommand === 'export' || subCommand === 'dump' || subCommand === 'init') {
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
          addLog(`    XDG User path:    ${item.xdgPath || 'N/A'}`);
          if (item.userOverridePath) {
            addLog(`    ✔ Active user override: ${item.userOverridePath}`);
          } else {
            addLog(`    ○ No user override detected.`);
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
      if (nonInteractive) {
        runModulesWorkflow();
      } else {
        setViewState('MODULES');
      }
    } else if (command === 'pods') {
      setViewState('PODS');
    } else if (command === 'nmap' || command === 'scan' || command === 'collect') {
      setViewState('NMAP');
    } else if (command === 'xml' || command === 'visualizer' || command === 'netmap') {
      setViewState('XML_VISUALIZER');
    } else if (command === 'threat-sim') {
      setViewState('THREAT_SIM');
    } else if (command === 'instances' || command === 'instance') {
      setViewState('INSTANCES');
    } else if (command === 'hosts' || command === 'hostr') {
      runHostsWorkflow();
    } else if (command === 'values' || command === 'config') {
      if (subCommand === 'export' || subCommand === 'dump' || nonInteractive) {
        runValuesWorkflow();
      } else {
        setViewState('VALUES');
      }
    } else {
      setFatalError(`Unknown command: ${command}`);
      setIsDone(true);
    }
  }, []);

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1 },
    React.createElement(Header, { command, domain, namespace: targetNamespace }),

    // State 1: Select Modules Screen
    viewState === 'SELECT_MODULES'
      ? React.createElement(SelectModules, {
          modules: globalModuleRegistry.getAll(),
          initialSelected: chosenModules,
          namespace: targetNamespace,
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

    // State 5: Interactive Modules Manager View
    viewState === 'MODULES'
      ? React.createElement(ModulesView, {
          domain,
          clusterName,
          namespace: targetNamespace,
          initialSelected: chosenModules,
          onApply: ({ enabledIds, toInstall, toUninstall, hasPendingChanges }) => {
            if (hasPendingChanges) {
              runApplyModulesWorkflow({ enabledIds, toInstall, toUninstall });
            } else {
              runUpWorkflow(enabledIds);
            }
          },
          onNavigate: (target, customPayload) => {
            if (target === 'up') {
              runUpWorkflow(customPayload || chosenModules);
            } else if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'values') {
              setViewState('VALUES');
            } else if (target === 'down') {
              runDownWorkflow();
            } else if (target === 'threat-sim') {
              setViewState('THREAT_SIM');
            } else if (target === 'hostr') {
              runHostsWorkflow();
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 6: Live Kubernetes Pods Monitor
    viewState === 'PODS'
      ? React.createElement(PodsView, {
          domain,
          clusterName,
          namespace: targetNamespace,
          onNavigate: (target) => {
            if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'up') {
              runUpWorkflow(chosenModules);
            } else if (target === 'down') {
              runDownWorkflow();
            } else if (target === 'modules') {
              setViewState('MODULES');
            } else if (target === 'values') {
              setViewState('VALUES');
            } else if (target === 'threat-sim') {
              setViewState('THREAT_SIM');
            } else if (target === 'hostr') {
              runHostsWorkflow();
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 7: Values & Chart Configuration Manager
    viewState === 'VALUES'
      ? React.createElement(ValuesView, {
          domain,
          customValuesDir,
          onNavigate: (target) => {
            if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'up') {
              runUpWorkflow(chosenModules);
            } else if (target === 'down') {
              runDownWorkflow();
            } else if (target === 'threat-sim') {
              setViewState('THREAT_SIM');
            } else if (target === 'hostr') {
              runHostsWorkflow();
            } else if (target === 'modules') {
              runModulesWorkflow();
            } else if (target === 'nmap') {
              setViewState('NMAP');
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 8: Nmap Data Collection & Reconnaissance View
    viewState === 'NMAP'
      ? React.createElement(DataCollectionView, {
          domain,
          ip,
          onNavigate: (target, optArg) => {
            if (target === 'xml-visualizer') {
              setSelectedXmlPath(optArg);
              setViewState('XML_VISUALIZER');
            } else if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'up') {
              runUpWorkflow(chosenModules);
            } else if (target === 'down') {
              runDownWorkflow();
            } else if (target === 'modules') {
              setViewState('MODULES');
            } else if (target === 'values') {
              setViewState('VALUES');
            } else if (target === 'pods') {
              setViewState('PODS');
            } else if (target === 'threat-sim') {
              setViewState('THREAT_SIM');
            } else if (target === 'hostr') {
              runHostsWorkflow();
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 9: Nmap XML Network Topology Visualizer View
    viewState === 'XML_VISUALIZER'
      ? React.createElement(NmapVisualizerView, {
          initialXmlPath: selectedXmlPath,
          onNavigate: (target) => {
            if (target === 'nmap') {
              setViewState('NMAP');
            } else if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'up') {
              runUpWorkflow(chosenModules);
            } else if (target === 'down') {
              runDownWorkflow();
            } else if (target === 'modules') {
              setViewState('MODULES');
            } else if (target === 'values') {
              setViewState('VALUES');
            } else if (target === 'pods') {
              setViewState('PODS');
            } else if (target === 'threat-sim') {
              setViewState('THREAT_SIM');
            } else if (target === 'hostr') {
              runHostsWorkflow();
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 10: Instances Manager View
    viewState === 'INSTANCES'
      ? React.createElement(InstancesView, {
          onNavigate: (target, customCluster) => {
            if (target === 'up') {
              runUpWorkflow(chosenModules);
            } else if (target === 'status') {
              runStatusWorkflow();
            } else if (target === 'pods') {
              setViewState('PODS');
            } else if (target === 'dashboard') {
              if (dashboardData) {
                setViewState('DASHBOARD');
              } else {
                runStatusWorkflow();
              }
            } else {
              exit();
            }
          }
        })
      : null,

    // State 7: Success View
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

    // Globally Context-Sensitive Action Menu & Workflow Breadcrumb Bar
    !nonInteractive
      ? React.createElement(MenuBar, {
          activeView: viewState,
          contextData: {
            isRunning: viewState === 'RUNNING' && !isDone,
            isDone
          }
        })
      : null
  );
};

export const App = (props) => {
  return React.createElement(
    ThemeProvider,
    { customConfig: props.theme ? { theme: { name: props.theme } } : null },
    React.createElement(
      ClipboardProvider,
      { isInteractive: !props.nonInteractive },
      React.createElement(AppContent, props)
    )
  );
};
