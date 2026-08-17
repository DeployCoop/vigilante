import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import { globalModuleRegistry } from '../modules/registry.js';
import { useClipboard } from './ClipboardManager.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const ModulesView = ({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  namespace = 'default',
  initialSelected = null,
  onNamespaceChange = null,
  onApply = null,
  onNavigate = null
}) => {
  const theme = useTheme();
  const [currentTargetNamespace, setCurrentTargetNamespace] = useState(namespace || 'default');
  const [isEditingNamespace, setIsEditingNamespace] = useState(false);
  const [namespaceInput, setNamespaceInput] = useState(namespace || 'default');

  const [modules, setModules] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState(new Set());
  const [installedMap, setInstalledMap] = useState(new Map());
  const [feedback, setFeedback] = useState(null);
  const [loading, setLoading] = useState(true);
  const { registerPanes } = useClipboard();

  // Load modules & query their live cluster status for target namespace
  const loadModules = useCallback(async (targetNs = currentTargetNamespace) => {
    try {
      setLoading(true);
      const allMods = globalModuleRegistry.getAll();
      const statusList = await Promise.all(
        allMods.map(async (mod) => {
          const st = await mod.status({ domain, clusterName, namespace: targetNs });
          const endpoints = await mod.getEndpoints({ domain, namespace: targetNs });
          return {
            id: mod.id,
            name: mod.name,
            description: mod.description,
            category: mod.category,
            dependencies: mod.dependencies || [],
            defaultEnabled: mod.defaultEnabled ?? true,
            installed: st.installed,
            status: st.status,
            pods: st.pods || [],
            endpoints: endpoints || []
          };
        })
      );

      setModules(statusList);

      const installed = new Map();
      statusList.forEach(m => installed.set(m.id, m.installed));
      setInstalledMap(installed);

      // Determine initial enabled set
      if (initialSelected && initialSelected.length > 0) {
        setSelected(new Set(initialSelected));
      } else {
        // If cluster has installed modules in this namespace, default to those
        const installedIds = statusList.filter(m => m.installed).map(m => m.id);
        if (installedIds.length > 0) {
          setSelected(new Set(installedIds));
        } else {
          setSelected(new Set(statusList.filter(m => m.defaultEnabled).map(m => m.id)));
        }
      }
      setLoading(false);
    } catch (err) {
      logger.error('MODULES:LOAD', `Failed to load modules: ${err.message}`, err);
      setLoading(false);
    }
  }, [domain, clusterName, initialSelected, currentTargetNamespace]);

  useEffect(() => {
    loadModules(currentTargetNamespace);
  }, [loadModules, currentTargetNamespace]);

  // Sync if parent updates namespace prop
  useEffect(() => {
    if (namespace && namespace !== currentTargetNamespace && !isEditingNamespace) {
      setCurrentTargetNamespace(namespace);
      setNamespaceInput(namespace);
    }
  }, [namespace]);

  // Register clipboard pane for copying modules summary
  useEffect(() => {
    registerPanes([
      {
        id: 'modules-summary',
        title: `Security Modules Summary (${currentTargetNamespace})`,
        startRow: 6,
        endRow: 35,
        getText: () => {
          return modules
            .map((m) => {
              const isEnabled = selected.has(m.id);
              const ep = m.endpoints.map(e => `    • ${e.name}: ${e.url}`).join('\n');
              return `• ${m.name} (${m.id}) [${isEnabled ? 'ENABLED' : 'DISABLED'}] [ns: ${currentTargetNamespace}] - Status: ${m.status}\n${ep || '    No endpoints'}`;
            })
            .join('\n\n');
        }
      }
    ]);
  }, [modules, selected, currentTargetNamespace, registerPanes]);

  // Toggle enable/disable for a module with dependency management
  const toggleModule = (targetMod) => {
    if (!targetMod) return;

    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(targetMod.id)) {
        // Disabling module
        next.delete(targetMod.id);
        logger.info('MODULES:TOGGLE', `Disabled module ${targetMod.id}`);

        // If other modules depend on this one, auto-disable them as well
        const dependents = modules.filter(m => m.dependencies?.includes(targetMod.id) && next.has(m.id));
        for (const dep of dependents) {
          next.delete(dep.id);
          logger.info('MODULES:TOGGLE', `Auto-disabled dependent module ${dep.id}`);
        }

        if (dependents.length > 0) {
          setFeedback({
            type: 'info',
            text: `○ Disabled '${targetMod.name}' and dependent package(s): ${dependents.map(d => d.name).join(', ')}`
          });
        } else {
          setFeedback({
            type: 'info',
            text: `○ Disabled '${targetMod.name}'. Press [Enter] to apply changes in '${currentTargetNamespace}'.`
          });
        }
      } else {
        // Enabling module
        next.add(targetMod.id);
        logger.info('MODULES:TOGGLE', `Enabled module ${targetMod.id}`);

        // If this module has dependencies, auto-enable them as well
        const missingDeps = (targetMod.dependencies || []).filter(depId => !next.has(depId));
        for (const depId of missingDeps) {
          next.add(depId);
          logger.info('MODULES:TOGGLE', `Auto-enabled dependency ${depId}`);
        }

        if (missingDeps.length > 0) {
          const depNames = modules.filter(m => missingDeps.includes(m.id)).map(m => m.name);
          setFeedback({
            type: 'success',
            text: `✔ Enabled '${targetMod.name}' + required dependenc${depNames.length > 1 ? 'ies' : 'y'}: ${depNames.join(', ')}`
          });
        } else {
          setFeedback({
            type: 'success',
            text: `✔ Enabled '${targetMod.name}'. Press [Enter] to apply changes in '${currentTargetNamespace}'.`
          });
        }
      }
      return next;
    });
  };

  // Calculate pending changes for current target namespace
  const toInstall = modules.filter(m => selected.has(m.id) && !m.installed).map(m => m.id);
  const toUninstall = modules.filter(m => !selected.has(m.id) && m.installed).map(m => m.id);
  const hasPendingChanges = toInstall.length > 0 || toUninstall.length > 0;

  const handleApply = () => {
    if (onApply) {
      logger.info('MODULES:APPLY', `Applying changes to namespace '${currentTargetNamespace}': toInstall=[${toInstall.join(', ')}], toUninstall=[${toUninstall.join(', ')}]`);
      onApply({
        enabledIds: Array.from(selected),
        toInstall,
        toUninstall,
        hasPendingChanges,
        namespace: currentTargetNamespace
      });
    }
  };

  // Keyboard navigation & interactive namespace editing
  useInput((input, key) => {
    // Mode A: Editing Target Namespace
    if (isEditingNamespace) {
      if (key.return) {
        // Confirm new namespace
        const cleanNs = namespaceInput.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-') || 'default';
        setCurrentTargetNamespace(cleanNs);
        setIsEditingNamespace(false);
        setFeedback({
          type: 'success',
          text: `✔ Target namespace switched to '${cleanNs}'. Live status refreshed.`
        });
        if (onNamespaceChange) {
          onNamespaceChange(cleanNs);
        }
        loadModules(cleanNs);
        return;
      }

      if (key.escape) {
        // Cancel namespace editing
        setNamespaceInput(currentTargetNamespace);
        setIsEditingNamespace(false);
        return;
      }

      if (key.backspace || key.delete) {
        setNamespaceInput(prev => prev.slice(0, -1));
        return;
      }

      // Append alphanumeric and hyphen characters
      if (input && input.length === 1 && /[a-zA-Z0-9_-]/.test(input)) {
        setNamespaceInput(prev => prev + input);
        return;
      }

      return;
    }

    // Mode B: Normal Modules View Navigation
    if (key.tab) {
      if (onNavigate) {
        onNavigate('menu');
      }
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // [n] or [N] -> Trigger Namespace Switcher Prompt
    if (keyChar === 'n') {
      setIsEditingNamespace(true);
      setNamespaceInput(currentTargetNamespace);
      setFeedback(null);
      return;
    }

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : modules.length - 1));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < modules.length - 1 ? c + 1 : 0));
      return;
    }

    // [Space] -> Toggle module enabled/disabled
    if (input === ' ') {
      const currentMod = modules[cursor];
      if (currentMod) {
        toggleModule(currentMod);
      }
      return;
    }

    // [Enter] or [a] -> Apply changes
    if (key.return || keyChar === 'a') {
      handleApply();
      return;
    }

    // Navigation delegates
    if (keyChar === 'u' && onNavigate) {
      onNavigate('up', Array.from(selected));
      return;
    }
    if (keyChar === 's' && onNavigate) {
      onNavigate('status');
      return;
    }
    if (keyChar === 'v' && onNavigate) {
      onNavigate('values');
      return;
    }
    if (keyChar === 'd' && onNavigate) {
      onNavigate('down');
      return;
    }
    if (keyChar === 't' && onNavigate) {
      onNavigate('threat-sim');
      return;
    }
    if (keyChar === 'h' && onNavigate) {
      onNavigate('hostr');
      return;
    }

    // [q] or [Esc] -> Return to dashboard
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border || 'cyan' },

    // Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(
          Text,
          { bold: true, color: theme.header || theme.primary },
          '📦 SECURITY MODULES & PACKAGE MANAGER '
        ),
        React.createElement(
          Text,
          { color: theme.warning || 'yellow', bold: true },
          `[Target NS: ${currentTargetNamespace}]`
        )
      ),
      React.createElement(
        Text,
        { color: theme.accent || 'cyan' },
        `${selected.size} of ${modules.length} Enabled`
      )
    ),

    // Namespace Editor Prompt (when user hits 'N')
    isEditingNamespace
      ? React.createElement(
          Box,
          {
            marginY: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.warning || 'yellow',
            flexDirection: 'column'
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              { color: theme.warning || 'yellow', bold: true },
              '🏷️  Set Target Kubernetes Namespace: '
            ),
            React.createElement(
              Text,
              { color: theme.accent || 'cyan', bold: true, underline: true },
              namespaceInput
            ),
            React.createElement(
              Text,
              { color: theme.primary || 'green' },
              ' █'
            )
          ),
          React.createElement(
            Text,
            { color: theme.muted || 'gray', marginTop: 1 },
            'Type the target namespace name and press [Enter] to confirm, or [Esc] to cancel.'
          )
        )
      : React.createElement(
          Box,
          { justifyContent: 'space-between', marginBottom: 1 },
          React.createElement(
            Text,
            { color: theme.muted || 'gray' },
            'Use ↑/↓ to navigate, [Space] to toggle, [n] to change target namespace, [Enter] to apply.'
          ),
          React.createElement(
            Text,
            { color: theme.warning || 'yellow' },
            'Press [n] to switch namespace'
          )
        ),

    // Feedback message
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.accent || 'cyan')
          },
          React.createElement(
            Text,
            { color: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.accent || 'cyan'), bold: true },
            feedback.text
          )
        )
      : null,

    loading
      ? React.createElement(
          Box,
          { marginY: 1 },
          React.createElement(Spinner, { type: 'dots' }),
          React.createElement(Text, { color: theme.accent || 'cyan', marginLeft: 1 }, `Querying module health in namespace '${currentTargetNamespace}'...`)
        )
      : null,

    // Modules list
    modules.map((mod, index) => {
      const isFocused = index === cursor;
      const isChecked = selected.has(mod.id);
      const isInstalled = mod.installed;

      let changeBadge = null;
      if (isChecked && !isInstalled) {
        changeBadge = React.createElement(Text, { color: theme.accent || 'cyan', bold: true }, ` [+ Will Install into ${currentTargetNamespace}]`);
      } else if (!isChecked && isInstalled) {
        changeBadge = React.createElement(Text, { color: theme.error || 'red', bold: true }, ` [- Will Uninstall from ${currentTargetNamespace}]`);
      }

      return React.createElement(
        Box,
        {
          key: mod.id,
          flexDirection: 'column',
          marginY: 0,
          paddingY: 0
        },
        React.createElement(
          Box,
          null,
          React.createElement(
            Text,
            { color: isFocused ? (theme.accent || 'cyan') : (theme.muted || 'gray'), bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: isChecked ? (theme.success || 'green') : (theme.muted || 'gray'), bold: isChecked },
            isChecked ? '[✔ ENABLED]  ' : '[  DISABLED] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? (theme.accent || 'yellow') : isChecked ? (theme.text || 'white') : (theme.muted || 'gray') },
            mod.name
          ),
          React.createElement(
            Text,
            { color: theme.secondary || 'magenta', marginLeft: 1 },
            `(${mod.category})`
          ),
          React.createElement(
            Text,
            { color: isInstalled ? (theme.success || 'green') : (theme.muted || 'gray'), marginLeft: 2 },
            `[${mod.status}]`
          ),
          changeBadge
        ),
        React.createElement(
          Box,
          { marginLeft: 4 },
          React.createElement(
            Text,
            { color: isFocused ? (theme.text || 'white') : (theme.muted || 'gray') },
            mod.description
          )
        ),
        mod.dependencies && mod.dependencies.length > 0
          ? React.createElement(
              Box,
              { marginLeft: 4 },
              React.createElement(
                Text,
                { color: theme.warning || 'yellow', dimColor: true },
                `↳ Requires: ${mod.dependencies.join(', ')}`
              )
            )
          : null,
        mod.endpoints && mod.endpoints.length > 0
          ? React.createElement(
              Box,
              { marginLeft: 4, marginBottom: 1 },
              React.createElement(
                Text,
                { color: theme.muted || 'gray' },
                `Endpoints: ${mod.endpoints.map(e => e.url).join(' | ')}`
              )
            )
          : React.createElement(Box, { marginBottom: 1 })
      );
    }),

    // Pending changes action banner
    hasPendingChanges
      ? React.createElement(
          Box,
          {
            marginTop: 1,
            padding: 1,
            borderStyle: 'single',
            borderColor: theme.warning || 'yellow',
            flexDirection: 'column'
          },
          React.createElement(
            Text,
            { bold: true, color: theme.warning || 'yellow' },
            `⚡ Pending Changes to Apply in namespace '${currentTargetNamespace}':`
          ),
          toInstall.length > 0
            ? React.createElement(
                Text,
                { color: theme.success || 'green' },
                `  • Install: ${toInstall.map(id => modules.find(m => m.id === id)?.name || id).join(', ')}`
              )
            : null,
          toUninstall.length > 0
            ? React.createElement(
                Text,
                { color: theme.error || 'red' },
                `  • Uninstall: ${toUninstall.map(id => modules.find(m => m.id === id)?.name || id).join(', ')}`
              )
            : null,
          React.createElement(
            Text,
            { bold: true, color: theme.success || 'green', marginTop: 1 },
            `Press [Enter] or [a] to Apply Changes into '${currentTargetNamespace}' now`
          )
        )
      : null,

    // Footer actions
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: theme.border || 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.accent || 'cyan', bold: true }, '[Space] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Toggle  '),
        React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, '[n] '),
        React.createElement(Text, { color: theme.text || 'white' }, `Namespace (${currentTargetNamespace})  `),
        React.createElement(Text, { color: theme.success || 'green', bold: true }, '[Enter] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Apply  '),
        React.createElement(Text, { color: theme.muted || 'gray' }, '| [u] Deploy All  [v] Values  [s] Status  [q] Return')
      ),
      React.createElement(
        Text,
        { color: theme.muted || 'gray', dimColor: true },
        'Use ↑/↓ or j/k to navigate'
      )
    )
  );
};
