import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import { globalModuleRegistry } from '../modules/registry.js';
import { useClipboard } from './ClipboardManager.js';
import { logger } from '../utils/logger.js';

export const ModulesView = ({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  initialSelected = null,
  onApply = null,
  onNavigate = null
}) => {
  const [modules, setModules] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState(new Set());
  const [installedMap, setInstalledMap] = useState(new Map());
  const [feedback, setFeedback] = useState(null);
  const [loading, setLoading] = useState(true);
  const { registerPanes } = useClipboard();

  // Load modules & query their live cluster status
  const loadModules = useCallback(async () => {
    try {
      setLoading(true);
      const allMods = globalModuleRegistry.getAll();
      const statusList = await Promise.all(
        allMods.map(async (mod) => {
          const st = await mod.status({ domain, clusterName });
          const endpoints = await mod.getEndpoints({ domain });
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
        // If cluster has installed modules, default to those; otherwise default to defaultEnabled
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
  }, [domain, clusterName, initialSelected]);

  useEffect(() => {
    loadModules();
  }, [loadModules]);

  // Register clipboard pane for copying modules summary
  useEffect(() => {
    registerPanes([
      {
        id: 'modules-summary',
        title: 'Security Modules Summary',
        startRow: 6,
        endRow: 35,
        getText: () => {
          return modules
            .map((m) => {
              const isEnabled = selected.has(m.id);
              const isInst = m.installed;
              const ep = m.endpoints.map(e => `    • ${e.name}: ${e.url}`).join('\n');
              return `• ${m.name} (${m.id}) [${isEnabled ? 'ENABLED' : 'DISABLED'}] - Cluster: ${m.status}\n${ep || '    No endpoints'}`;
            })
            .join('\n\n');
        }
      }
    ]);
  }, [modules, selected, registerPanes]);

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
            text: `○ Disabled '${targetMod.name}'. Press [Enter] to apply changes.`
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
            text: `✔ Enabled '${targetMod.name}'. Press [Enter] to apply changes.`
          });
        }
      }
      return next;
    });
  };

  // Calculate pending changes
  const toInstall = modules.filter(m => selected.has(m.id) && !m.installed).map(m => m.id);
  const toUninstall = modules.filter(m => !selected.has(m.id) && m.installed).map(m => m.id);
  const hasPendingChanges = toInstall.length > 0 || toUninstall.length > 0;

  const handleApply = () => {
    if (onApply) {
      logger.info('MODULES:APPLY', `Applying changes: toInstall=[${toInstall.join(', ')}], toUninstall=[${toUninstall.join(', ')}]`);
      onApply({
        enabledIds: Array.from(selected),
        toInstall,
        toUninstall,
        hasPendingChanges
      });
    }
  };

  // Keyboard navigation
  useInput((input, key) => {
    const keyChar = (input || '').toLowerCase();

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
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: 'cyan' },
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Text,
        { bold: true, color: 'cyan' },
        '📦 SECURITY MODULES & PACKAGE MANAGER'
      ),
      React.createElement(
        Text,
        { color: 'yellow' },
        `${selected.size} of ${modules.length} Enabled`
      )
    ),
    React.createElement(
      Text,
      { color: 'gray', marginBottom: 1 },
      'Use ↑/↓ to navigate, [Space] to enable/disable modules, and [Enter] to apply changes.'
    ),

    // Feedback message
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? 'green' : feedback.type === 'error' ? 'red' : 'cyan'
          },
          React.createElement(
            Text,
            { color: feedback.type === 'success' ? 'green' : feedback.type === 'error' ? 'red' : 'cyan', bold: true },
            feedback.text
          )
        )
      : null,

    // Modules list
    modules.map((mod, index) => {
      const isFocused = index === cursor;
      const isChecked = selected.has(mod.id);
      const isInstalled = mod.installed;

      let changeBadge = null;
      if (isChecked && !isInstalled) {
        changeBadge = React.createElement(Text, { color: 'cyan', bold: true }, ' [+ Will Install]');
      } else if (!isChecked && isInstalled) {
        changeBadge = React.createElement(Text, { color: 'red', bold: true }, ' [- Will Uninstall]');
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
            { color: isFocused ? 'cyan' : 'gray', bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: isChecked ? 'green' : 'gray', bold: isChecked },
            isChecked ? '[✔ ENABLED]  ' : '[  DISABLED] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? 'yellow' : isChecked ? 'white' : 'gray' },
            mod.name
          ),
          React.createElement(
            Text,
            { color: 'magenta', marginLeft: 1 },
            `(${mod.category})`
          ),
          React.createElement(
            Text,
            { color: isInstalled ? 'green' : 'gray', marginLeft: 2 },
            `[${mod.status}]`
          ),
          changeBadge
        ),
        React.createElement(
          Box,
          { marginLeft: 4 },
          React.createElement(
            Text,
            { color: isFocused ? 'white' : 'gray' },
            mod.description
          )
        ),
        mod.dependencies && mod.dependencies.length > 0
          ? React.createElement(
              Box,
              { marginLeft: 4 },
              React.createElement(
                Text,
                { color: 'yellow', dimColor: true },
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
                { color: 'gray' },
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
            borderColor: 'yellow',
            flexDirection: 'column'
          },
          React.createElement(
            Text,
            { bold: true, color: 'yellow' },
            `⚡ Pending Changes to Apply:`
          ),
          toInstall.length > 0
            ? React.createElement(
                Text,
                { color: 'green' },
                `  • Install: ${toInstall.map(id => modules.find(m => m.id === id)?.name || id).join(', ')}`
              )
            : null,
          toUninstall.length > 0
            ? React.createElement(
                Text,
                { color: 'red' },
                `  • Uninstall: ${toUninstall.map(id => modules.find(m => m.id === id)?.name || id).join(', ')}`
              )
            : null,
          React.createElement(
            Text,
            { bold: true, color: 'green', marginTop: 1 },
            'Press [Enter] or [a] to Apply Changes now'
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
        borderColor: 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'cyan', bold: true }, '[Space] '),
        React.createElement(Text, { color: 'white' }, 'Toggle  '),
        React.createElement(Text, { color: 'green', bold: true }, '[Enter] '),
        React.createElement(Text, { color: 'white' }, 'Apply  '),
        React.createElement(Text, { color: 'gray' }, '| [u] Deploy All  [v] Values  [s] Status  [q] Return')
      ),
      React.createElement(
        Text,
        { color: 'gray', dimColor: true },
        'Use ↑/↓ or j/k to navigate'
      )
    )
  );
};
