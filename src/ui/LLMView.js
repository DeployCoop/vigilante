import React, { useState, useEffect, useRef } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import { useTheme } from './theme.js';
import { useClipboard } from './ClipboardManager.js';
import {
  checkOllamaHealth,
  listOllamaModels,
  runAnalystInference,
  saveAnalysisReport,
  getOllamaHost
} from '../engine/llm.js';
import { loadConfig } from '../engine/config.js';

export const PRESET_ANALYSES = [
  {
    key: '1',
    shortcut: 'r',
    name: 'Recon & Open Ports',
    description: 'Summarize discovered hosts, open ports, and attack surfaces',
    prompt: 'Analyze all discovered network hosts, open ports, and services. Highlight critical attack surfaces, unusual open port combinations, and security risks.'
  },
  {
    key: '2',
    shortcut: 'v',
    name: 'Vulnerability & CVEs',
    description: 'Audit service versions & NSE script findings for CVEs',
    prompt: 'Audit discovered service software versions and Nmap CVE script findings. Highlight high-severity vulnerabilities, outdated software, and outline remediation steps.'
  },
  {
    key: '3',
    shortcut: 'e',
    name: 'Incident Triage Review',
    description: 'Examine Evidence Vault artifacts for suspicious anomalies',
    prompt: 'Review the Incident Response Evidence Vault triage dumps (ping jitter, MTR loss, TLS certs, HTTP headers, ARP neighbor caches) and identify anomalous or suspicious behaviors.'
  },
  {
    key: '4',
    shortcut: 'k',
    name: 'Kubernetes Pod Audit',
    description: 'Audit pod restarts, crash loops, and cluster health',
    prompt: 'Analyze current Kubernetes pod statuses across all namespaces. Check for CrashLoopBackOff states, excessive restart loops, failed readiness probes, or misconfigured pods.'
  },
  {
    key: '5',
    shortcut: 't',
    name: 'Threat Correlation',
    description: 'Correlate network topology with threat scenarios & defense advice',
    prompt: 'Correlate the live network topology and ingress endpoints with simulated threat vectors (SIGMA rules, port scans, brute force, DNS tunneling) and provide actionable defense and hardening advice.'
  }
];

export const LLMView = ({ onNavigate = null, domain = 'vigilante.local' }) => {
  const theme = useTheme();
  const { copyToClipboard } = useClipboard();

  const cfg = loadConfig();
  const [provider, setProvider] = useState(cfg.ai?.defaultProvider || 'ollama');
  const [model, setModel] = useState(
    cfg.ai?.[provider]?.defaultModel || (provider === 'ollama' ? 'llama3.2' : 'gpt-4o')
  );

  const [ollamaStatus, setOllamaStatus] = useState({ ok: false, checking: true });
  const [ollamaModels, setOllamaModels] = useState([]);
  const [isModelModalOpen, setIsModelModalOpen] = useState(false);
  const [modalCursor, setModalCursor] = useState(0);

  const [messages, setMessages] = useState([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [statusStage, setStatusStage] = useState('');
  const [elapsedSec, setElapsedSec] = useState(0);
  const [streamingText, setStreamingText] = useState('');
  const [inputPrompt, setInputPrompt] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  const [promptHistory, setPromptHistory] = useState([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [feedback, setFeedback] = useState(null);
  const abortControllerRef = useRef(null);

  // Auto-check Ollama health and local models on mount
  useEffect(() => {
    let isMounted = true;
    async function initOllama() {
      const health = await checkOllamaHealth();
      if (!isMounted) return;
      setOllamaStatus({ ok: health.ok, version: health.version, error: health.error, checking: false });

      if (health.ok) {
        const models = await listOllamaModels();
        if (isMounted && models.length > 0) {
          setOllamaModels(models);
          // If current model not set or default, pick first available
          if (!model || model === 'llama3.2') {
            const hasLlama = models.find(m => m.name.includes('llama3') || m.model.includes('llama3'));
            setModel(hasLlama ? hasLlama.name : models[0].name);
          }
        }
      }
    }
    initOllama();
    return () => { isMounted = false; };
  }, []);

  // Elapsed seconds timer during generation
  useEffect(() => {
    if (!isGenerating) {
      setElapsedSec(0);
      return;
    }
    const timer = setInterval(() => {
      setElapsedSec(s => s + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [isGenerating]);

  // Send a query to the active LLM engine
  const handleSendPrompt = async (promptText) => {
    if (!promptText || !promptText.trim() || isGenerating) return;

    const userMessage = {
      id: `msg-${Date.now()}-u`,
      role: 'user',
      text: promptText.trim(),
      timestamp: new Date().toLocaleTimeString()
    };

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setMessages(prev => [...prev, userMessage]);
    setPromptHistory(prev => [promptText.trim(), ...prev.filter(p => p !== promptText.trim())]);
    setHistoryIdx(-1);
    setInputPrompt('');
    setIsTyping(false);
    setIsGenerating(true);
    setStatusStage('Compiling live MCP security context...');
    setElapsedSec(0);
    setStreamingText('');
    setFeedback(null);

    try {
      // Build conversation history for API call
      const historyForInference = messages.map(m => ({
        role: m.role,
        content: m.text
      }));

      const res = await runAnalystInference({
        provider,
        model,
        messages: historyForInference,
        prompt: promptText.trim(),
        onStatusUpdate: (stage) => {
          setStatusStage(stage);
        },
        onChunk: (_chunk, fullText) => {
          setStreamingText(fullText);
        },
        signal: controller.signal
      });

      const assistantMessage = {
        id: `msg-${Date.now()}-a`,
        role: 'assistant',
        text: res.content,
        provider: res.provider,
        model: res.model,
        timestamp: new Date().toLocaleTimeString()
      };

      setMessages(prev => [...prev, assistantMessage]);
      setStreamingText('');
    } catch (err) {
      if (err.name === 'AbortError') {
        setFeedback({ type: 'info', text: '⚠️ Generation cancelled by user.' });
        const cancelMessage = {
          id: `msg-${Date.now()}-cancel`,
          role: 'assistant',
          text: '⚠️ *Analysis query cancelled by user.*',
          provider,
          model,
          timestamp: new Date().toLocaleTimeString()
        };
        setMessages(prev => [...prev, cancelMessage]);
      } else {
        setFeedback({ type: 'error', text: `✖ Inference error (${provider}/${model}): ${err.message}` });
        const errorMessage = {
          id: `msg-${Date.now()}-err`,
          role: 'assistant',
          text: `⚠️ **Inference Failed**: ${err.message}\n\n*Tip: Check that Ollama is running (\`ollama serve\`) or verify your API key in \`config.yaml\`.*`,
          provider,
          model,
          timestamp: new Date().toLocaleTimeString()
        };
        setMessages(prev => [...prev, errorMessage]);
      }
    } finally {
      setIsGenerating(false);
      abortControllerRef.current = null;
    }
  };

  // Copy latest assistant response
  const handleCopyLatest = async () => {
    const lastAssistant = [...messages].reverse().find(m => m.role === 'assistant');
    if (lastAssistant && lastAssistant.text) {
      await copyToClipboard(lastAssistant.text);
      setFeedback({ type: 'success', text: '✔ Copied AI analysis to system clipboard!' });
      setTimeout(() => setFeedback(null), 3000);
    } else {
      setFeedback({ type: 'info', text: 'No AI response available to copy yet.' });
      setTimeout(() => setFeedback(null), 2500);
    }
  };

  // Export report to Evidence Vault
  const handleExportReport = async () => {
    const lastAssistant = [...messages].reverse().find(m => m.role === 'assistant');
    if (!lastAssistant || !lastAssistant.text) {
      setFeedback({ type: 'info', text: 'No analysis to export. Ask a question first.' });
      setTimeout(() => setFeedback(null), 2500);
      return;
    }

    try {
      const topic = messages.find(m => m.role === 'user')?.text?.slice(0, 30) || 'security-analysis';
      const result = await saveAnalysisReport(topic, lastAssistant.text, {
        provider: lastAssistant.provider,
        model: lastAssistant.model
      });

      setFeedback({
        type: 'success',
        text: `✔ Exported report to ${result.filename}${result.isSigned ? ' (🔏 GPG signed)' : ''}!`
      });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({ type: 'error', text: `Failed to export report: ${err.message}` });
    }
  };

  // Keyboard navigation
  useInput((input, key) => {
    // Mode A: Model & Provider Selection Modal
    if (isModelModalOpen) {
      const modalOptions = [
        ...ollamaModels.map(m => ({ provider: 'ollama', model: m.name, label: `Ollama: ${m.name} (${m.size})` })),
        { provider: 'ollama', model: 'llama3.2', label: 'Ollama: llama3.2 (default)' },
        { provider: 'ollama', model: 'mistral', label: 'Ollama: mistral' },
        { provider: 'ollama', model: 'deepseek-r1', label: 'Ollama: deepseek-r1' },
        { provider: 'anthropic', model: 'claude-3-5-sonnet-20241022', label: 'Claude: claude-3-5-sonnet' },
        { provider: 'anthropic', model: 'claude-3-5-haiku-20241022', label: 'Claude: claude-3-5-haiku' },
        { provider: 'openai', model: 'gpt-4o', label: 'OpenAI: gpt-4o' },
        { provider: 'openai', model: 'gpt-4o-mini', label: 'OpenAI: gpt-4o-mini' },
        { provider: 'gemini', model: 'gemini-2.0-flash', label: 'Gemini: gemini-2.0-flash' }
      ];

      if (key.upArrow || input === 'k') {
        setModalCursor(c => (c > 0 ? c - 1 : modalOptions.length - 1));
        return;
      }
      if (key.downArrow || input === 'j') {
        setModalCursor(c => (c < modalOptions.length - 1 ? c + 1 : 0));
        return;
      }
      if (key.return) {
        const selectedOpt = modalOptions[modalCursor];
        if (selectedOpt) {
          setProvider(selectedOpt.provider);
          setModel(selectedOpt.model);
          setFeedback({ type: 'success', text: `Switched AI Provider to ${selectedOpt.provider.toUpperCase()} (${selectedOpt.model})` });
          setTimeout(() => setFeedback(null), 3000);
        }
        setIsModelModalOpen(false);
        return;
      }
      if (key.escape || input === 'q') {
        setIsModelModalOpen(false);
        return;
      }
      return;
    }

    // Mode B: Interactive Prompt Typing
    if (isTyping) {
      if (key.return) {
        handleSendPrompt(inputPrompt);
        return;
      }
      if (key.escape) {
        setIsTyping(false);
        return;
      }
      if (key.upArrow) {
        if (promptHistory.length > 0) {
          const nextIdx = Math.min(historyIdx + 1, promptHistory.length - 1);
          setHistoryIdx(nextIdx);
          setInputPrompt(promptHistory[nextIdx]);
        }
        return;
      }
      if (key.downArrow) {
        if (historyIdx > 0) {
          const nextIdx = historyIdx - 1;
          setHistoryIdx(nextIdx);
          setInputPrompt(promptHistory[nextIdx]);
        } else if (historyIdx === 0) {
          setHistoryIdx(-1);
          setInputPrompt('');
        }
        return;
      }
      if (key.backspace || key.delete) {
        setInputPrompt(prev => prev.slice(0, -1));
        return;
      }
      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setInputPrompt(prev => prev + input);
        return;
      }
      return;
    }

    // Mode C: When generating, allow Esc to abort
    if (isGenerating) {
      if (key.escape) {
        abortControllerRef.current?.abort();
        return;
      }
      return;
    }

    // Mode D: Normal Navigation & Hotkeys
    if (key.tab && onNavigate) {
      onNavigate('menu');
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // [i] or [/] or [Space] -> Enter Prompt Typing Mode
    if (keyChar === 'i' || keyChar === '/' || input === ' ') {
      setIsTyping(true);
      return;
    }

    // [m] -> Open Model Switcher Modal
    if (keyChar === 'm') {
      setIsModelModalOpen(true);
      return;
    }

    // Presets 1-5 or r, v, e, k, t
    const preset = PRESET_ANALYSES.find(p => p.key === keyChar || p.shortcut === keyChar);
    if (preset) {
      handleSendPrompt(preset.prompt);
      return;
    }

    // [c] -> Copy latest response
    if (keyChar === 'c') {
      handleCopyLatest();
      return;
    }

    // [x] -> Export report
    if (keyChar === 'x') {
      handleExportReport();
      return;
    }

    // [l] -> Clear conversation
    if (keyChar === 'l') {
      setMessages([]);
      setStreamingText('');
      setFeedback({ type: 'info', text: 'Conversation cleared.' });
      setTimeout(() => setFeedback(null), 2000);
      return;
    }

    // Navigation delegates
    if (keyChar === 'b' && onNavigate) {
      onNavigate('dashboard');
      return;
    }
    if (keyChar === 'n' && onNavigate) {
      onNavigate('nmap');
      return;
    }
    if (keyChar === 'p' && onNavigate) {
      onNavigate('pods');
      return;
    }

    // [q] or [Esc] -> Return
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  return React.createElement(
    Box,
    {
      flexDirection: 'column',
      padding: 1,
      borderStyle: 'round',
      borderColor: theme.border || 'cyan'
    },
    // Top Title & Provider Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.primary || 'cyan', bold: true }, '🤖 AI SECURITY & FORENSICS ANALYST '),
        React.createElement(Text, { color: theme.text || 'white' }, `[Provider: `),
        React.createElement(Text, { color: theme.accent || 'yellow', bold: true }, provider.toUpperCase()),
        React.createElement(Text, { color: theme.text || 'white' }, ` | Model: `),
        React.createElement(Text, { color: theme.success || 'green', bold: true }, model),
        React.createElement(Text, { color: theme.text || 'white' }, `]`)
      ),
      React.createElement(
        Box,
        null,
        isGenerating
          ? React.createElement(
              Box,
              { marginRight: 2 },
              React.createElement(Text, { color: theme.warning || 'yellow' }, React.createElement(Spinner, { type: 'dots' })),
              React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, ` ${statusStage || 'Analyzing...'} (${elapsedSec}s)`)
            )
          : null,
        provider === 'ollama'
          ? ollamaStatus.ok
            ? React.createElement(Text, { color: theme.success || 'green', bold: true }, `🟢 Ollama Local (v${ollamaStatus.version || '0.x'})`)
            : React.createElement(Text, { color: theme.error || 'red', bold: true }, `🔴 Ollama Offline (Run 'ollama serve')`)
          : React.createElement(Text, { color: theme.secondary || 'magenta', bold: true }, `☁️ Cloud API`)
      )
    ),

    // Feedback banner
    feedback
      ? React.createElement(
          Box,
          { marginBottom: 1 },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? theme.error : feedback.type === 'success' ? theme.success : theme.info },
            feedback.text
          )
        )
      : null,

    // Main Conversation Display Box
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        minHeight: 14,
        maxHeight: 22,
        borderStyle: 'single',
        borderColor: theme.muted || 'gray',
        padding: 1
      },
      messages.length === 0 && !isGenerating
        ? React.createElement(
            Box,
            { flexDirection: 'column' },
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              '💡 Welcome to Vigilante AI Analyst — Powered by Local Ollama & MCP Telemetry'
            ),
            React.createElement(
              Text,
              { color: theme.text || 'white' },
              'Ask any question about your local network topology, discovered hosts, open ports, Evidence Vault forensic dumps, and Kubernetes pods.'
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray', marginTop: 1 },
              'Quick Presets: Press [1] Recon Summary, [2] CVE Audit, [3] Triage Review, [4] Pods Audit, [5] Threat Correlation'
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              'Custom Query: Press [i] or [/] to type a prompt. Press [m] to switch AI model / provider.'
            )
          )
        : null,

      // Render conversation messages
      messages.map((m) =>
        React.createElement(
          Box,
          {
            key: m.id,
            flexDirection: 'column',
            marginBottom: 1
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              {
                color: m.role === 'user' ? (theme.accent || 'yellow') : (theme.primary || 'cyan'),
                bold: true
              },
              m.role === 'user' ? '👤 Analyst Query' : `🛡️ Vigilante AI (${m.provider}/${m.model})`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray', dimColor: true },
              ` [${m.timestamp}]`
            )
          ),
          React.createElement(
            Text,
            { color: theme.text || 'white' },
            m.text
          )
        )
      ),

      // Live Streaming / Thinking Indicator Card with Spinner & Timer
      isGenerating
        ? React.createElement(
            Box,
            {
              flexDirection: 'column',
              marginTop: 1,
              padding: 1,
              borderStyle: 'round',
              borderColor: theme.warning || 'yellow'
            },
            React.createElement(
              Box,
              { justifyContent: 'space-between' },
              React.createElement(
                Box,
                null,
                React.createElement(Text, { color: theme.warning || 'yellow' }, React.createElement(Spinner, { type: 'dots' })),
                React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, ` ${statusStage || `Analyzing with ${provider.toUpperCase()} (${model})...`}`)
              ),
              React.createElement(
                Text,
                { color: theme.accent || 'yellow', bold: true },
                `⏱️  ${elapsedSec}s [Esc to cancel]`
              )
            ),
            streamingText
              ? React.createElement(
                  Box,
                  { marginTop: 1, flexDirection: 'column' },
                  React.createElement(Text, { color: theme.muted || 'gray', dimColor: true }, '--- Live Streaming Output ---'),
                  React.createElement(Text, { color: theme.text || 'white' }, streamingText)
                )
              : React.createElement(
                  Text,
                  { color: theme.muted || 'gray', dimColor: true, marginTop: 1 },
                  elapsedSec >= 8
                    ? `⏳ Local model (${model}) is evaluating prompt tokens and generating response. Please wait...`
                    : `⏳ Initializing reasoning engine and compiling MCP telemetry context...`
                )
          )
        : null
    ),

    // Interactive Input Bar with active status/spinner during generation
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingX: 1,
        borderStyle: 'round',
        borderColor: isGenerating
          ? (theme.warning || 'yellow')
          : isTyping
            ? (theme.accent || 'yellow')
            : (theme.muted || 'gray')
      },
      isGenerating
        ? React.createElement(
            Box,
            null,
            React.createElement(Text, { color: theme.warning || 'yellow' }, React.createElement(Spinner, { type: 'dots' })),
            React.createElement(
              Text,
              { color: theme.warning || 'yellow', bold: true },
              ` ⏳ Analysis in progress (${elapsedSec}s): ${statusStage || 'Processing...'} — Press [Esc] to abort`
            )
          )
        : React.createElement(
            React.Fragment,
            null,
            React.createElement(
              Text,
              { color: isTyping ? theme.accent : theme.muted, bold: true },
              isTyping ? '❯ ' : '💬 [i/Space to type] '
            ),
            React.createElement(
              Text,
              { color: isTyping ? theme.text : theme.muted },
              isTyping
                ? inputPrompt || ''
                : inputPrompt || 'Type your security query or press [1-5] for quick analysis presets...'
            ),
            isTyping
              ? React.createElement(Text, { color: theme.accent, bold: true }, ' █')
              : null
          )
    ),

    // Quick Presets Bar
    React.createElement(
      Box,
      { marginTop: 1, justifyContent: 'space-between' },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.accent, bold: true }, '[1] '),
        React.createElement(Text, { color: theme.text }, 'Recon  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[2] '),
        React.createElement(Text, { color: theme.text }, 'CVEs  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[3] '),
        React.createElement(Text, { color: theme.text }, 'Triage  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[4] '),
        React.createElement(Text, { color: theme.text }, 'Pods  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[5] '),
        React.createElement(Text, { color: theme.text }, 'Threats')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.secondary, bold: true }, '[m] '),
        React.createElement(Text, { color: theme.text }, 'Model  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[c] '),
        React.createElement(Text, { color: theme.text }, 'Copy  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[x] '),
        React.createElement(Text, { color: theme.text }, 'Export  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[Tab] '),
        React.createElement(Text, { color: theme.text }, 'Hub  '),
        React.createElement(Text, { color: theme.muted, bold: true }, '[q] '),
        React.createElement(Text, { color: theme.muted }, 'Return')
      )
    ),

    // Modal: Model & Provider Selector
    isModelModalOpen
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginTop: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.accent || 'yellow'
          },
          React.createElement(
            Text,
            { color: theme.accent || 'yellow', bold: true, marginBottom: 1 },
            '🎯 SELECT AI PROVIDER & MODEL (Use ↑/↓ and Enter):'
          ),
          [
            ...ollamaModels.map(m => ({ provider: 'ollama', model: m.name, label: `🟢 Ollama (Local): ${m.name} (${m.size})` })),
            { provider: 'ollama', model: 'llama3.2', label: '🟢 Ollama (Local): llama3.2' },
            { provider: 'ollama', model: 'mistral', label: '🟢 Ollama (Local): mistral' },
            { provider: 'ollama', model: 'deepseek-r1', label: '🟢 Ollama (Local): deepseek-r1' },
            { provider: 'anthropic', model: 'claude-3-5-sonnet-20241022', label: '☁️ Anthropic: claude-3-5-sonnet' },
            { provider: 'anthropic', model: 'claude-3-5-haiku-20241022', label: '☁️ Anthropic: claude-3-5-haiku' },
            { provider: 'openai', model: 'gpt-4o', label: '☁️ OpenAI: gpt-4o' },
            { provider: 'openai', model: 'gpt-4o-mini', label: '☁️ OpenAI: gpt-4o-mini' },
            { provider: 'gemini', model: 'gemini-2.0-flash', label: '☁️ Google Gemini: gemini-2.0-flash' }
          ].map((opt, idx) => {
            const isSelected = idx === modalCursor;
            const isActiveCurrent = opt.provider === provider && opt.model === model;
            return React.createElement(
              Box,
              { key: `${opt.provider}-${opt.model}-${idx}` },
              React.createElement(
                Text,
                { color: isSelected ? theme.accent : theme.text, bold: isSelected },
                `${isSelected ? '❯ ' : '  '}${opt.label}${isActiveCurrent ? ' [ACTIVE]' : ''}`
              )
            );
          })
        )
      : null
  );
};
