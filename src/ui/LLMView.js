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
  getOllamaHost,
  SUPPORTED_PROVIDERS,
  getProviderStatus
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
  const [isProviderModalOpen, setIsProviderModalOpen] = useState(false);
  const [providerModalCursor, setProviderModalCursor] = useState(0);
  const [isModelModalOpen, setIsModelModalOpen] = useState(false);
  const [modelModalCursor, setModelModalCursor] = useState(0);

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
  const [errorAlert, setErrorAlert] = useState(null);
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
    setErrorAlert(null);

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

      if (!res?.content || !res.content.trim()) {
        throw new Error(`Empty response received from ${provider.toUpperCase()} (${model}). The model returned no text output.`);
      }

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
        const errMsg = err.message || 'Unknown error occurred during AI inference';
        const isMemoryOrContext = errMsg.includes('Empty response') || errMsg.includes('memory') || errMsg.includes('context');

        setFeedback({ type: 'error', text: `✖ ${errMsg}` });
        setErrorAlert({
          title: isMemoryOrContext ? 'AI Empty Response / Resource Limit' : 'AI Inference Failed',
          message: errMsg,
          provider,
          model,
          timestamp: new Date().toLocaleTimeString()
        });

        const errorMessage = {
          id: `msg-${Date.now()}-err`,
          role: 'assistant',
          isError: true,
          text: `🚨 **Inference Failed / Empty Response**: ${errMsg}\n\n*Diagnostics & Next Steps:*\n• **Ollama**: Verify daemon is active (\`ollama serve\`) or test in terminal (\`ollama run ${model}\`).\n• **Memory / Context Limit**: The local model may have run out of VRAM or exceeded token limits. Try a smaller model (Press \`[m]\` to select e.g. \`llama3.2:1b\` or \`qwen2.5:3b\`).\n• **Cloud Providers**: Check API keys in \`config.yaml\` or environment variables.`,
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

  // Dynamic list of models for the active provider
  const activeProviderModels = (() => {
    if (provider === 'ollama') {
      if (ollamaModels && ollamaModels.length > 0) {
        return ollamaModels.map(m => ({
          model: m.name,
          label: `🟢 Ollama (Local): ${m.name} (${m.size || 'ready'})`
        }));
      }
      return [
        { model: 'llama3.2', label: '🟢 Ollama (Local): llama3.2 (default)' },
        { model: 'llama3.3', label: '🟢 Ollama (Local): llama3.3' },
        { model: 'mistral', label: '🟢 Ollama (Local): mistral' },
        { model: 'deepseek-r1', label: '🟢 Ollama (Local): deepseek-r1' },
        { model: 'qwen2.5-coder', label: '🟢 Ollama (Local): qwen2.5-coder' },
        { model: 'phi3', label: '🟢 Ollama (Local): phi3' }
      ];
    }

    const provObj = SUPPORTED_PROVIDERS.find(p => p.id === provider);
    if (provObj && provObj.models) {
      return provObj.models.map(m => ({
        model: m,
        label: `${provObj.icon} ${provObj.name}: ${m}`
      }));
    }

    return [{ model, label: `${provider}: ${model}` }];
  })();

  // Keyboard navigation
  useInput((input, key) => {
    // Mode A0: Error Alert Modal Dismissal
    if (errorAlert) {
      if (key.return || key.escape || input === ' ' || input === 'q') {
        setErrorAlert(null);
        return;
      }
      return;
    }

    // Mode A1: Provider Selection Modal
    if (isProviderModalOpen) {
      if (key.upArrow || input === 'k') {
        setProviderModalCursor(c => (c > 0 ? c - 1 : SUPPORTED_PROVIDERS.length - 1));
        return;
      }
      if (key.downArrow || input === 'j') {
        setProviderModalCursor(c => (c < SUPPORTED_PROVIDERS.length - 1 ? c + 1 : 0));
        return;
      }
      if (key.return) {
        const chosenProvider = SUPPORTED_PROVIDERS[providerModalCursor];
        if (chosenProvider) {
          setProvider(chosenProvider.id);
          const nextModel = chosenProvider.id === 'ollama'
            ? (ollamaModels[0]?.name || chosenProvider.defaultModel)
            : chosenProvider.defaultModel;
          setModel(nextModel);

          const status = getProviderStatus(chosenProvider.id, cfg);
          if (!status.isConfigured && chosenProvider.type === 'cloud') {
            setFeedback({
              type: 'warning',
              text: `Switched to ${chosenProvider.label} (${nextModel}). ⚠️ Set $${chosenProvider.envKey} in environment or config.yaml before querying.`
            });
          } else {
            setFeedback({
              type: 'success',
              text: `✔ Switched AI Provider to ${chosenProvider.label} (${nextModel})`
            });
          }
          setTimeout(() => setFeedback(null), 3500);
        }
        setIsProviderModalOpen(false);
        return;
      }
      if (key.escape || input === 'q') {
        setIsProviderModalOpen(false);
        return;
      }
      return;
    }

    // Mode A2: Model Selection Modal for Active Provider
    if (isModelModalOpen) {
      if (key.upArrow || input === 'k') {
        setModelModalCursor(c => (c > 0 ? c - 1 : activeProviderModels.length - 1));
        return;
      }
      if (key.downArrow || input === 'j') {
        setModelModalCursor(c => (c < activeProviderModels.length - 1 ? c + 1 : 0));
        return;
      }
      if (key.return) {
        const selectedOpt = activeProviderModels[modelModalCursor];
        if (selectedOpt) {
          setModel(selectedOpt.model);
          setFeedback({ type: 'success', text: `✔ Model set to ${selectedOpt.model} for ${provider.toUpperCase()}` });
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

    // [p] -> Open Provider Switcher Modal
    if (keyChar === 'p') {
      const currentIdx = SUPPORTED_PROVIDERS.findIndex(p => p.id === provider);
      setProviderModalCursor(currentIdx >= 0 ? currentIdx : 0);
      setIsProviderModalOpen(true);
      return;
    }

    // [m] -> Open Model Switcher Modal
    if (keyChar === 'm') {
      const currentModelIdx = activeProviderModels.findIndex(m => m.model === model);
      setModelModalCursor(currentModelIdx >= 0 ? currentModelIdx : 0);
      setIsModelModalOpen(true);
      return;
    }

    // [i] or [/] or [Space] -> Enter Prompt Typing Mode
    if (keyChar === 'i' || keyChar === '/' || input === ' ') {
      setIsTyping(true);
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
          : (() => {
              const status = getProviderStatus(provider, cfg);
              return status.isConfigured
                ? React.createElement(Text, { color: theme.success || 'green', bold: true }, `${status.icon} ${status.name} (Key: Configured)`)
                : React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, `⚠️ ${status.name} (Missing $${status.envKey})`);
            })()
      )
    ),

    // Feedback banner
    feedback
      ? React.createElement(
          Box,
          { marginBottom: 1 },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? theme.error : feedback.type === 'warning' ? (theme.warning || 'yellow') : feedback.type === 'success' ? theme.success : theme.info },
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
              '💡 Welcome to Vigilante AI Analyst — Multi-Provider Security & Forensics Intelligence'
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
              'Switch AI Engine: Press [p] for Provider (Ollama/Claude/ChatGPT/Gemini/DeepSeek/Groq), [m] for Model, [i] to type a prompt.'
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
            marginBottom: 1,
            padding: m.isError ? 1 : 0,
            borderStyle: m.isError ? 'round' : undefined,
            borderColor: m.isError ? (theme.error || 'red') : undefined
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              {
                color: m.isError
                  ? (theme.error || 'red')
                  : m.role === 'user'
                    ? (theme.accent || 'yellow')
                    : (theme.primary || 'cyan'),
                bold: true
              },
              m.isError
                ? `🚨 Error (${m.provider}/${m.model})`
                : m.role === 'user'
                  ? '👤 Analyst Query'
                  : `🛡️ Vigilante AI (${m.provider}/${m.model})`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray', dimColor: true },
              ` [${m.timestamp}]`
            )
          ),
          React.createElement(
            Text,
            { color: m.isError ? (theme.error || 'red') : (theme.text || 'white') },
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
                    ? `⏳ AI Engine (${provider}/${model}) is evaluating prompt tokens and compiling response. Please wait...`
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
        React.createElement(Text, { color: theme.primary, bold: true }, '[p] '),
        React.createElement(Text, { color: theme.text }, 'Provider  '),
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

    // Modal 1: Error Alert Popup Modal
    errorAlert
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginTop: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.error || 'red'
          },
          React.createElement(
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(
              Text,
              { color: theme.error || 'red', bold: true },
              `🚨 ${errorAlert.title.toUpperCase()}`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray', dimColor: true },
              `[${errorAlert.provider}/${errorAlert.model} @ ${errorAlert.timestamp}]`
            )
          ),
          React.createElement(
            Text,
            { color: theme.text || 'white', bold: true },
            `Error: ${errorAlert.message}`
          ),
          React.createElement(
            Box,
            { flexDirection: 'column', marginTop: 1 },
            React.createElement(
              Text,
              { color: theme.warning || 'yellow', bold: true },
              '💡 Troubleshooting Tips:'
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              ` • Ollama: Verify 'ollama serve' is running or test with 'ollama run ${errorAlert.model}'.`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              ` • Cloud Providers: Check API key in config.yaml or set environment variable (e.g. $OPENAI_API_KEY, $ANTHROPIC_API_KEY).`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              ` • Switch Provider/Model: Press [p] to switch provider or [m] to choose a different model.`
            )
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              '👉 Press [Enter], [Space], or [Esc] to dismiss this alert'
            )
          )
        )
      : null,

    // Modal 2: Dedicated AI Provider Selector Modal ([p])
    isProviderModalOpen
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
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              '🎯 SELECT AI INFERENCE PROVIDER (Use ↑/↓ and Enter):'
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              '[Esc to close]'
            )
          ),
          SUPPORTED_PROVIDERS.map((p, idx) => {
            const status = getProviderStatus(p.id, cfg);
            const isSelected = idx === providerModalCursor;
            const isActive = p.id === provider;
            return React.createElement(
              Box,
              { key: p.id, justifyContent: 'space-between' },
              React.createElement(
                Text,
                { color: isSelected ? theme.accent : theme.text, bold: isSelected },
                `${isSelected ? '❯ ' : '  '}${p.icon} ${p.label}${isActive ? ' [ACTIVE]' : ''}`
              ),
              React.createElement(
                Text,
                {
                  color: status.isConfigured
                    ? (theme.success || 'green')
                    : (theme.warning || 'yellow'),
                  dimColor: !isSelected
                },
                status.isConfigured ? `✔ ${status.configuredKey || 'Ready'}` : `⚠️ ${status.statusText}`
              )
            );
          })
        )
      : null,

    // Modal 3: Model Selector Modal for Active Provider ([m])
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
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              `🎯 SELECT MODEL FOR ${provider.toUpperCase()} (Use ↑/↓ and Enter):`
            ),
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              '[Esc to close]'
            )
          ),
          activeProviderModels.map((opt, idx) => {
            const isSelected = idx === modelModalCursor;
            const isActive = opt.model === model;
            return React.createElement(
              Box,
              { key: `${provider}-${opt.model}-${idx}` },
              React.createElement(
                Text,
                { color: isSelected ? theme.accent : theme.text, bold: isSelected },
                `${isSelected ? '❯ ' : '  '}${opt.label}${isActive ? ' [ACTIVE]' : ''}`
              )
            );
          })
        )
      : null
  );
};
