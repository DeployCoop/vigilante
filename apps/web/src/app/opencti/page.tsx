'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Satellite,
  RefreshCw,
  Search,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

interface OpenCtiIndicator {
  id?: string | null;
  name?: string | null;
  pattern?: string | null;
  score?: number | null;
  revoked?: boolean;
  labels?: string[];
  iocType?: string;
  iocValue?: string | null;
}

interface OpenCtiStatus {
  connection?: {
    connected?: boolean;
    url?: string;
    user?: { id?: string; name?: string | null; email?: string | null };
    error?: string;
  };
  cache?: { count?: number; syncedAt?: string; url?: string } | null;
}

interface LookupResult {
  value?: string;
  type?: string;
  found?: boolean;
  observables?: { id?: string | null; entityType?: string | null; observableValue?: string | null; score?: number | null }[];
  indicators?: OpenCtiIndicator[];
}

export default function OpenCtiPage() {
  const [status, setStatus] = useState<OpenCtiStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lookupValue, setLookupValue] = useState<string>('');
  const [lookup, setLookup] = useState<LookupResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState<boolean>(false);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  // No synchronous setLoading(true) here: this is called from an effect on
  // mount (loading already starts true), and the rule against setState in
  // effects flags a synchronous setState inside the fetch path.
  const fetchStatus = useCallback(() => {
    fetch('/api/opencti/status')
      .then((res) => res.json())
      .then((d) => {
        if (d.success === false) {
          setError(d.error || 'OpenCTI status unavailable');
          setStatus(null);
        } else {
          setError(null);
          setStatus(d);
        }
        setLoading(false);
      })
      .catch(() => {
        setError('OpenCTI status request failed');
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const runLookup = () => {
    const value = lookupValue.trim();
    if (!value) return;
    setLookupLoading(true);
    setLookupError(null);
    fetch(`/api/opencti/lookup?value=${encodeURIComponent(value)}`)
      .then((res) => res.json())
      .then((d) => {
        if (d.success === false) {
          setLookupError(d.error || 'Lookup failed');
          setLookup(null);
        } else {
          setLookupError(null);
          setLookup(d);
        }
        setLookupLoading(false);
      })
      .catch(() => {
        setLookupError('Lookup request failed');
        setLookupLoading(false);
      });
  };

  const runSync = () => {
    setSyncing(true);
    setSyncMessage(null);
    fetch('/api/opencti/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
      .then((res) => res.json())
      .then((d) => {
        if (d.success === false) {
          setSyncMessage(`Sync failed: ${d.error || 'unknown error'}`);
        } else {
          setSyncMessage(`Synced ${d.synced} indicator(s); cache now holds ${d.count}.`);
          fetchStatus();
        }
        setSyncing(false);
      })
      .catch(() => {
        setSyncMessage('Sync request failed');
        setSyncing(false);
      });
  };

  const connected = status?.connection?.connected === true;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
            <Satellite className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              OpenCTI Threat Intelligence
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950 border border-sky-800 text-sky-300">
                STIX 2.1
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Look up observables and sync indicators from the configured OpenCTI instance into the local CTI cache.
            </p>
          </div>
        </div>
        <button
          onClick={() => { setLoading(true); fetchStatus(); }}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 text-xs hover:bg-slate-700"
        >
          <RefreshCw className="w-4 h-4" /> Refresh status
        </button>
      </div>

      {loading ? (
        <p className="text-sm text-slate-400">Loading OpenCTI status…</p>
      ) : error ? (
        <div className="flex items-center gap-2 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
            <h2 className="text-sm font-semibold text-white mb-2">Instance</h2>
            <div className="flex items-center gap-2 text-sm">
              {connected ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <XCircle className="w-4 h-4 text-red-400" />
              )}
              <span className="text-slate-200">{connected ? 'Connected' : 'Not connected'}</span>
            </div>
            <p className="text-xs text-slate-400 mt-2 font-mono break-all">{status?.connection?.url ?? '—'}</p>
            {connected && status?.connection?.user ? (
              <p className="text-xs text-slate-400 mt-1">
                {status.connection.user.name || status.connection.user.id}
                {status.connection.user.email ? ` <${status.connection.user.email}>` : ''}
              </p>
            ) : null}
            {!connected && status?.connection?.error ? (
              <p className="text-xs text-red-300 mt-2">{status.connection.error}</p>
            ) : null}
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
            <h2 className="text-sm font-semibold text-white mb-2">Synced indicator cache</h2>
            {status?.cache ? (
              <>
                <p className="text-sm text-slate-200">{status.cache.count ?? 0} indicator(s)</p>
                <p className="text-xs text-slate-400 mt-1">Last sync: {status.cache.syncedAt ?? '—'}</p>
              </>
            ) : (
              <p className="text-sm text-slate-400">No cache yet — run a sync.</p>
            )}
            <button
              onClick={runSync}
              disabled={syncing || !connected}
              className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-sky-600 text-white text-xs hover:bg-sky-500 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Syncing…' : 'Sync indicators'}
            </button>
            {syncMessage ? <p className="text-xs text-slate-300 mt-2">{syncMessage}</p> : null}
          </div>
        </div>
      )}

      <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
        <h2 className="text-sm font-semibold text-white mb-2">Look up an observable</h2>
        <div className="flex gap-2">
          <input
            value={lookupValue}
            onChange={(e) => setLookupValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') runLookup(); }}
            placeholder="IP, domain, URL, or file hash"
            className="flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <button
            onClick={runLookup}
            disabled={lookupLoading || !lookupValue.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-sky-600 text-white text-xs hover:bg-sky-500 disabled:opacity-50"
          >
            <Search className="w-4 h-4" /> {lookupLoading ? 'Looking up…' : 'Look up'}
          </button>
        </div>
        {lookupError ? (
          <p className="text-xs text-red-300 mt-3">{lookupError}</p>
        ) : null}
        {lookup ? (
          <div className="mt-4">
            <p className="text-sm text-slate-200">
              {lookup.value} ({lookup.type}) — {lookup.found ? 'known to OpenCTI' : 'not found'}
            </p>
            {(lookup.indicators || []).length > 0 ? (
              <table className="w-full mt-3 text-xs">
                <thead>
                  <tr className="text-left text-slate-400 border-b border-slate-800">
                    <th className="py-2 pr-2">Indicator</th>
                    <th className="py-2 pr-2">Score</th>
                    <th className="py-2 pr-2">Labels</th>
                    <th className="py-2">Pattern</th>
                  </tr>
                </thead>
                <tbody>
                  {lookup.indicators.map((ind) => (
                    <tr key={ind.id || ind.pattern || ''} className="border-b border-slate-800/60 text-slate-200">
                      <td className="py-2 pr-2">{ind.name || ind.id || '—'}</td>
                      <td className="py-2 pr-2">{ind.score ?? '—'}</td>
                      <td className="py-2 pr-2">{(ind.labels || []).join(', ') || '—'}</td>
                      <td className="py-2 font-mono text-[11px] break-all">{ind.pattern || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
