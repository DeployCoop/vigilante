'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck,
  Key,
  RefreshCw,
  Plus,
  Trash2,
  Save,
  AlertCircle,
  Copy,
  X,
  Lock,
  UserCheck,
  ShieldAlert
} from 'lucide-react';
import { useAbilityContext } from '@/lib/ability';
import { apiErrorMessage } from '@/lib/envelope';

interface Grant {
  permission: string;
  scope?: { moduleId?: string; namespace?: string; clusterName?: string };
}

interface PublicPrincipal {
  id: string;
  name: string;
  kind: string;
  role: string;
  oidcSubject?: string;
  disabled: boolean;
  grants: Grant[];
  revocations: string[];
  hasToken: boolean;
}

interface AuditEntry {
  ts: string;
  principalId: string | null;
  permission?: string;
  allowed?: boolean;
  reason?: string;
  route: string;
  event?: string;
}

interface TokenReveal {
  title: string;
  token: string;
}

const inputCls =
  'w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none';
const btnCls =
  'px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono rounded-lg flex items-center space-x-1.5 transition-colors disabled:opacity-50';
const primaryBtnCls =
  'px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold rounded-lg flex items-center space-x-1.5 transition-colors disabled:opacity-50 shadow-sm';

export default function AccessPage() {
  const { status, principal: me, signIn, signOut, openSignInPrompt } = useAbilityContext();
  const [loading, setLoading] = useState(true);
  const [authzEnabled, setAuthzEnabled] = useState<boolean | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [principals, setPrincipals] = useState<PublicPrincipal[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [roles, setRoles] = useState<string[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState<TokenReveal | null>(null);

  // Enable form
  const [ownerName, setOwnerName] = useState('Admin Owner');
  const [ownerPassword, setOwnerPassword] = useState('');
  const [enabling, setEnabling] = useState(false);

  // Create form
  const [createName, setCreateName] = useState('');
  const [createKind, setCreateKind] = useState('human');
  const [createRole, setCreateRole] = useState('operator');
  const [createOidc, setCreateOidc] = useState('');

  // Editor state (per principal id)
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editRole, setEditRole] = useState('operator');
  const [editDisabled, setEditDisabled] = useState(false);
  const [editGrants, setEditGrants] = useState<Grant[]>([]);
  const [editRevocations, setEditRevocations] = useState<string[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/authz/principals');
      const data = await res.json().catch(() => ({}));
      if (res.status === 401 || res.status === 403) {
        setForbidden(true);
        setAuthzEnabled(true);
        return;
      }
      if (!res.ok) throw new Error(apiErrorMessage(data, `Request failed (${res.status})`));
      setForbidden(false);
      setAuthzEnabled(Boolean(data.authzEnabled));
      setPrincipals(data.principals ?? []);
      setPermissions(data.permissions ?? []);
      setRoles(data.roles ?? []);
      if (data.authzEnabled) {
        const auditRes = await fetch('/api/authz/audit?limit=50');
        if (auditRes.ok) {
          const auditData = await auditRes.json();
          setAudit(auditData.entries ?? []);
        }
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const fail = async (res: Response) => {
    const data = await res.json().catch(() => ({}));
    setError(apiErrorMessage(data, `Request failed (${res.status})`));
  };

  const handleEnable = async () => {
    setEnabling(true);
    setError(null);
    try {
      const res = await fetch('/api/authz/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: ownerName,
          ...(ownerPassword.trim() ? { password: ownerPassword.trim() } : {}),
        }),
      });
      if (!res.ok) return await fail(res);
      const data = await res.json();
      setReveal({
        title: data.isCustomPassword
          ? `Initial owner password configured for ${data.principal.name}`
          : `Owner token for ${data.principal.name} — save this now (shown once)`,
        token: data.token,
      });
      setMessage(
        'Authorization enabled! Store initialized at ~/.vigilante/authz.yaml (mode 0600).'
      );
      setOwnerPassword('');
      await load();
    } finally {
      setEnabling(false);
    }
  };

  const handleCreate = async () => {
    setError(null);
    setMessage(null);
    const res = await fetch('/api/authz/principals', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: createName,
        kind: createKind,
        role: createRole,
        ...(createOidc.trim() ? { oidcSubject: createOidc.trim() } : {}),
      }),
    });
    if (!res.ok) return await fail(res);
    const data = await res.json();
    if (data.token) {
      setReveal({ title: `Token for ${data.principal.name} — shown once`, token: data.token });
    }
    setMessage(`Principal ${data.principal.name} created.`);
    setCreateName('');
    setCreateOidc('');
    await load();
  };

  const startEdit = (p: PublicPrincipal) => {
    setEditingId(p.id);
    setEditRole(p.role);
    setEditDisabled(p.disabled);
    setEditGrants(p.grants.map((g) => ({ ...g, scope: g.scope ? { ...g.scope } : undefined })));
    setEditRevocations([...p.revocations]);
    setError(null);
  };

  const handleSaveEdit = async (p: PublicPrincipal) => {
    setError(null);
    const grants = editGrants
      .filter((g) => g.permission)
      .map((g) => {
        const scope: Grant['scope'] = {};
        if (g.scope?.moduleId?.trim()) scope.moduleId = g.scope.moduleId.trim();
        if (g.scope?.namespace?.trim()) scope.namespace = g.scope.namespace.trim();
        if (g.scope?.clusterName?.trim()) scope.clusterName = g.scope.clusterName.trim();
        return Object.keys(scope).length ? { permission: g.permission, scope } : { permission: g.permission };
      });
    const res = await fetch(`/api/authz/principals/${encodeURIComponent(p.id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: editRole,
        grants,
        revocations: editRevocations,
        disabled: editDisabled,
      }),
    });
    if (!res.ok) return await fail(res);
    setMessage(`${p.name} updated.`);
    setEditingId(null);
    await load();
  };

  const handleToggleDisabled = async (p: PublicPrincipal) => {
    setError(null);
    const res = await fetch(`/api/authz/principals/${encodeURIComponent(p.id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: p.role,
        grants: p.grants,
        revocations: p.revocations,
        disabled: !p.disabled,
      }),
    });
    if (!res.ok) return await fail(res);
    await load();
  };

  const handleRotate = async (p: PublicPrincipal) => {
    setError(null);
    const res = await fetch(`/api/authz/principals/${encodeURIComponent(p.id)}/rotate`, {
      method: 'POST',
    });
    if (!res.ok) return await fail(res);
    const data = await res.json();
    setReveal({ title: `New token for ${p.name} — shown once`, token: data.token });
    await load();
  };

  const handleDelete = async (p: PublicPrincipal) => {
    if (!window.confirm(`Remove principal ${p.name} (${p.id})? This cannot be undone.`)) return;
    setError(null);
    const res = await fetch(`/api/authz/principals/${encodeURIComponent(p.id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) return await fail(res);
    setMessage(`${p.name} removed.`);
    await load();
  };

  const roleBadge = (role: string) =>
    role === 'owner'
      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
      : role === 'admin'
        ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
        : role === 'operator'
          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
          : role === 'webhook'
            ? 'bg-purple-500/15 text-purple-300 border-purple-500/30'
            : 'bg-slate-500/15 text-slate-300 border-slate-500/30';

  return (
    <div className="space-y-6 max-w-6xl mx-auto font-mono">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900/90 border border-slate-800 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white tracking-tight">Access Control & Security Audit</h2>
          </div>
          <p className="text-xs text-slate-400">
            RBAC & ABAC authorization engine backed by CASL. Principals, roles, and scoped grants stored in{' '}
            <code className="text-cyan-300">~/.vigilante/authz.yaml</code>.
          </p>
          {me && (
            <p className="text-xs text-slate-400 flex items-center gap-1.5 pt-1">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Signed in as:</span>
              <span className="text-slate-200 font-semibold">{me.name}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded border ${roleBadge(me.role)}`}>
                {me.role}
              </span>
            </p>
          )}
          {status === 'local-board' && (
            <p className="text-xs text-amber-400/90 pt-1">
              ⚠️ Local board mode — loopback session active. Enable authorization below to lock down API access.
            </p>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button onClick={() => void load()} className={btnCls} disabled={loading}>
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
          {(status === 'ready' || status === 'unknown-principal') && (
            <button onClick={() => void signOut()} className={btnCls}>
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>Sign Out</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="flex items-start space-x-2 p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-300">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}
      {message && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>{message}</span>
        </div>
      )}

      {/* Token Reveal Banner */}
      {reveal && (
        <div className="p-5 bg-amber-500/10 border border-amber-500/40 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-amber-300 flex items-center space-x-2">
              <Key className="w-4 h-4 text-amber-400" />
              <span>{reveal.title}</span>
            </h3>
            <button
              onClick={() => setReveal(null)}
              className="text-slate-400 hover:text-slate-200"
              aria-label="Dismiss token"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-amber-200">
              {reveal.token}
            </code>
            <button
              className={btnCls}
              onClick={() => void navigator.clipboard?.writeText(reveal.token)}
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </button>
            <button
              className={btnCls}
              onClick={() => {
                void signIn(reveal.token);
                setMessage('Token saved to this browser session.');
              }}
            >
              <Save className="w-3.5 h-3.5 text-cyan-400" />
              <span>Sign In With Token</span>
            </button>
          </div>
          <p className="text-[11px] text-amber-300/80">
            Only the SHA-256 / scrypt hash is stored on the server. If this token is lost, rotate it immediately.
          </p>
        </div>
      )}

      {loading && <p className="text-xs text-slate-400">Loading access control state…</p>}

      {/* Uninitialized State: Bootstrap Initial Owner */}
      {!loading && authzEnabled === false && (
        <div className="p-6 bg-slate-900/90 border border-amber-500/30 rounded-xl space-y-4">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Authorization is Uninitialized</h3>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            The control plane is currently in loopback mode. Enabling authorization generates a fail-closed{' '}
            <code className="text-cyan-300">~/.vigilante/authz.yaml</code> store, locks down all 26 API routes with
            CASL ability checks, and provisions the initial Owner principal.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl">
            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">Initial Owner Name</span>
              <input
                value={ownerName}
                onChange={(e) => setOwnerName(e.target.value)}
                className={inputCls}
              />
            </label>
            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">
                Admin Password <span className="text-slate-500">(≥12 chars, or blank for auto-generated token)</span>
              </span>
              <input
                type="password"
                placeholder="Leave blank for vig_ token"
                value={ownerPassword}
                onChange={(e) => setOwnerPassword(e.target.value)}
                className={inputCls}
              />
            </label>
          </div>
          <div className="pt-2">
            <button onClick={() => void handleEnable()} disabled={enabling} className={primaryBtnCls}>
              <Lock className="w-3.5 h-3.5" />
              <span>{enabling ? 'Initializing…' : 'Initialize & Lock Down Vigilante'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Forbidden / Non-Owner Prompt */}
      {!loading && forbidden && (
        <div className="p-6 bg-slate-900 border border-red-500/30 rounded-xl space-y-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-red-300 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>Restricted Access: Owner Role Required</span>
            </h3>
            <p className="text-xs text-slate-400 max-w-2xl">
              Access control management requires the <code className="text-cyan-300">users:manage_permissions</code>{' '}
              permission. Sign in with an Owner token to manage principals and security policies.
            </p>
          </div>
          <button
            onClick={() => openSignInPrompt()}
            className={primaryBtnCls}
          >
            <Key className="w-3.5 h-3.5" />
            <span>Enter Owner Token / Password</span>
          </button>
        </div>
      )}

      {/* Principal Management */}
      {!loading && authzEnabled && !forbidden && (
        <>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white tracking-wider uppercase">Active Principals</h3>
              <span className="text-xs text-slate-500">{principals.length} principals enrolled</span>
            </div>

            {principals.map((p) => (
              <div key={p.id} className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
                <div className="flex flex-wrap items-center gap-2 justify-between">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-100">{p.name}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded border uppercase tracking-wider ${roleBadge(p.role)}`}>
                      {p.role}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded border border-slate-700 text-slate-400">
                      {p.kind}
                    </span>
                    {p.disabled && (
                      <span className="text-[10px] px-2 py-0.5 rounded border border-red-500/40 text-red-300 bg-red-500/10">
                        disabled
                      </span>
                    )}
                    <span className="text-[11px] text-slate-500 font-mono">{p.id}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className={btnCls} onClick={() => startEdit(p)}>Edit</button>
                    <button className={btnCls} onClick={() => void handleRotate(p)}>Rotate Token</button>
                    <button className={btnCls} onClick={() => void handleToggleDisabled(p)}>
                      {p.disabled ? 'Enable' : 'Disable'}
                    </button>
                    <button
                      className={`${btnCls} hover:bg-red-500/20 hover:border-red-500/40 hover:text-red-300`}
                      onClick={() => void handleDelete(p)}
                      title="Delete principal"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 space-y-1">
                  <p>
                    Authentication: {p.hasToken ? 'API Token / Password' : '—'}
                    {p.oidcSubject ? ` · OIDC Subject: ${p.oidcSubject}` : ''}
                  </p>
                  {p.grants.length > 0 && (
                    <p>
                      Explicit Grants:{' '}
                      {p.grants
                        .map(
                          (g) =>
                            g.permission +
                            (g.scope
                              ? ` (${[
                                  g.scope.moduleId && `module=${g.scope.moduleId}`,
                                  g.scope.namespace && `ns=${g.scope.namespace}`,
                                  g.scope.clusterName && `cluster=${g.scope.clusterName}`,
                                ]
                                  .filter(Boolean)
                                  .join(', ')})`
                              : '')
                        )
                        .join(' · ')}
                    </p>
                  )}
                  {p.revocations.length > 0 && (
                    <p className="text-red-400/90">Revocations: {p.revocations.join(' · ')}</p>
                  )}
                </div>

                {/* Inline Principal Editor */}
                {editingId === p.id && (
                  <div className="border-t border-slate-800 pt-4 space-y-4">
                    <div className="grid sm:grid-cols-2 gap-3">
                      <label className="space-y-1">
                        <span className="text-[11px] text-slate-400">Role</span>
                        <select value={editRole} onChange={(e) => setEditRole(e.target.value)} className={inputCls}>
                          {roles.map((r) => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      </label>
                      <label className="flex items-center gap-2 pt-6">
                        <input
                          type="checkbox"
                          checked={editDisabled}
                          onChange={(e) => setEditDisabled(e.target.checked)}
                          className="h-4 w-4 accent-red-500 rounded"
                        />
                        <span className="text-xs text-slate-300">Disable Principal (revoke all access)</span>
                      </label>
                    </div>

                    {/* Scoped Grants Editor */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-300">Scoped Grants (ABAC)</span>
                        <button
                          className={btnCls}
                          onClick={() =>
                            setEditGrants([...editGrants, { permission: permissions[0] ?? 'cluster:read', scope: {} }])
                          }
                        >
                          <Plus className="w-3.5 h-3.5" />
                          <span>Add Scoped Grant</span>
                        </button>
                      </div>
                      {editGrants.map((g, i) => (
                        <div key={i} className="flex flex-wrap gap-2 items-center">
                          <select
                            value={g.permission}
                            onChange={(e) =>
                              setEditGrants(editGrants.map((x, j) => (j === i ? { ...x, permission: e.target.value } : x)))
                            }
                            className="flex-1 min-w-44 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-100 font-mono"
                          >
                            {permissions.map((perm) => (
                              <option key={perm} value={perm}>{perm}</option>
                            ))}
                          </select>
                          <input
                            placeholder="moduleId (optional)"
                            value={g.scope?.moduleId ?? ''}
                            onChange={(e) =>
                              setEditGrants(editGrants.map((x, j) => (j === i ? { ...x, scope: { ...x.scope, moduleId: e.target.value } } : x)))
                            }
                            className="w-32 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-100 font-mono"
                          />
                          <input
                            placeholder="namespace (optional)"
                            value={g.scope?.namespace ?? ''}
                            onChange={(e) =>
                              setEditGrants(editGrants.map((x, j) => (j === i ? { ...x, scope: { ...x.scope, namespace: e.target.value } } : x)))
                            }
                            className="w-32 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-100 font-mono"
                          />
                          <input
                            placeholder="clusterName (opt)"
                            value={g.scope?.clusterName ?? ''}
                            onChange={(e) =>
                              setEditGrants(editGrants.map((x, j) => (j === i ? { ...x, scope: { ...x.scope, clusterName: e.target.value } } : x)))
                            }
                            className="w-32 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-100 font-mono"
                          />
                          <button
                            className={btnCls}
                            onClick={() => setEditGrants(editGrants.filter((_, j) => j !== i))}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>

                    {/* Revocations Editor */}
                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-slate-300">
                        Explicit Revocations (subtract from role capabilities)
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {permissions.map((perm) => {
                          const active = editRevocations.includes(perm);
                          return (
                            <button
                              key={perm}
                              onClick={() =>
                                setEditRevocations(
                                  active
                                    ? editRevocations.filter((x) => x !== perm)
                                    : [...editRevocations, perm]
                                )
                              }
                              className={`text-[10px] px-2 py-1 rounded border transition-colors ${
                                active
                                  ? 'bg-red-500/20 border-red-500/50 text-red-300'
                                  : 'border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-300'
                              }`}
                            >
                              {perm}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div className="flex justify-end gap-2 pt-2">
                      <button className={btnCls} onClick={() => setEditingId(null)}>Cancel</button>
                      <button className={primaryBtnCls} onClick={() => void handleSaveEdit(p)}>
                        <Save className="w-3.5 h-3.5" />
                        <span>Save Changes</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Create Principal Card */}
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Enroll New Principal</h3>
            <div className="grid sm:grid-cols-2 gap-3">
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Principal Name</span>
                <input
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  className={inputCls}
                  placeholder="analyst-1 / automation-runner"
                />
              </label>
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">OIDC Subject (Optional — SSO sign-in)</span>
                <input
                  value={createOidc}
                  onChange={(e) => setCreateOidc(e.target.value)}
                  className={inputCls}
                  placeholder="sub or email from identity provider"
                />
              </label>
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Kind</span>
                <select value={createKind} onChange={(e) => setCreateKind(e.target.value)} className={inputCls}>
                  <option value="human">human</option>
                  <option value="service">service</option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Role</span>
                <select value={createRole} onChange={(e) => setCreateRole(e.target.value)} className={inputCls}>
                  {roles.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="flex justify-end">
              <button className={primaryBtnCls} disabled={!createName.trim()} onClick={() => void handleCreate()}>
                <Plus className="w-3.5 h-3.5" />
                <span>Create Principal</span>
              </button>
            </div>
          </div>

          {/* Audit Log Table */}
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Security Audit Log</h3>
              <span className="text-[11px] text-slate-500">Live JSONL stream from ~/.vigilante/audit.log</span>
            </div>
            {audit.length === 0 ? (
              <p className="text-xs text-slate-500">No audited operations logged yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-800">
                      <th className="py-2 pr-3">Timestamp</th>
                      <th className="py-2 pr-3">Principal</th>
                      <th className="py-2 pr-3">Permission / Event</th>
                      <th className="py-2 pr-3">Decision</th>
                      <th className="py-2 pr-3">Reason</th>
                      <th className="py-2">Route</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.map((entry, i) => (
                      <tr key={i} className="border-b border-slate-800/50 text-slate-300">
                        <td className="py-2 pr-3 whitespace-nowrap text-slate-500">
                          {new Date(entry.ts).toLocaleTimeString()}
                        </td>
                        <td className="py-2 pr-3 text-cyan-300 font-semibold">{entry.principalId ?? 'anonymous'}</td>
                        <td className="py-2 pr-3">
                          {entry.event ? `session · ${entry.event.replace('session_', '')}` : entry.permission}
                        </td>
                        <td className="py-2 pr-3">
                          {entry.event ? (
                            <span className="text-slate-400">EVENT</span>
                          ) : (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              entry.allowed ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/20 text-red-300'
                            }`}>
                              {entry.allowed ? 'ALLOW' : 'DENY'}
                            </span>
                          )}
                        </td>
                        <td className="py-2 pr-3 text-slate-400">{entry.reason ?? '—'}</td>
                        <td className="py-2 text-slate-400 truncate max-w-xs">{entry.route}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
