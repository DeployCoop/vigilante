'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from 'react';
import {
  abilityFromMe,
  emptyAbility,
  endSession,
  exchangeTokenForSession,
  subjectFor,
  type AbilityStatus,
  type AuthzTarget,
  type ClientAbility,
  type MePrincipal,
  type MeResponse
} from './ability-core';
import { ShieldCheck, Key, AlertCircle, X, Lock } from 'lucide-react';

interface AbilityContextValue {
  status: AbilityStatus;
  principal: MePrincipal | null;
  can: (permission: string, target?: AuthzTarget) => boolean;
  signIn: (token: string) => Promise<boolean>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
  openSignInPrompt: () => void;
}

const AbilityContext = createContext<AbilityContextValue>({
  status: 'loading',
  principal: null,
  can: () => false,
  signIn: async () => false,
  signOut: async () => {},
  refresh: async () => {},
  openSignInPrompt: () => {}
});

export function useAbilityContext(): AbilityContextValue {
  return useContext(AbilityContext);
}

export function useCan(permission: string, target?: AuthzTarget): boolean {
  const { can } = useAbilityContext();
  return can(permission, target);
}

export function Can({
  permission,
  target,
  children,
  fallback = null
}: {
  permission: string;
  target?: AuthzTarget;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const allowed = useCan(permission, target);
  return <>{allowed ? children : fallback}</>;
}

const PROMPT_DISMISSED_KEY = 'vigilante_token_prompt_dismissed';

export function AbilityProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AbilityStatus>('loading');
  const [principal, setPrincipal] = useState<MePrincipal | null>(null);
  const [ability, setAbility] = useState<ClientAbility>(() => emptyAbility());
  const [promptDismissed, setPromptDismissed] = useState(false);
  const [promptOpen, setPromptOpen] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');
  const [signingIn, setSigningIn] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/authz/me');
      const body = (await res.json().catch(() => null)) as MeResponse | null;
      const derived = abilityFromMe(body, res.status);
      setStatus(derived.status);
      setAbility(derived.ability);
      setPrincipal(body?.principal ?? null);
    } catch {
      setStatus('unauthenticated');
      setAbility(emptyAbility());
      setPrincipal(null);
    }
  }, []);

  useEffect(() => {
    try {
      setPromptDismissed(window.sessionStorage.getItem(PROMPT_DISMISSED_KEY) === '1');
    } catch {
      // ignore
    }
    void refresh();
  }, [refresh]);

  const openSignInPrompt = useCallback(() => {
    setPromptOpen(true);
    setSignInError(null);
  }, []);

  const signIn = useCallback(
    async (secret: string): Promise<boolean> => {
      setSigningIn(true);
      setSignInError(null);
      try {
        const ok = await exchangeTokenForSession(secret.trim());
        if (ok) {
          setPromptOpen(false);
          setTokenDraft('');
          await refresh();
          return true;
        } else {
          setSignInError('Invalid token or password');
          return false;
        }
      } catch (err: any) {
        setSignInError(err?.message || 'Login failed');
        return false;
      } finally {
        setSigningIn(false);
      }
    },
    [refresh]
  );

  const signOut = useCallback(async () => {
    await endSession();
    setSignInError(null);
    await refresh();
  }, [refresh]);

  const can = useCallback(
    (permission: string, target?: AuthzTarget) => {
      const [, action] = permission.split(':');
      if (!action) return false;
      return ability.can(action, subjectFor(permission, target) as any);
    },
    [ability]
  );

  const value = useMemo<AbilityContextValue>(
    () => ({ status, principal, can, signIn, signOut, refresh, openSignInPrompt }),
    [status, principal, can, signIn, signOut, refresh, openSignInPrompt]
  );

  const dismissPrompt = () => {
    setPromptDismissed(true);
    setPromptOpen(false);
    try {
      window.sessionStorage.setItem(PROMPT_DISMISSED_KEY, '1');
    } catch {
      // ignore
    }
  };

  const showPrompt =
    promptOpen || ((status === 'unauthenticated' || status === 'unknown-principal') && !promptDismissed);

  return (
    <AbilityContext.Provider value={value}>
      {children}
      {showPrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/95 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                    Authenticate to Vigilante
                  </h3>
                  <p className="text-xs text-slate-400">
                    Enter your principal token (`vig_...`) or password
                  </p>
                </div>
              </div>
              <button
                onClick={dismissPrompt}
                className="text-slate-400 hover:text-slate-200 transition-colors p-1"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {signInError && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{signInError}</span>
              </div>
            )}

            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (tokenDraft.trim()) {
                  await signIn(tokenDraft);
                }
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 font-mono">
                  Token or Password
                </label>
                <div className="relative">
                  <Key className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="password"
                    value={tokenDraft}
                    onChange={(e) => setTokenDraft(e.target.value)}
                    placeholder="vig_... or admin password"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none font-mono"
                    autoFocus
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={dismissPrompt}
                  className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  Browse as Guest
                </button>
                <button
                  type="submit"
                  disabled={signingIn || !tokenDraft.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-900 font-bold text-xs rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>{signingIn ? 'Signing In...' : 'Authenticate'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </AbilityContext.Provider>
  );
}
