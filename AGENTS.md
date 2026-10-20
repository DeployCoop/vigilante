<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **vigilante** (5972 symbols, 15403 relationships, 272 execution flows).

> Index stale? Run `node .gitnexus/run.cjs analyze --index-only` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? Bootstrap with `npx`, `bunx`, or `pnpm dlx` — e.g. `bunx gitnexus@latest analyze` (npm 11 npx crash; #1939).

## Always Do

- **MUST run impact before editing.** Use `impact({target: "symbolName", direction: "upstream"})` or `node .gitnexus/run.cjs impact "symbolName" --direction upstream --repo .`; report callers, processes, and risk. Never substitute grep for graph analysis.
- **MUST analyze graph changes before committing.** Use `detect_changes({scope: "all"})` (MCP) or `node .gitnexus/run.cjs detect-changes --scope all --repo .` (CLI fallback). `partial: true` or `truncated: true` is not a clean check — a zero means unseen, not unaffected; re-run it. For regression review: `detect_changes({scope: "compare", base_ref: "main"})` or `node .gitnexus/run.cjs detect-changes --scope compare --base-ref "main" --repo .`.
- MUST warn on HIGH/CRITICAL `risk` pre-edit; never use `riskSharedAxes` to waive a HIGH/CRITICAL `risk` warning. Compare File/symbol: MCP File omits axes; Graph-RAG expands File.
- **MUST treat `risk: UNKNOWN` as unresolved, not as low.** An empty caller set is not evidence the symbol is unused — it can also mean the callers are not resolvable by the index (plain-object property access, dynamic dispatch, cross-language calls). `impact` pairs `UNKNOWN` with a `riskNote` saying so. Confirm with a text search before treating the symbol as safe to change or delete; do not proceed on the strength of a zero.
- **MUST use `query({search_query: "concept"})` for concepts/flows, `context({name: "symbolName"})` for a named symbol, or `impact` for blast radius, on read-only callers, dependencies, imports, or execution flow.** Graph first; text search only for empty/`UNKNOWN`/literals.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method before MCP/CLI impact analysis.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis, and never read `UNKNOWN` as an all-clear — it means the walk could not answer, which is the one verdict that requires confirming by other means.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit before MCP/CLI graph change analysis.

## Resources

| Resource | Use for |
| --- | --- |
| `gitnexus://repo/vigilante/context` | Codebase overview, check index freshness |
| `gitnexus://repo/vigilante/clusters` | All functional areas |
| `gitnexus://repo/vigilante/processes` | All execution flows |
| `gitnexus://repo/vigilante/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
| --- | --- |
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->

---

# Vigilante — Project Architecture & Agent Engineering Guide

**Vigilante** is an AI-native cybersecurity orchestration, incident response, network reconnaissance, and CTF cyber range platform designed for local Kubernetes (`k3d` in Docker and native host `k3s`). It provides full operational parity across a **Next.js 14 Web Operations Portal** (`apps/web`), a **React Ink Terminal UI & CLI** (`apps/ink`), and a **78-tool Model Context Protocol (MCP) Server** (`packages/vigilante_lib/src/mcp/server.js`).

---

## 1. Monorepo Structure & Workspaces

Managed with `pnpm` workspaces (`Node.js >= 22.5`, ESM `"type": "module"`):

```text
vigilante/
├── packages/
│   └── vigilante_lib/            # Shared core library (engines, modules, authz, MCP, CLI helpers)
│       ├── src/
│       │   ├── cli/              # Non-TUI CLI command implementations (authz.js, doctor.js)
│       │   ├── engine/           # 70+ security, SOAR, forensics, cluster, and CTF engines
│       │   ├── mcp/              # stdio MCP server exposing 78 tools & 16 resources
│       │   ├── modules/          # 12 Kubernetes Helm/manifest security package orchestrators
│       │   ├── utils/            # Logger, clipboard, shell & formatting utilities
│       │   └── index.js          # Root barrel (includes Ink UI exports — DO NOT import in apps/web)
│       └── test/                 # Package-scoped unit tests (e.g. authz.test.js)
├── apps/
│   ├── ink/                      # @vigilante/ink — React Ink v4 Terminal UI & CLI
│   │   ├── bin/vigilante.js      # Main CLI entrypoint (37+ subcommands)
│   │   └── src/ui/               # Canonical home of all React Ink TUI views
│   ├── web/                      # @vigilante/web — Next.js 14 App Router Web Operations Portal
│   │   ├── public/images/        # Cyberpunk operative & badge artwork
│   │   └── src/
│   │       ├── app/              # 28 UI views (/event, /ctf, /battlestation, etc.) & 36 /api/* routes
│   │       ├── components/       # AppShell, CommandPalette, AuthzProvider
│   │       ├── lib/              # Server/client authz bridges (authz-server.ts, ability.ts)
│   │       └── middleware.ts     # Fail-closed session/token authentication & route guard
│   └── githubio/                 # githubio — Next.js 16 (Turbopack) + MDX Documentation Site
│       ├── public/images/        # Cyberpunk operative & badge artwork
│       └── src/app/              # Landing page & 14 MDX documentation manuals (/docs/*)
├── tests/                        # 84 root integration, engine, CLI, and security regression suites
├── bootstrap.sh                  # Automated Debian/Ubuntu/Kali provisioning & preflight script
└── values/                       # Default exported Helm values overrides
```

### Symlink Layout (Important)
- `packages/vigilante_lib/src/{engine,mcp,modules,utils,cli}` is the **single source of truth** for backend logic.
- `apps/ink/src/ui/` is the **single source of truth** for React Ink terminal components.
- Root `src/*` and `apps/ink/src/{engine,mcp,modules,utils}` are **symlinks** pointing to `packages/vigilante_lib/src/*` so root-level tests (`tests/*.js`) and CLI binaries resolve identically. Edit the canonical files in `packages/vigilante_lib/src/` or `apps/ink/src/ui/`.

---

## 2. Core Subsystems & Capabilities

### A. Dual Kubernetes Runtime (`k3d` & `k3s`)
- Managed by `packages/vigilante_lib/src/engine/cluster.js`, `k8s.js`, `instances.js`, and `modules/base.js`.
- Supports **Docker-based `k3d`** (`--provider k3d`, default) and **native host `k3s`** (`--provider k3s` or `--k3s`).
- Automatically issues locally trusted wildcard TLS certificates (`*.vigilante.local`) via `mkcert` and synchronizes `/etc/hosts` via `vigilante hostr`.

### B. 12 Deployable Security Modules (`packages/vigilante_lib/src/modules/`)
Registered in `modules/registry.js` and inheriting from `BaseModule` (`modules/base.js`):
`vigil-soc`, `opensearch`, `wazuh`, `bloodhound`, `falco`, `suricata`, `zeek`, `zap`, `flamingo`, `kctf`, `openvas`, and `vigil-local`.

### C. CASL RBAC / ABAC Authorization (`authz.js` & `authz-oidc.js`)
- **State**: `$XDG_CONFIG_HOME/vigilante/authz.yaml` (override via `VIGILANTE_AUTHZ_FILE`).
- **Audit Trail**: Size-rotated JSONL log at `$XDG_CONFIG_HOME/vigilante/audit.log` (`VIGILANTE_AUDIT_LOG`).
- **Roles**: `owner`, `admin`, `operator`, `analyst`, `auditor`, `viewer`.
- **Scopes**: Grants can be scoped by `module`, `namespace`, `cluster`, `source` (`loopback` vs `any`), and `authMethod` (`session`, `token`, `oidc`).
- **Cryptography**: `crypto.scryptSync` for passwords, SHA-256 digests for bearer tokens and 12-hour `HttpOnly` session cookies (`vigilante_session`), and `crypto.timingSafeEqual` for all secret comparisons.

### D. CTF Cyber Range, Tournament Engine & Solver Workbench
- **Engines**: `kctf.js` (ephemeral `nsjail` sandboxes & HMAC flags), `tournament.js` (Jeopardy dynamic decay $500 \to 100$, First Blood multipliers 🩸 $1.5\times$ / 🥈 $1.25\times$ / 🥉 $1.1\times$, Attack-Defense 120s SLA ticks, King of the Hill), `ctf-tools.js` (De Bruijn cyclic offsets, cipher auto-ID, JWT inspector, Wiener/Fermat/Trial RSA factorizer, ROP gadget finder, XOR crib drag), `ctf-client.js` (workspace scaffolder `./ctf-workspace`, GPG-signed writeups, Merkle solve sealing), and `llm.js` (3-tier Socratic AI Mentor with zero flag leaks).
- **Web Routes**: `/event` (Player Field Manual, Readiness Radar, 1-Click Workspace Scaffolder, Interactive Solver Workbench) and `/ctf` (Challenge Arena & Scoreboard).
- **CLI**: `vigilante ctf <host|spawn|sandboxes|reap|scoreboard|join|submit|rop|rsa|triage|crash|ask|tools>`.

---

## 3. Non-Negotiable Engineering & Security Rules

### Rule 1: Subpath Imports in `apps/web` (CRITICAL)
**NEVER** import the root `'vigilante_lib'` barrel inside `apps/web` (e.g., `import { ... } from 'vigilante_lib'`).
- **Why**: `packages/vigilante_lib/src/index.js` re-exports React Ink terminal UI views (`./ui/*`), which pulls `ink` and terminal dependencies into Next.js webpack bundles and breaks the build.
- **Always use explicit subpath exports**:
  ```ts
  import { loadConfig } from 'vigilante_lib/engine/config.js';
  import { decide } from 'vigilante_lib/engine/authz.js';
  import { getModuleRegistry } from 'vigilante_lib/modules/registry.js';
  ```

### Rule 2: Fail-Closed Cryptography & Verification
- **Dynamic CTF Flags**: `deriveTeamHmacFlag` and flag submission endpoints (`/api/ctf/challenges`, `vigilante ctf submit`) require a configured secret (`VIGILANTE_CTF_SECRET`) and must verify against the derived HMAC. Never accept arbitrary flags or register user-submitted flags as the expected answer.
- **Pinned Key Verification**: In `federation.js`, `supplychain.js` (Cosign), `ledger.js` (Merkle audit ledger), `evidencepack.js` (RFC 3161 bundles), and `snapshot.js`, verification must fail closed (`valid: false` / `verified: false`) when keys, digests, or signatures are missing or tampered with. Payloads must be canonicalized (`canonicalJson`) before signing/verifying.

### Rule 3: Injection-Sink & Path-Traversal Hardening
- **No Shell Interpolation**: Execute external binaries via array argv (`execa(cmd, args)` or `execFile`), never via unquoted shell string concatenation. When generating shell scripts (`remediation.js`), quote all dynamic tokens with `shQuote`.
- **SQL & XML Safety**: In `sigma.js` and `datalake.js`, escape SQL string literals and `LIKE` wildcards (`%`, `_`, `\`). In `openvas.js`, escape all XML attributes/bodies via `escapeXml`.
- **Kubernetes & Hosts Sanitizers**: Validate and sanitize identifiers (`sanitizePathComponent`, DNS label checks) before emitting Kubernetes YAML manifests (`kctf.js`, `threats.js`) or `/etc/hosts` entries (`hosts.js`).
- **Path Containment**: Any file read/write path constructed from user parameters, incident IDs, or archive entries must be verified to stay within its intended base directory via `path.resolve` prefix validation.

### Rule 4: Honest Synthetic / Emulation Marking (D19 Invariant)
- Many security engines (`kubeaudit.js`, `nuclei.js`, `zap.js`, `openvas.js`, `trivy.js`) can operate in air-gapped or workstation environments where the underlying scanner binary is not installed.
- Whenever an engine falls back to emulated/synthetic output, both the returned object and any persisted JSON artifact on disk **MUST** include `synthetic: true` and `runner: 'none'`. Compliance fallbacks must report check status as `'UNKNOWN'` (never fabricate `'PASS'` totals).

### Rule 5: Web Portal API Route Authorization
- Every page and API route in `apps/web` is guarded by `apps/web/src/middleware.ts` and `apps/web/src/lib/authz-server.ts`.
- When adding a new `/api/*` route in `apps/web`, always:
  1. Enforce `requirePermission(req, '<resource>:<action>', scope)` inside the route handler.
  2. Register the route prefix and required permission in `apps/web/src/middleware.ts`.

### Rule 6: MDX Safety in `apps/githubio`
- `apps/githubio` compiles `.mdx` files using `@next/mdx` and Turbopack without a LaTeX math plugin.
- **Never** write raw `{...}` expressions (such as LaTeX `$$\text{Flag}$$` or unescaped curly braces) in prose outside fenced code blocks or inline backticks, or Next.js static prerendering will fail with `ReferenceError: <ident> is not defined`.
- **Never** include `file:///...` workstation-local links in documentation pages; always use clean Next.js routes (`/docs/ctf`, `/docs/web-authz`, `/docs/cli`, etc.).

---

## 4. Verification & Pre-Commit Checklist

Before committing any change, run the relevant verification suites:

1. **GitNexus Impact Analysis (Pre-Edit)**:
   ```bash
   node .gitnexus/run.cjs impact "<symbolName>" --direction upstream --repo .
   ```
2. **Core Engine, CLI & Security Invariant Tests (84 Suites)**:
   ```bash
   pnpm test
   # Or run targeted invariant suites:
   node tests/test-fail-closed-crypto.js
   node tests/test-injection-sinks.js
   node tests/test-traversal.js
   node tests/test-synthetic-marking.js
   node tests/test-ctf-integrity.js
   node packages/vigilante_lib/test/authz.test.js
   ```
3. **Web Operations Portal Production Build (`apps/web`)**:
   ```bash
   pnpm --filter @vigilante/web build
   ```
4. **Documentation Static Export & Pagefind Index (`apps/githubio`)**:
   ```bash
   pnpm --filter githubio build
   ```
5. **GitNexus Change & Blast-Radius Verification (Pre-Commit)**:
   ```bash
   node .gitnexus/run.cjs detect-changes --scope all --repo .
   ```
