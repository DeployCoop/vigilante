import React from 'react';
import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="text-2xl font-black tracking-wider text-emerald-400">VIGILANTE</span>
          <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-mono">v0.6.0</span>
        </div>
        <div className="flex items-center space-x-6 text-sm text-slate-400">
          <Link href="/docs" className="hover:text-emerald-400 transition">Documentation</Link>
          <Link href="/docs/ctf" className="hover:text-emerald-400 transition">CTF Cyber Range</Link>
          <Link href="/docs/web-authz" className="hover:text-emerald-400 transition">Web Portal & Authz</Link>
          <a href="#features" className="hover:text-emerald-400 transition">Features</a>
          <a href="#modules" className="hover:text-emerald-400 transition">Modules</a>
          <a href="#quickstart" className="hover:text-emerald-400 transition">Quickstart</a>
          <a href="https://github.com/DeployCoop/vigilante" target="_blank" rel="noreferrer" className="text-emerald-400 hover:text-emerald-300 transition font-medium">GitHub →</a>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-12 space-y-16">
        {/* Hero */}
        <section className="text-center space-y-6 pt-8 pb-12 border-b border-slate-800">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            Dual Parity: Next.js Web Operations Portal ⟷ React Ink Terminal CLI
          </div>
          <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight text-white">
            Cybersecurity <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-sky-400">Orchestration & Cyber Range</span> Platform
          </h1>
          <p className="max-w-3xl mx-auto text-lg sm:text-xl text-slate-400 leading-relaxed">
            Automated cyber range, AI-native autonomous SOC, and threat simulation mesh built natively for local Kubernetes
            with dual support for <strong>k3d</strong> (Docker) and native <strong>k3s</strong>.
          </p>
          <div className="flex justify-center gap-4 pt-4">
            <a href="#quickstart" className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold px-6 py-3 rounded-lg shadow-lg hover:shadow-emerald-500/20 transition">
              Get Started
            </a>
            <Link href="/docs/getting-started" className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold px-6 py-3 rounded-lg transition">
              Read Docs
            </Link>
            <Link href="/docs/ctf" className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-6 py-3 rounded-lg transition">
              CTF Guide →
            </Link>
          </div>
        </section>

        {/* Overview */}
        <section id="features" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Platform Capabilities</h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-purple-400 text-xl font-bold">🚩 CTF Cyber Range & Solver Workbench</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Google kCTF ephemeral sandboxes under <code>nsjail</code>, Jeopardy/Attack-Defense/KotH tournaments,
                3-tier Socratic AI Mentor, De Bruijn cyclic buffers, JWT inspector, RSA factorizers, and Merkle-anchored GPG writeups.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-cyan-400 text-xl font-bold">🖥️ Full-Featured Web Operations Portal</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Next.js 14 Web Portal (<code>apps/web</code>) mirroring all 25+ terminal security panes: NastyMap Recon,
                BattleStation live SOC, PCAP Forensics, Packet Sniffer, Kernel eBPF Lineage, and Shift-Left CI/CD Audit.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-amber-400 text-xl font-bold">🔐 Enterprise CASL RBAC / ABAC Security</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Fail-closed authorization engine (<code>~/.vigilante/authz.yaml</code>) with scoped grants, OIDC SSO,
                12h <code>HttpOnly</code> session cookies, scrypt passwords, SHA-256 tokens, and size-rotated audit logs.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-emerald-400 text-xl font-bold">🤖 Vigil SOC & Bifrost LLM Gateway</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Autonomous, agentic AI investigation engine with native LLM gateway routing, ReAct loop analysis,
                multi-agent incident war rooms, and automated NIST SP 800-61 Rev. 2 post-mortems.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-blue-400 text-xl font-bold">☸️ Dual K3d & Native K3s Orchestration</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Spin up isolated multi-cluster environments in Docker (k3d) or deploy directly into host-level K3s clusters
                with automated wildcard TLS certificates (<code>mkcert</code>) and zero-config <code>/etc/hosts</code> routing.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-rose-400 text-xl font-bold">🛡️ SOAR Active Containment & HoneyMesh</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Sub-second zero-trust network isolation (<code>isolatePod</code>), container freeze (SIGSTOP), deception canary tokens,
                and Falco eBPF kernel monitoring with live syscall behavioral anomaly detection.
              </p>
            </div>
          </div>
        </section>

        {/* Modules */}
        <section id="modules" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Supported Security Modules</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border border-slate-800 rounded-lg overflow-hidden">
              <thead className="bg-slate-900 text-slate-300 uppercase font-mono text-xs">
                <tr>
                  <th className="py-3 px-4">Module</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Default Ingress URL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-400 font-mono text-xs">
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">kctf</td>
                  <td className="py-3 px-4 font-sans text-sm">Google kCTF cyber range, ephemeral nsjail challenges & tournament arena</td>
                  <td className="py-3 px-4">ctf.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">vigil-soc</td>
                  <td className="py-3 px-4 font-sans text-sm">Autonomous AI SOC, Bifrost LLM gateway, PostgreSQL & Redis</td>
                  <td className="py-3 px-4">vigil.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">opensearch</td>
                  <td className="py-3 px-4 font-sans text-sm">Distributed SIEM engine & OpenSearch Dashboards analytics</td>
                  <td className="py-3 px-4">siem.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">openvas</td>
                  <td className="py-3 px-4 font-sans text-sm">Greenbone Community Edition (GVM) vulnerability scanner</td>
                  <td className="py-3 px-4">openvas.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">wazuh</td>
                  <td className="py-3 px-4 font-sans text-sm">Host-based intrusion detection (HIDS), agent manager, indexer</td>
                  <td className="py-3 px-4">wazuh.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">bloodhound</td>
                  <td className="py-3 px-4 font-sans text-sm">Active Directory & Kubernetes attack path analysis (Neo4j)</td>
                  <td className="py-3 px-4">bloodhound.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">falco</td>
                  <td className="py-3 px-4 font-sans text-sm">Kernel-level runtime threat detection using eBPF</td>
                  <td className="py-3 px-4">DaemonSet / GRPC</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Architecture */}
        <section id="architecture" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Architecture</h2>
          <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-xl space-y-4">
            <p className="text-slate-300">
              Vigilante provides dual user interfaces operating against an identical set of 32 security engines and
              Kubernetes cluster instances (<strong>k3d</strong> or <strong>k3s</strong>).
            </p>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto border border-slate-800">
              <pre>{`+-----------------------------------------------------------------------------------------+
|                                    HOST WORKSTATION                                     |
|  Next.js Web Portal (apps/web)  <=============>  React Ink TUI (apps/ink: pnpm cli)     |
|                                       ||                                                |
|             Vigilante Security Engine (packages/vigilante_lib: 32 Engines)               |
|             • CASL RBAC/ABAC Authz Store (~/.vigilante/authz.yaml)                     |
|             • CTF Tournament & Solver Workbench (De Bruijn, JWT, RSA, XOR)              |
|             • SOAR Active Containment, Deception Mesh, & Evidence Vault                 |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                        KUBERNETES RUNTIME: k3d or Native k3s                            |
|  Traefik Ingress: *.vigilante.local (Zero-config mkcert TLS & /etc/hosts)               |
|    |--> kCTF Cyber Range (nsjail TCP & HTTP Ephemeral Sandboxes)                        |
|    |--> Vigil SOC (Web + Backend + Bifrost Gateway)                                     |
|    |--> OpenSearch SIEM + Wazuh XDR + OpenVAS Scanner                                   |
|    |--> Falco eBPF Kernel DaemonSet & Suricata / Zeek Network Sensors                   |
+-----------------------------------------------------------------------------------------+`}</pre>
            </div>
          </div>
        </section>

        {/* Quickstart */}
        <section id="quickstart" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Quickstart</h2>
          <div className="space-y-4 text-slate-300">
            <p>Clone the repository and provision your environment using the automated bootstrapper or direct CLI:</p>
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg font-mono text-xs space-y-3">
              <div>
                <span className="text-slate-500"># 1. Automated Bootstrap (Debian / Ubuntu / Kali)</span>
                <div className="text-emerald-400">sudo ./bootstrap.sh</div>
              </div>
              <div>
                <span className="text-slate-500"># 2. Or manual install</span>
                <div className="text-emerald-400">pnpm install && pnpm link --global</div>
              </div>
              <div>
                <span className="text-slate-500"># 3. Launch Next.js Web Operations Portal</span>
                <div className="text-emerald-400">pnpm dev:web  # Open http://localhost:3000</div>
              </div>
              <div>
                <span className="text-slate-500"># 4. Launch React Ink Terminal TUI</span>
                <div className="text-emerald-400">pnpm cli       # or: vigilante</div>
              </div>
              <div>
                <span className="text-slate-500"># 5. Direct CTF Player Field Manual & Arena</span>
                <div className="text-emerald-400">http://localhost:3000/event  # or: vigilante ctf</div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800 mt-20 py-8 text-center text-sm text-slate-500">
        <p>Vigilante Security Orchestration & Cyber Range Platform &copy; 2026. Built by DeployCoop.</p>
      </footer>
    </div>
  );
}
