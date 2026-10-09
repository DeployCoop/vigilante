import React from 'react';

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="text-2xl font-black tracking-wider text-emerald-400">VIGILANTE</span>
          <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-mono">v0.1.0</span>
        </div>
        <div className="flex items-center space-x-6 text-sm text-slate-400">
          <a href="/docs" className="hover:text-emerald-400 transition">Documentation</a>
          <a href="#features" className="hover:text-emerald-400 transition">Features</a>
          <a href="#modules" className="hover:text-emerald-400 transition">Modules</a>
          <a href="#architecture" className="hover:text-emerald-400 transition">Architecture</a>
          <a href="#quickstart" className="hover:text-emerald-400 transition">Quickstart</a>
          <a href="https://github.com/DeployCoop/vigilante" target="_blank" rel="noreferrer" className="text-emerald-400 hover:text-emerald-300 transition font-medium">GitHub →</a>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-12 space-y-16">
        {/* Hero */}
        <section className="text-center space-y-6 pt-8 pb-12 border-b border-slate-800">
          <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight text-white">
            Cybersecurity <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">Orchestration</span> Platform
          </h1>
          <p className="max-w-3xl mx-auto text-lg sm:text-xl text-slate-400">
            Next-generation automated security range, AI-native autonomous SOC, and threat simulation mesh built natively for local Kubernetes (k3d).
          </p>
          <div className="flex justify-center gap-4 pt-4">
            <a href="#quickstart" className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold px-6 py-3 rounded-lg shadow-lg hover:shadow-emerald-500/20 transition">
              Get Started
            </a>
            <a href="/docs" className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold px-6 py-3 rounded-lg transition">
              Read Docs
            </a>
          </div>
        </section>

        {/* Overview */}
        <section id="features" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Platform Capabilities</h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-emerald-400 text-xl font-bold mb-2">🤖 Vigil SOC & Bifrost Gateway</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Autonomous, agentic AI investigation engine with native LLM gateway routing, ReAct loop analysis, and automated NIST incident containment.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-cyan-400 text-xl font-bold mb-2">🛡️ Full SIEM & XDR Mesh</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Integrated OpenSearch analytics, Wazuh manager & indexer, Suricata network IDS/IPS, and Zeek protocol metadata inspection.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-purple-400 text-xl font-bold mb-2">🚩 Cyber Range & CTF Tools</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Pre-configured Google kCTF, CTFd, BloodHound CE with Neo4j graph attack paths, and ephemeral target sandbox orchestration.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-amber-400 text-xl font-bold mb-2">🔍 Vulnerability Dossier</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Consolidated continuous scanning pipeline integrating Greenbone OpenVAS/GVM, Aqua Trivy, and ProjectDiscovery Nuclei.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-rose-400 text-xl font-bold mb-2">🐝 Deception & HoneyMesh</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Canary tokens, synthetic ServiceAccounts, tripwires, and autonomous deception meshes delivering real-time telemetry upon unauthorized access.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition">
              <div className="text-blue-400 text-xl font-bold mb-2">⚡ eBPF Kernel Lineage</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Falco eBPF daemonsets capturing deep process ancestry, container breakout attempts, and live syscall behavioral anomalies.
              </p>
            </div>
          </div>
        </section>

        {/* Modules */}
        <section id="modules" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Supported Modules</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border border-slate-800 rounded-lg overflow-hidden">
              <thead className="bg-slate-900 text-slate-300 uppercase font-mono text-xs">
                <tr>
                  <th className="py-3 px-4">Module</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Default Port / Host</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-400">
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">vigil-soc</td>
                  <td className="py-3 px-4">Autonomous AI SOC, Bifrost LLM gateway, PostgreSQL & Redis</td>
                  <td className="py-3 px-4 font-mono text-xs">vigil.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">opensearch</td>
                  <td className="py-3 px-4">Distributed SIEM engine & OpenSearch Dashboards</td>
                  <td className="py-3 px-4 font-mono text-xs">opensearch.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">openvas</td>
                  <td className="py-3 px-4">Greenbone Community Edition (GVM) vulnerability scanner</td>
                  <td className="py-3 px-4 font-mono text-xs">openvas.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">wazuh</td>
                  <td className="py-3 px-4">Host-based intrusion detection (HIDS), agent manager, indexer</td>
                  <td className="py-3 px-4 font-mono text-xs">wazuh.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">bloodhound</td>
                  <td className="py-3 px-4">Active Directory & Azure attack path analysis (Neo4j)</td>
                  <td className="py-3 px-4 font-mono text-xs">bloodhound.vigilante.local</td>
                </tr>
                <tr className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 font-semibold text-emerald-400">falco</td>
                  <td className="py-3 px-4">Kernel-level runtime threat detection using eBPF</td>
                  <td className="py-3 px-4 font-mono text-xs">DaemonSet / GRPC</td>
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
              Vigilante manages an isolated local <strong>k3d</strong> Kubernetes cluster. Ingress routing maps DNS wildcard entries (<code className="text-emerald-400">*.vigilante.local</code>) directly into cluster ingress services via dynamic <code className="text-emerald-400">/etc/hosts</code> synchronization.
            </p>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto border border-slate-800">
              <pre>{`+-------------------------------------------------------------------------+
|                              HOST WORKSTATION                           |
|  CLI / TUI (Ink)  --->  Vigilante Orchestrator  --->  Helm / K8s Client |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                        K3D ISOLATED CLUSTER                             |
|  Traefik Ingress: *.vigilante.local                                     |
|    |--> Vigil SOC (Web + Backend + Bifrost Gateway)                     |
|    |--> OpenSearch + Dashboards                                         |
|    |--> OpenVAS / GVM Security Scanner                                  |
|    |--> Wazuh SIEM & HIDS Manager                                       |
|    |--> Falco eBPF Kernel Monitor                                       |
|    \\--> Deception Mesh & Cyber Range Challenges                         |
+-------------------------------------------------------------------------+`}</pre>
            </div>
          </div>
        </section>

        {/* Quickstart */}
        <section id="quickstart" className="space-y-6">
          <h2 className="text-3xl font-bold text-white border-l-4 border-emerald-400 pl-4">Quickstart</h2>
          <div className="space-y-4 text-slate-300">
            <p>Clone the repository and launch the full security stack with simple CLI commands:</p>
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg font-mono text-sm space-y-3">
              <div>
                <span className="text-slate-500"># 1. Clone repository</span>
                <div className="text-emerald-400">git clone https://github.com/DeployCoop/vigilante.git && cd vigilante</div>
              </div>
              <div>
                <span className="text-slate-500"># 2. Install workspace dependencies</span>
                <div className="text-emerald-400">pnpm install</div>
              </div>
              <div>
                <span className="text-slate-500"># 3. Launch interactive Terminal UI (Ink)</span>
                <div className="text-emerald-400">pnpm cli</div>
              </div>
              <div>
                <span className="text-slate-500"># Or provision cluster directly</span>
                <div className="text-emerald-400">./bin/vigilante.js start</div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800 mt-20 py-8 text-center text-sm text-slate-500">
        <p>Vigilante Security Orchestration Platform &copy; 2026. Built by DeployCoop.</p>
      </footer>
    </div>
  );
}
