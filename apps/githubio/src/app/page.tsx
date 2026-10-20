import React from 'react';
import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-emerald-500 selection:text-slate-950">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <img
            src="/vigilante/images/vigilante-badge.jpg"
            alt="Vigilante Emblem"
            className="w-10 h-10 rounded-full border-2 border-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.5)] object-cover"
          />
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black tracking-wider text-emerald-400">VIGILANTE</span>
              <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-mono">v0.6.0</span>
            </div>
            <span className="text-[10px] font-mono tracking-widest text-cyan-400 uppercase">Cyber Defense · CTF Range · eBPF Ops</span>
          </div>
        </div>
        <div className="flex items-center space-x-6 text-sm text-slate-400">
          <Link href="/docs" className="hover:text-emerald-400 transition">Documentation</Link>
          <Link href="/docs/ctf" className="hover:text-emerald-400 transition">CTF Cyber Range</Link>
          <Link href="/docs/web-authz" className="hover:text-emerald-400 transition">Web Portal & Authz</Link>
          <a href="#dossier" className="hover:text-emerald-400 transition">Operative</a>
          <a href="#features" className="hover:text-emerald-400 transition">Capabilities</a>
          <a href="#modules" className="hover:text-emerald-400 transition">Modules</a>
          <a href="#quickstart" className="hover:text-emerald-400 transition">Quickstart</a>
          <a href="https://github.com/DeployCoop/vigilante" target="_blank" rel="noreferrer" className="text-emerald-400 hover:text-emerald-300 transition font-medium">GitHub →</a>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-12 space-y-20">
        {/* Hero Section with Cyberpunk Character Split */}
        <section className="grid lg:grid-cols-12 gap-8 items-center pt-4 pb-12 border-b border-slate-800">
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
              Autonomous Recon · eBPF Kernel Probing · CTF Cyber Range
            </div>

            <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight">
              Infiltrate, Sniff & Defend with <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-sky-400">Vigilante</span>
            </h1>

            <p className="text-lg text-slate-300 leading-relaxed">
              Equipped like an elite cyberpunk rogue: directional RF/SDR sniffers, loss-less eBPF packet carvers,
              dynamic honeytoken deception meshes, and automated Google kCTF tournament arenas—engineered natively for <strong>k3d</strong> and bare-metal <strong>k3s</strong>.
            </p>

            <div className="flex flex-wrap gap-4 pt-2">
              <a href="#quickstart" className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-6 py-3 rounded-lg shadow-[0_0_20px_rgba(16,185,129,0.35)] transition">
                ⚡ Deploy Vigilante
              </a>
              <Link href="/docs/ctf" className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-6 py-3 rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.3)] transition">
                🚩 Enter CTF Arena →
              </Link>
              <Link href="/docs/getting-started" className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold px-6 py-3 rounded-lg transition">
                📖 Manual
              </Link>
            </div>

            {/* Quick Status Bar */}
            <div className="grid grid-cols-3 gap-3 pt-4 border-t border-slate-800/80 font-mono text-xs text-slate-400">
              <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">RUNTIME ENGINE</div>
                <div className="text-emerald-400 font-bold">k3d / Native k3s</div>
              </div>
              <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">DUAL PARITY</div>
                <div className="text-cyan-400 font-bold">Web 28v ⟷ Ink TUI</div>
              </div>
              <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">AUTHORIZATION</div>
                <div className="text-purple-400 font-bold">CASL RBAC / ABAC</div>
              </div>
            </div>
          </div>

          {/* Rogue Character Display Card */}
          <div className="lg:col-span-5 relative group">
            <div className="relative rounded-2xl overflow-hidden border-2 border-emerald-500/50 shadow-[0_0_35px_rgba(16,185,129,0.25)] bg-slate-900">
              <img
                src="/vigilante/images/vigilante-rogue-operative.jpg"
                alt="Vigilante Cyberpunk Rogue Operative"
                className="w-full h-auto object-cover group-hover:scale-105 transition duration-700"
              />

              {/* Holographic Overlay Badges */}
              <div className="absolute top-3 left-3 bg-slate-950/85 backdrop-blur border border-emerald-500/40 px-3 py-1 rounded-md text-[11px] font-mono text-emerald-300 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>OPERATIVE: VIGILANTE-01</span>
              </div>

              <div className="absolute top-3 right-3 bg-slate-950/85 backdrop-blur border border-cyan-500/40 px-2.5 py-1 rounded-md text-[10px] font-mono text-cyan-300 uppercase">
                PROMISCUOUS: ON
              </div>

              <div className="absolute bottom-0 inset-x-0 bg-gradient-to-t from-slate-950 via-slate-950/90 to-transparent p-4 space-y-2 border-t border-slate-800/80">
                <div className="flex justify-between items-center text-xs font-mono text-slate-300">
                  <span className="text-emerald-400 font-bold">LOADOUT: YAGI SDR + eBPF DECK</span>
                  <span className="text-slate-500">CLASS: NET-ROGUE</span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2">
                  Specialized in deep packet inspection, lateral movement tracking, wireless signal triangulation, and ephemeral challenge cracking.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Operative Dossier & Gear Showcase */}
        <section id="dossier" className="space-y-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-l-4 border-cyan-400 pl-4">
            <div>
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">Tactical Inventory</span>
              <h2 className="text-3xl font-bold text-white">Operative Dossier: Surveillance & Infiltration Gear</h2>
            </div>
            <p className="text-sm text-slate-400 max-w-md">
              Vigilante combines the stealth of an offensive network infiltrator with the rigor of an enterprise SOC engineer.
            </p>
          </div>

          {/* Panoramic Action Banner */}
          <div className="relative rounded-2xl overflow-hidden border border-slate-800 shadow-[0_0_40px_rgba(6,182,212,0.15)] group">
            <img
              src="/vigilante/images/vigilante-rooftop-ops.jpg"
              alt="Vigilante Rooftop Cyber Range Operations"
              className="w-full h-72 sm:h-96 object-cover object-center group-hover:scale-[1.02] transition duration-700"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-950/40 to-transparent flex flex-col justify-end p-6 sm:p-8">
              <div className="max-w-2xl space-y-2">
                <span className="inline-block px-2.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-xs font-mono">
                  FIELD OPS · SECTOR 7 OVERWATCH
                </span>
                <h3 className="text-2xl sm:text-3xl font-black text-white">
                  Autonomous Tactical Range & Packet Interception
                </h3>
                <p className="text-sm text-slate-300">
                  Deploying multi-channel hardware sniffers, real-time Fourier transform beaconing detectors, and sandboxed attack chains across local cluster networks.
                </p>
              </div>
            </div>
          </div>

          {/* 3-Pillar Gear Breakdown */}
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-slate-900/80 border border-emerald-500/30 p-6 rounded-xl space-y-4 hover:border-emerald-500/60 transition">
              <div className="w-12 h-12 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-2xl text-emerald-400">
                📡
              </div>
              <h3 className="text-xl font-bold text-white">Sniffing & Spectrum Arsenal</h3>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400">▸</span>
                  <span><strong>Directional RF/SDR Yagi</strong>: Passive wireless spectrum harvesting & rogue AP discovery.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400">▸</span>
                  <span><strong>Kernel eBPF Ring Buffer</strong>: Zero-overhead packet carving for HTTP, SMB, and TLS flows.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400">▸</span>
                  <span><strong>Shannon Entropy Scanner</strong>: Detects encrypted payload spikes & covert DNS exfiltration.</span>
                </li>
              </ul>
            </div>

            <div className="bg-slate-900/80 border border-cyan-500/30 p-6 rounded-xl space-y-4 hover:border-cyan-500/60 transition">
              <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-2xl text-cyan-400">
                ⚡
              </div>
              <h3 className="text-xl font-bold text-white">Detection & Deception Rig</h3>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">▸</span>
                  <span><strong>Deception Canary Mesh</strong>: Plant decoy ServiceAccounts, fake cloud secrets, and honeynets.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">▸</span>
                  <span><strong>DFT Beaconing Periodicity</strong>: Fourier transform spectral analysis flags C2 heartbeat jitter.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">▸</span>
                  <span><strong>Falco eBPF Threat Sensor</strong>: Real-time container escape & fileless memfd execution traps.</span>
                </li>
              </ul>
            </div>

            <div className="bg-slate-900/80 border border-purple-500/30 p-6 rounded-xl space-y-4 hover:border-purple-500/60 transition">
              <div className="w-12 h-12 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-2xl text-purple-400">
                ⚔️
              </div>
              <h3 className="text-xl font-bold text-white">Infiltration & CTF Solver Deck</h3>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-purple-400">▸</span>
                  <span><strong>Cyclic Buffer Engine</strong>: De Bruijn pattern generation & stack crash offset calculations.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-purple-400">▸</span>
                  <span><strong>Cryptographic Factorizer</strong>: Wiener continued fractions, Fermat, and trial division for RSA.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-purple-400">▸</span>
                  <span><strong>ROP Gadget Harvester</strong>: Rapid x86_64 gadget discovery and stack alignment verification.</span>
                </li>
              </ul>
            </div>
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
                Next.js 14 Web Portal (<code>apps/web</code>) mirroring all 28 terminal security panes: NastyMap Recon,
                BattleStation live SOC, PCAP Forensics, Packet Sniffer, Kernel eBPF Lineage, and Shift-Left CI/CD Audit.
              </p>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl hover:border-slate-700 transition space-y-2">
              <div className="text-amber-400 text-xl font-bold">🔐 Enterprise CASL RBAC / ABAC Security</div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Fail-closed authorization engine (<code>~/.config/vigilante/authz.json</code>) with scoped grants, OIDC SSO,
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
|             • CASL RBAC/ABAC Authz Store (~/.config/vigilante/authz.json)               |
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
