"use strict";exports.id=510,exports.ids=[510],exports.modules={9510:(e,i,t)=>{t.d(i,{C6:()=>E,Fd:()=>L,Fu:()=>D,ME:()=>R,Nh:()=>_,OI:()=>d,Oh:()=>F,_V:()=>C,aq:()=>b,m8:()=>M,mr:()=>m,pf:()=>$});var n=t(3977),r=t(7561),a=t(612),o=t(9411),s=t(893),c=t(5518);function l(){let e=process.env.XDG_CONFIG_HOME||o.join(a.homedir(),".config"),i=o.join(e,".vigilante"),t=o.join(e,"vigilante");return r.existsSync(i)?i:(r.existsSync(t),t)}function u(){return o.join(l(),"config.yaml")}function d(){return o.join(l(),"values")}function m(){return o.join(l(),"nmaps")}function y(){return o.join(l(),"oobscans")}function f(){return o.join(l(),"recon")}function g(){return o.join(l(),"nuclei")}function v(){return o.join(l(),"trivy")}function p(){return o.join(l(),"kubeaudit")}function h(){return o.join(l(),"netexec")}function k(){return o.join(l(),"zap")}function S(){return o.join(l(),"pcap")}function b(){return o.join(l(),"dossiers")}function w(){return o.join(l(),"bloodhound")}function I(){return o.join(l(),"cti")}function O(){return o.join(l(),"canary")}function x(){return o.join(l(),"carved")}function j(){return o.join(l(),"datalake")}function P(){return o.join(l(),"wasm")}function A(){return o.join(l(),"purpleteam")}function G(){return o.join(l(),"evidence")}function E(){return o.join(l(),"playbooks")}function C(){return o.join(l(),"instances")}function D(e="vigilante-dev"){return o.join(C(),$(e||"vigilante-dev"))}function _(e="vigilante-dev"){return o.join(D(e),"values")}function $(e){return e?String(e).trim().replace(/\//g,"_").replace(/[^a-zA-Z0-9._-]/g,"_"):"unknown"}function M(e,i){let t=$(e||"local_network"),n=$(i||"127.0.0.1");return o.join(G(),t,n)}let K={theme:{name:"default",colors:{primary:"cyan",secondary:"magenta",accent:"yellow",success:"green",warning:"yellow",error:"red",info:"blue",muted:"gray",border:"cyan",text:"white",header:"cyan",selectedBg:"gray",selectedText:"yellow",banner:"magenta"}},defaults:{domain:"vigilante.local",clusterName:"vigilante-dev",ip:"127.0.0.1",valuesDir:""},hostr:{enabled:!0,autoSyncOnUp:!0,autoCleanOnDown:!0},gpg:{enabled:!1,keyId:"",autoSign:!0,detached:!0,armor:!0,gnupgHome:""},modules:{vigilLocal:{chartPath:"/home/djehauti/git/vigil/infra/helm/vigil"},kctf:{enabled:!1,challengePortRange:"30000-32767",powDifficulty:0},openvas:{enabled:!1,feedRelease:"24.10",defaultProfile:"full-and-fast"},wazuh:{enabled:!1,version:"4.14.7"},flamingo:{enabled:!1,protocols:"ssh,snmp,ldap,http,dns,ftp"},oobscan:{enabled:!0,defaultProfile:"standard",disableLogins:!1,linkLocalWait:"3s"},nuclei:{enabled:!0,concurrency:25,rateLimit:150,severity:"critical,high,medium"},recon:{enabled:!0,naabuRate:1e3},trivy:{enabled:!0,severity:"CRITICAL,HIGH,MEDIUM"},kubeaudit:{enabled:!0},netexec:{enabled:!0},falco:{enabled:!1},suricata:{enabled:!1},zeek:{enabled:!1},zap:{enabled:!1},bloodhound:{enabled:!1}},behavior:{autoWatchPods:!0,podsPollIntervalMs:2e3}},N=`# ==============================================================================
# Vigilante Configuration & Theming
# Location: $XDG_CONFIG_HOME/vigilante/config.yaml
# ==============================================================================

# Active Theme Configuration
# Predefined themes: default, cyberpunk, dracula, nord, matrix, monokai
theme:
  name: "default"
  
  # Custom color overrides (ANSI color names: cyan, magenta, yellow, green, red, blue, gray, white)
  colors:
    primary: "cyan"
    secondary: "magenta"
    accent: "yellow"
    success: "green"
    warning: "yellow"
    error: "red"
    info: "blue"
    muted: "gray"
    border: "cyan"
    text: "white"
    header: "cyan"
    selectedBg: "gray"
    selectedText: "yellow"
    banner: "magenta"

# Default CLI & Cluster Settings
defaults:
  domain: "vigilante.local"
  clusterName: "vigilante-dev"
  ip: "127.0.0.1"
  # Optional custom values directory (defaults to $XDG_CONFIG_HOME/vigilante/values)
  valuesDir: ""

# Host Resolution (hostr) Settings
# Controls automatic /etc/hosts management during cluster up/down workflows.
# Note: Even when disabled, manual 'vigilante hostr' or pressing [h] remains available.
hostr:
  enabled: true         # Set to false to disable all automatic /etc/hosts modifications
  autoSyncOnUp: true    # Automatically sync local domain mappings on 'vigilante up'
  autoCleanOnDown: true # Automatically clean up domain mappings on 'vigilante down'

# GPG Digital Signature & Evidence Integrity
# Signs evidence artifacts, scans, and reports at creation time for non-repudiation
gpg:
  enabled: false        # Set to true to enable cryptographic signing
  keyId: ""             # GPG Key ID, fingerprint, or email (e.g., security@vigilante.local)
  autoSign: true        # Automatically sign files upon creation
  detached: true        # Generate detached ASCII-armored signatures (.asc)
  gnupgHome: ""         # Optional custom GNUPGHOME directory path

# AI Assistant & Security Forensics Analyst (Ollama, Claude, ChatGPT, Gemini, DeepSeek, Groq, OpenRouter)
# Ollama works out-of-the-box first and foremost for local, private model inference.
ai:
  defaultProvider: "ollama"         # Default provider: ollama, anthropic, openai, gemini, deepseek, groq, openrouter
  ollama:
    host: "http://localhost:11434"   # Local Ollama server address (or $OLLAMA_HOST)
    defaultModel: "llama3.2"         # Default local model (auto-detected from ollama list)
    temperature: 0.2
  anthropic:
    apiKey: ""                       # Anthropic API Key (or set $ANTHROPIC_API_KEY)
    defaultModel: "claude-3-5-sonnet-20241022"
    temperature: 0.2
  openai:
    apiKey: ""                       # OpenAI API Key (or set $OPENAI_API_KEY)
    defaultModel: "gpt-4o"
    temperature: 0.2
  gemini:
    apiKey: ""                       # Google Gemini API Key (or set $GEMINI_API_KEY / $GOOGLE_API_KEY)
    defaultModel: "gemini-2.0-flash"
    temperature: 0.2
  deepseek:
    apiKey: ""                       # DeepSeek API Key (or set $DEEPSEEK_API_KEY)
    defaultModel: "deepseek-chat"
    temperature: 0.2
  groq:
    apiKey: ""                       # Groq API Key (or set $GROQ_API_KEY)
    defaultModel: "llama-3.3-70b-versatile"
    temperature: 0.2
  openrouter:
    apiKey: ""                       # OpenRouter API Key (or set $OPENROUTER_API_KEY)
    defaultModel: "anthropic/claude-3.5-sonnet"
    temperature: 0.2

# Modular Package Configuration & Local Repositories
modules:
  vigilLocal:
    # Path to local checkout of Vigil SOC repository helm chart
    chartPath: "/home/djehauti/git/vigil/infra/helm/vigil"
  flamingo:
    enabled: false
    protocols: "ssh,snmp,ldap,http,dns,ftp"
  falco:
    enabled: false
  suricata:
    enabled: false
  zeek:
    enabled: false
  zap:
    enabled: false
  bloodhound:
    enabled: false
  nuclei:
    enabled: true
    concurrency: 25
    rateLimit: 150
  trivy:
    enabled: true
    severity: "CRITICAL,HIGH,MEDIUM"
  recon:
    enabled: true

# Runtime Monitor Behavior
behavior:
  autoWatchPods: true
  podsPollIntervalMs: 2000
`;async function L(){let e=l(),i=d(),t=m(),r=y(),a=f(),s=g(),D=v(),_=p(),$=h(),M=k(),K=S(),L=b(),R=w(),F=o.join(l(),"containments"),H=I(),z=O(),T=x(),U=j(),Y=P(),q=A(),B=G(),W=E(),V=C(),X=u(),J=!1;try{await n.mkdir(i,{recursive:!0}),await n.mkdir(t,{recursive:!0}),await n.mkdir(r,{recursive:!0}),await n.mkdir(a,{recursive:!0}),await n.mkdir(s,{recursive:!0}),await n.mkdir(D,{recursive:!0}),await n.mkdir(_,{recursive:!0}),await n.mkdir($,{recursive:!0}),await n.mkdir(M,{recursive:!0}),await n.mkdir(K,{recursive:!0}),await n.mkdir(L,{recursive:!0}),await n.mkdir(R,{recursive:!0}),await n.mkdir(F,{recursive:!0}),await n.mkdir(H,{recursive:!0}),await n.mkdir(z,{recursive:!0}),await n.mkdir(T,{recursive:!0}),await n.mkdir(U,{recursive:!0}),await n.mkdir(Y,{recursive:!0}),await n.mkdir(q,{recursive:!0}),await n.mkdir(B,{recursive:!0}),await n.mkdir(W,{recursive:!0}),await n.mkdir(V,{recursive:!0});try{await n.access(X)}catch{await n.writeFile(X,N,"utf8"),J=!0,c.k.info("CONFIG",`Initialized default config.yaml at ${X}`)}}catch(e){c.k.warn("CONFIG",`Failed to ensure config directories: ${e.message}`)}return{configDir:e,valuesDir:i,nmapsDir:t,oobscansDir:r,reconDir:a,nucleiDir:s,trivyDir:D,kubeauditDir:_,netexecDir:$,zapDir:M,pcapDir:K,dossiersDir:L,bloodhoundDir:R,containmentsDir:F,ctiDir:H,canaryDir:z,carveDir:T,datalakeDir:U,wasmDir:Y,purpleDir:q,evidenceDir:B,playbooksDir:W,instancesDir:V,configFile:X,created:J}}function R(){!function(){l();let e=d(),i=m(),t=y(),n=f(),a=g(),o=v(),s=p(),c=h(),D=k(),_=S(),$=b(),M=w(),K=I(),L=O(),R=x(),F=j(),H=P(),z=A(),T=G(),U=E(),Y=C(),q=u();try{r.existsSync(e)||r.mkdirSync(e,{recursive:!0}),r.existsSync(i)||r.mkdirSync(i,{recursive:!0}),r.existsSync(t)||r.mkdirSync(t,{recursive:!0}),r.existsSync(n)||r.mkdirSync(n,{recursive:!0}),r.existsSync(a)||r.mkdirSync(a,{recursive:!0}),r.existsSync(o)||r.mkdirSync(o,{recursive:!0}),r.existsSync(s)||r.mkdirSync(s,{recursive:!0}),r.existsSync(c)||r.mkdirSync(c,{recursive:!0}),r.existsSync(D)||r.mkdirSync(D,{recursive:!0}),r.existsSync(_)||r.mkdirSync(_,{recursive:!0}),r.existsSync($)||r.mkdirSync($,{recursive:!0}),r.existsSync(M)||r.mkdirSync(M,{recursive:!0}),r.existsSync(containmentsDir)||r.mkdirSync(containmentsDir,{recursive:!0}),r.existsSync(K)||r.mkdirSync(K,{recursive:!0}),r.existsSync(L)||r.mkdirSync(L,{recursive:!0}),r.existsSync(R)||r.mkdirSync(R,{recursive:!0}),r.existsSync(F)||r.mkdirSync(F,{recursive:!0}),r.existsSync(H)||r.mkdirSync(H,{recursive:!0}),r.existsSync(z)||r.mkdirSync(z,{recursive:!0}),r.existsSync(T)||r.mkdirSync(T,{recursive:!0}),r.existsSync(U)||r.mkdirSync(U,{recursive:!0}),r.existsSync(Y)||r.mkdirSync(Y,{recursive:!0}),r.existsSync(q)||r.writeFileSync(q,N,"utf8")}catch(e){}}();let e=u();try{if(r.existsSync(e)){let i=r.readFileSync(e,"utf8"),t=(0,s.zD)(i);if(t&&"object"==typeof t)return{...K,...t,theme:{name:t.theme?.name||K.theme.name,colors:{...t.theme?.colors||{}}},defaults:{...K.defaults,...t.defaults||{}},hostr:{...K.hostr,...t.hostr||{}},gpg:{...K.gpg,...t.gpg||{}},modules:{...K.modules,...t.modules||{},vigilLocal:{...K.modules?.vigilLocal,...t.modules?.vigilLocal||{}},kctf:{...K.modules?.kctf,...t.modules?.kctf||{}},openvas:{...K.modules?.openvas,...t.modules?.openvas||{}},wazuh:{...K.modules?.wazuh,...t.modules?.wazuh||{}}},behavior:{...K.behavior,...t.behavior||{}}}}}catch(i){c.k.warn("CONFIG",`Could not parse ${e}: ${i.message}. Using defaults.`)}return{...K}}async function F(e){let i=u(),t=l();await n.mkdir(t,{recursive:!0});let r=(0,s.$w)(e,{indent:2});await n.writeFile(i,r,"utf8"),c.k.info("CONFIG",`Saved configuration to ${i}`)}},5518:(e,i,t)=>{t.d(i,{k:()=>c});var n=t(7561),r=t(9411),a=t(612);let o=r.join(a.tmpdir(),".vigilante.log");function s(e,i,t,r=null){try{let a=new Date().toISOString(),s=`[${a}] [${e.padEnd(5)}] [${i}] ${t}`;if(null!=r){if(r instanceof Error)s+=`
  Stack: ${r.stack||r.message}`;else if("object"==typeof r)try{s+=`
  Data: ${JSON.stringify(r)}`}catch{s+=`
  Data: [Circular or unstringifiable object]`}else s+=`
  Details: ${r}`}s+="\n",n.appendFileSync(o,s,"utf8")}catch{}}let c={debug:(e,i,t)=>s("DEBUG",e,i,t),info:(e,i,t)=>s("INFO",e,i,t),warn:(e,i,t)=>s("WARN",e,i,t),error:(e,i,t)=>s("ERROR",e,i,t),getLogPath:()=>o}}};