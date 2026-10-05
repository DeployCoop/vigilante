"use strict";exports.id=527,exports.ids=[527],exports.modules={7527:(e,t,a)=>{a.a(e,async(e,n)=>{try{a.d(t,{QO:()=>m,bO:()=>l,kL:()=>d,lp:()=>p,sQ:()=>c});var i=a(1167),r=a(6005);a(7503),a(8849);var o=a(5518),s=e([i]);i=(s.then?(await s)():s)[0];let p=[{id:"web",name:"Web Exploitation",icon:"\uD83C\uDF10",color:"blue",description:"HTTP/HTTPS vulnerabilities, auth bypass, injection & token flaws"},{id:"pwn",name:"Binary Exploitation (nsjail)",icon:"\uD83D\uDCA3",color:"red",description:"Sandboxed TCP ELF binaries running under nsjail process isolation"},{id:"crypto",name:"Cryptography",icon:"\uD83D\uDD11",color:"yellow",description:"Math, block ciphers, padding oracles & key exchange puzzles"},{id:"rev",name:"Reverse Engineering",icon:"\uD83D\uDD04",color:"magenta",description:"Static/dynamic binary inspection, crackmes & decompilation"},{id:"forensics",name:"Digital Forensics",icon:"\uD83D\uDD0E",color:"cyan",description:"PCAP packet captures, disk images, memory dumps & log analysis"},{id:"misc",name:"Miscellaneous & Jails",icon:"\uD83E\uDDE9",color:"green",description:"Python/bash jail sandboxes, esoteric challenges & logic puzzles"}],m=[{id:"web-flag-leak",name:"Flag Leak Portal",category:"web",difficulty:"Easy",port:8080,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{kctf_w3b_1nj3ct10n_succ3ss}",description:"Nginx static service with hidden administrative headers and debug endpoints.",image:"nginx:alpine",hints:["Inspect HTTP response headers and look for non-standard administrative parameters."],containerConfig:{ports:[80],env:[{name:"CHALLENGE_NAME",value:"Flag Leak Portal"},{name:"FLAG",value:"VIGILANTE{kctf_w3b_1nj3ct10n_succ3ss}"}]}},{id:"web-auth-bypass",name:"JWT Auth Bypass Service",category:"web",difficulty:"Medium",port:8081,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{jwt_n0n3_4lg0r1thm_byp4ss}",description:"Web API accepting bearer tokens with algorithm misconfiguration flaws.",image:"busybox:latest",hints:["Test the algorithm header parameter or forge an unverified signature token."],containerConfig:{ports:[80],command:["sh","-c"],args:['while true; do echo -e "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\"service\\":\\"AuthGate\\",\\"status\\":\\"ready\\",\\"tip\\":\\"Provide Bearer token\\"}" | nc -lp 80; done']}},{id:"web-sqli-portal",name:"Employee Directory Portal",category:"web",difficulty:"Hard",port:8082,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{un10n_s3l3ct_fl4g_dump3d}",description:"Simulated backend directory search interface with structured database queries.",image:"busybox:latest",hints:["Probe the search parameter using boolean-based or union-based inputs."],containerConfig:{ports:[80],command:["sh","-c"],args:['while true; do echo -e "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>Employee Directory</h1><p>Search query required</p>" | nc -lp 80; done']}},{id:"pwn-nsjail-echo",name:"nsjail Echo Service",category:"pwn",difficulty:"Easy",port:31337,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{kctf_nsj41l_pwn_fl4g_c4ptur3d}",description:"Isolated network socket echoing contestant input running inside nsjail container.",image:"busybox:latest",hints:["Connect via netcat and probe how the input stream is reflected back."],containerConfig:{ports:[31337],command:["sh","-c"],args:['while true; do echo -e "=== kCTF nsjail Protected Sandbox ===\\nTarget: echo service\\nFlag is stored in memory\\nInput: " | nc -lp 31337 -e sh -c \'echo "FLAG: VIGILANTE{kctf_nsj41l_pwn_fl4g_c4ptur3d}"\'; done']}},{id:"pwn-rop-bof",name:"Buffer Overflow & ROP Arena",category:"pwn",difficulty:"Medium",port:31338,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{r3t_2_w1n_c4ll_ch41n}",description:"TCP service vulnerable to standard stack smashing and control flow redirection.",image:"busybox:latest",hints:["Determine the offset between the stack buffer and the saved return pointer."],containerConfig:{ports:[31338],command:["sh","-c"],args:['while true; do echo -e "=== ROP & Stack Smashing Arena ===\\nBuffer: 64 bytes\\nReturn address hijackable\\nInput: " | nc -lp 31338 -e sh -c \'echo "FLAG: VIGILANTE{r3t_2_w1n_c4ll_ch41n}"\'; done']}},{id:"pwn-heap-sandbox",name:"Heap Allocator Jail",category:"pwn",difficulty:"Hard",port:31339,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{tcache_p01s0n_pr1m1t1v3}",description:"Interactive chunk allocator challenge testing use-after-free and double-free handling.",image:"busybox:latest",hints:["Observe allocation order and chunk reuse behavior after deletion."],containerConfig:{ports:[31339],command:["sh","-c"],args:['while true; do echo -e "=== Heap Allocation Console ===\\nCommands: [1] Alloc [2] Free [3] View [4] Exit\\nChoice: " | nc -lp 31339 -e sh -c \'echo "FLAG: VIGILANTE{tcache_p01s0n_pr1m1t1v3}"\'; done']}},{id:"crypto-oracle-rsa",name:"RSA Parity Oracle",category:"crypto",difficulty:"Medium",port:20001,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{lsb_0r4cl3_b1n4ry_s34rch}",description:"Interactive TCP service providing least-significant-bit parity feedback for ciphertexts.",image:"busybox:latest",hints:["Multiply ciphertext by 2^e mod N and query parity to perform a binary search."],containerConfig:{ports:[20001],command:["sh","-c"],args:['while true; do echo -e "=== RSA Parity Oracle ===\\nN = 0xd4729f...\\ne = 65537\\nCiphertext: 0x48a...\\nSend c mod N: " | nc -lp 20001 -e sh -c \'echo "PARITY: EVEN | FLAG: VIGILANTE{lsb_0r4cl3_b1n4ry_s34rch}"\'; done']}},{id:"crypto-xor-stream",name:"Reused Key Stream Oracle",category:"crypto",difficulty:"Easy",port:20002,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{m4ny_t1m3_p4d_x0r_cr4ck}",description:"Demonstrates many-time-pad vulnerability by encrypting multiple plaintexts with identical keystreams.",image:"busybox:latest",hints:["XOR two ciphertexts together to eliminate the keystream and analyze character cribs."],containerConfig:{ports:[20002],command:["sh","-c"],args:['while true; do echo -e "=== Keystream Reuse Service ===\\nCT1: 1f0e4b78...\\nCT2: 1201407a...\\nSend candidate: " | nc -lp 20002 -e sh -c \'echo "FLAG: VIGILANTE{m4ny_t1m3_p4d_x0r_cr4ck}"\'; done']}},{id:"rev-crackme-license",name:"Crackme License Validator",category:"rev",difficulty:"Easy",port:9001,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{s3r14l_k3y_v3r1f13d_0x99}",description:"Web service providing the crackme binary for download and an online key verification endpoint.",image:"nginx:alpine",hints:["Disassemble the validation routine to extract the mathematical key check algorithm."],containerConfig:{ports:[80],env:[{name:"FLAG",value:"VIGILANTE{s3r14l_k3y_v3r1f13d_0x99}"}]}},{id:"rev-wasm-verifier",name:"WebAssembly Authenticator",category:"rev",difficulty:"Medium",port:9002,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{w4sm_byt3c0d3_d3c0mp1l3d}",description:"Client-side WebAssembly module validating passphrases through obfuscated linear memory logic.",image:"nginx:alpine",hints:["Convert the .wasm binary to WAT (WebAssembly text) or inspect exports with Ghidra."],containerConfig:{ports:[80],env:[{name:"FLAG",value:"VIGILANTE{w4sm_byt3c0d3_d3c0mp1l3d}"}]}},{id:"forensics-pcap-extract",name:"Exfiltration Packet Analyzer",category:"forensics",difficulty:"Easy",port:9101,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{pcap_dns_tunn3l_3xf1l}",description:"Forensics case file containing network PCAP capture with hidden covert channel transmissions.",image:"nginx:alpine",hints:["Filter DNS query logs in Wireshark for base64 or hex encoded subdomains."],containerConfig:{ports:[80],env:[{name:"FLAG",value:"VIGILANTE{pcap_dns_tunn3l_3xf1l}"}]}},{id:"forensics-log-detective",name:"SIEM Incident Triage Case",category:"forensics",difficulty:"Medium",port:9102,protocol:"TCP",serviceType:"HTTP",defaultFlag:"VIGILANTE{s13m_t1m3l1n3_c0rr3l4t10n}",description:"Simulated multi-source log stream recording an adversary pivoting across internal subnets.",image:"nginx:alpine",hints:["Correlate user logon events (4624) with suspicious parent-child process invocations."],containerConfig:{ports:[80],env:[{name:"FLAG",value:"VIGILANTE{s13m_t1m3l1n3_c0rr3l4t10n}"}]}},{id:"misc-pyjail-escape",name:"Restricted Python Sandbox",category:"misc",difficulty:"Medium",port:13337,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{pyth0n_subcl4ss3s_3sc4p3}",description:"Python REPL with __builtins__ stripped, challenging contestants to reach os.system or open.",image:"busybox:latest",hints:['Traverse the object subclass inheritance tree: "".__class__.__mro__[1].__subclasses__()'],containerConfig:{ports:[13337],command:["sh","-c"],args:['while true; do echo -e "=== Python Restricted Sandbox ===\\nBuiltins removed\\nTry to read /flag.txt\\n>>> " | nc -lp 13337 -e sh -c \'echo "FLAG: VIGILANTE{pyth0n_subcl4ss3s_3sc4p3}"\'; done']}},{id:"misc-bash-jail",name:"Alphanumeric Bash Jail",category:"misc",difficulty:"Hard",port:13338,protocol:"TCP",serviceType:"TCP",defaultFlag:"VIGILANTE{b4sh_p4r4m3t3r_3xp4ns10n}",description:"Restricted shell rejecting spaces, slashes, and control symbols, requiring parameter expansion.",image:"busybox:latest",hints:["Use ${IFS} for whitespace and construct command strings from environment variable slices."],containerConfig:{ports:[13338],command:["sh","-c"],args:['while true; do echo -e "=== Restricted Bash Jail ===\\nNo spaces, slashes or wildcards\\n$ " | nc -lp 13338 -e sh -c \'echo "FLAG: VIGILANTE{b4sh_p4r4m3t3r_3xp4ns10n}"\'; done']}}],u=new Map;async function c({teamId:e,challengeId:t,namespace:a="ctf-sandboxes",ttlMinutes:n=45,domain:s="vigilante.local",secretKey:c="vigilante-ctf-secret",clusterName:l="vigilante-dev",mock:d=!1}={}){if(!e||!t)throw Error("Both teamId and challengeId are required to spawn a sandbox");let p=Array.from(u.values()).filter(t=>t.teamId===e&&"ACTIVE"===t.status);if(p.length>=3)throw Error("Team concurrency limit exceeded: Maximum 3 active sandboxes allowed per team. Please terminate an active instance before creating a new one.");let g=p.find(e=>e.challengeId===t);if(g)return g;let h=m.find(e=>e.id===t);if(!h)throw Error(`Challenge '${t}' not found in catalog`);let f=function({teamId:e,challengeId:t,secretKey:a="vigilante-ctf-secret"}){let n=r.createHmac("sha256",a);n.update(`${e}:${t}`);let i=n.digest("hex").slice(0,16);return`VIGILANTE{${t}_${e}_${i}}`}({teamId:e,challengeId:t,secretKey:c}),y=e.toLowerCase().replace(/[^a-z0-9]/g,""),b=t.toLowerCase().replace(/[^a-z0-9-]/g,""),v=`sbx-${y}-${b}-${r.randomBytes(3).toString("hex")}`,T=Date.now(),_=new Date(T+6e4*n).toISOString(),I=`${y}-${b}.ctf.${s}`,w="HTTP"===h.serviceType?`http://${I}`:`nc ${s} ${h.port}`,x=function({teamId:e,challengeId:t,sandboxId:a,namespace:n="ctf-sandboxes",domain:i="vigilante.local",flag:r,ttlMinutes:o=45,targetPort:s=8080,containerConfig:c={}}){let l=e.toLowerCase().replace(/[^a-z0-9]/g,""),d=t.toLowerCase().replace(/[^a-z0-9-]/g,""),p=`${l}-${d}`,m=`${p}.ctf.${i}`,u=new Date(Date.now()+6e4*o).toISOString(),g=new Date().toISOString(),h=c.image||"nginx:alpine",f=c.ports&&c.ports[0]||80;return`---
apiVersion: v1
kind: Namespace
metadata:
  name: ${n}
  labels:
    vigilante.dev/purpose: ctf-sandboxes
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${p}
  namespace: ${n}
  labels:
    vigilante.dev/sandbox-id: ${a}
    vigilante.dev/team-id: ${e}
    vigilante.dev/challenge-id: ${t}
    app: ${p}
  annotations:
    vigilante.dev/created-at: "${g}"
    vigilante.dev/expires-at: "${u}"
    vigilante.dev/ttl-minutes: "${o}"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${p}
  template:
    metadata:
      labels:
        app: ${p}
        vigilante.dev/sandbox-id: ${a}
        vigilante.dev/team-id: ${e}
        vigilante.dev/challenge-id: ${t}
    spec:
      containers:
        - name: challenge
          image: ${h}
          ports:
            - containerPort: ${f}
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 250m
              memory: 128Mi
          env:
            - name: FLAG
              value: "${r}"
            - name: TEAM_ID
              value: "${e}"
            - name: CHALLENGE_ID
              value: "${t}"
---
apiVersion: v1
kind: Service
metadata:
  name: ${p}
  namespace: ${n}
  labels:
    app: ${p}
    vigilante.dev/sandbox-id: ${a}
spec:
  type: ClusterIP
  selector:
    app: ${p}
  ports:
    - name: challenge-port
      port: ${s}
      targetPort: ${f}
      protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${p}-ingress
  namespace: ${n}
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: web,websecure
    ingress.kubernetes.io/ssl-redirect: "false"
spec:
  rules:
    - host: ${m}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ${p}
                port:
                  number: ${s}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${p}-netpol
  namespace: ${n}
spec:
  podSelector:
    matchLabels:
      app: ${p}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: traefik
      ports:
        - protocol: TCP
          port: ${f}
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
`}({teamId:e,challengeId:t,sandboxId:v,namespace:a,domain:s,flag:f,ttlMinutes:n,targetPort:h.port,containerConfig:h.containerConfig});if(!d)try{await (0,i.execa)("kubectl",["apply","-f","-","--context",`k3d-${l}`],{input:x})}catch(e){o.k.warn("KCTF:SPAWNER",`Kubernetes apply fallback: ${e.message}`)}let k={id:v,teamId:e,challengeId:t,challengeName:h.name,category:h.category,port:h.port,protocol:h.protocol,serviceType:h.serviceType,host:I,connectionUrl:w,flag:f,namespace:a,createdAt:new Date(T).toISOString(),expiresAt:_,ttlMinutes:n,status:"ACTIVE",manifest:x};return u.set(v,k),o.k.info("KCTF:SPAWNER",`Provisioned sandbox '${v}' for Team '${e}' on '${t}' (TTL: ${n}m)`),k}async function l({namespace:e="ctf-sandboxes",teamId:t=null,clusterName:a="vigilante-dev"}={}){let n=Date.now(),i=[];for(let[e,a]of u.entries()){if(t&&a.teamId!==t)continue;let e=new Date(a.expiresAt).getTime()-n,r=Math.max(0,Math.round(e/6e4)),o=e<=0;i.push({...a,remainingMinutes:r,status:o?"EXPIRED":a.status})}return i}async function d({sandboxId:e,teamId:t,challengeId:a,namespace:n="ctf-sandboxes",clusterName:r="vigilante-dev",mock:s=!1}={}){let c=e,l=null;if(c&&u.has(c))l=u.get(c);else if(t&&a){for(let[e,n]of u.entries())if(n.teamId===t&&n.challengeId===a){c=e,l=n;break}}if(!l)return{success:!1,message:"Sandbox not found"};if(l.status="TERMINATED",u.delete(c),!s){let e=l.teamId.toLowerCase().replace(/[^a-z0-9]/g,""),t=l.challengeId.toLowerCase().replace(/[^a-z0-9-]/g,""),a=`${e}-${t}`;try{await (0,i.execa)("kubectl",["delete","deployment,service,ingress,networkpolicy",a,`${a}-ingress`,`${a}-netpol`,"-n",n,"--context",`k3d-${r}`,"--ignore-not-found=true"])}catch{}}return o.k.info("KCTF:SPAWNER",`Terminated sandbox '${c}'`),{success:!0,sandboxId:c}}n()}catch(e){n(e)}})},5518:(e,t,a)=>{a.d(t,{k:()=>c});var n=a(7561),i=a(9411),r=a(612);let o=i.join(r.tmpdir(),".vigilante.log");function s(e,t,a,i=null){try{let r=new Date().toISOString(),s=`[${r}] [${e.padEnd(5)}] [${t}] ${a}`;if(null!=i){if(i instanceof Error)s+=`
  Stack: ${i.stack||i.message}`;else if("object"==typeof i)try{s+=`
  Data: ${JSON.stringify(i)}`}catch{s+=`
  Data: [Circular or unstringifiable object]`}else s+=`
  Details: ${i}`}s+="\n",n.appendFileSync(o,s,"utf8")}catch{}}let c={debug:(e,t,a)=>s("DEBUG",e,t,a),info:(e,t,a)=>s("INFO",e,t,a),warn:(e,t,a)=>s("WARN",e,t,a),error:(e,t,a)=>s("ERROR",e,t,a),getLogPath:()=>o}}};