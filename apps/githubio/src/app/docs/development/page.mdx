# 🛠️ Vigilante Contributor & Developer Guide

This document outlines best practices, testing conventions, and development patterns for contributing to **Vigilante**.

---

## 1. Development Setup

### Prerequisites
- **Node.js**: v20+ (Node.js v26 recommended for built-in `node:sqlite` DatabaseSync)
- **pnpm**: v9+ or v11+
- **Docker**, **k3d**, **mkcert**, **kubectl**, **helm**

### Installation
```bash
# Clone the repository
git clone https://github.com/DeployCoop/vigilante.git
cd vigilante

# Install dependencies
pnpm install

# Link CLI globally for local testing
pnpm link --global
```

Verify your installation:
```bash
vigilante status
```

---

## 2. Running Test Suites

Vigilante features a comprehensive suite of **70 unit and integration test suites** located in [`tests/`](file:///mnt/unreal/git/DeployCoop/vigilante/tests/).

Run all tests:
```bash
pnpm test
```

### Running Individual Tests
You can run any specific test suite using `node`:
```bash
# Test BPF-LSM policy synthesizer
node tests/test-lsm.js

# Test statistical C2 beaconing & FFT detector
node tests/test-beaconing.js

# Test anti-ransomware canary traps & entropy monitor
node tests/test-ransomware.js

# Test multi-agent incident war room & consensus debate
node tests/test-warroom.js

# Test local offline semantic CTI & vector search
node tests/test-vectorcti.js

# Test BattleStation canvas, Header sparklines & MitreView
node tests/test-battlestation-canvas.js

# Test cryptographic Merkle ledger & legal chain-of-custody
node tests/test-ledger.js

# Test composite attack graph & blast-radius explorer
node tests/test-attackgraph.js

# Test MCP server tools (78 tools)
node tests/test-mcp.js
```

### Testing Guidelines
- **Zero Test Leaks**: Tests must use temporary directories (`fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-'))`) and clean up upon completion.
- **Teardown Hooks**: Engines that maintain state (such as `datalake.js` database handles) must provide explicit cleanup methods (`closeDataLake()`) invoked in test teardown blocks.
- **Mock Safety**: When testing external CLI tools (`kubectl`, `nmap`, `trivy`), use mocked outputs or fixture files located in `tests/fixtures/`.

---

## 3. Terminal UI Architecture (React & Ink)

All interactive terminal views in [`src/ui/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/ui/) are built with React and Ink.

### Pure `React.createElement` (No JSX)
To ensure native Node.js ESM execution without requiring build-step transpilation, **do not write JSX**. All Ink views must use pure `React.createElement(...)`:

```javascript
import React from 'react';
import { Box, Text } from 'ink';

export function ExampleView({ title, status }) {
  return React.createElement(
    Box,
    {
      flexDirection: 'column',
      borderStyle: 'round',
      borderColor: 'cyan',
      padding: 1
    },
    React.createElement(Text, { bold: true, color: 'green' }, title),
    React.createElement(Text, { color: 'gray' }, `Status: ${status}`)
  );
}
```

### Input Guards & Subview Navigation
In [`src/ui/App.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/ui/App.js), ensure that top-level keyboard hotkeys do not collide with active subviews:

```javascript
useInput((input, key) => {
  // Always permit [Tab] to return to the Operations Hub
  if (key.tab) {
    setActiveView('hub');
    return;
  }

  // Guard against top-level hotkeys when a subview is handling input
  if (activeView !== 'hub' && activeView !== 'status') {
    return;
  }

  // Handle top-level view switching
  if (input === 'b') setActiveView('battle');
  if (input === 'p') setActiveView('pods');
});
```

---

## 4. Creating a Custom Module

To add a new security package to the Vigilante ecosystem, extend [`BaseModule`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/base.js):

1. Create a new directory in `src/modules/<module-name>/`:
   ```text
   src/modules/my-tool/
   ├── index.js
   ├── values/
   │   └── my-tool.yaml
   └── charts/
   ```

2. Implement the module contract:
   ```javascript
   import { BaseModule } from '../base.js';

   export class MyToolModule extends BaseModule {
     constructor() {
       super('my-tool', 'Custom Security Tool Description');
       this.category = 'Threat Detection';
     }

     async preInstall(context) {
       // Validate prerequisites, create namespaces
     }

     async install(context) {
       // Deploy Helm chart or apply manifests
     }

     async postInstall(context) {
       // Register ingress domains in /etc/hosts
     }

     async getStatus(context) {
       // Return live pod/service health
     }

     getIngressUrls(domain) {
       return [`https://mytool.${domain}`];
     }
   }
   ```

3. Register the module in [`src/modules/registry.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/registry.js).

---

## 5. Authoring WebAssembly (Wasm) Plugins

Vigilante's Wasm engine ([`src/engine/wasm.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/wasm.js)) executes sandboxed detectors:

- Modules export an `evaluate_event(event_ptr, event_len)` function returning an integer risk score ($0$ = Clean, $>1000$ = Critical Anomaly).
- Modules can be compiled from Rust (`wasm32-unknown-unknown`), Go, or AssemblyScript.
- Install plugins into the active registry:
  ```javascript
  import { installWasmPlugin } from 'vigilante';
  await installWasmPlugin('my-detector.wasm', wasmBuffer);
  ```
