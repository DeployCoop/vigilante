#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

await import(path.join(__dirname, '..', 'apps', 'ink', 'bin', 'vigilante.js'));
