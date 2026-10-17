#!/usr/bin/env node
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// A bare filesystem path is not a valid ESM specifier (on Windows it
// throws ERR_UNSUPPORTED_ESM_URL_SCHEME); import the file:// URL.
await import(pathToFileURL(path.join(__dirname, '..', 'apps', 'ink', 'bin', 'vigilante.js')).href);
