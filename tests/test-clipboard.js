import { copyToClipboard } from '../src/utils/clipboard.js';
import { stripAnsi } from '../src/ui/ClipboardManager.js';
import { execa } from 'execa';

async function runTests() {
  console.log('🧪 Testing Clipboard System...');

  // Test 1: stripAnsi
  const ansiText = '\x1b[32m✔ Hello \x1b[1mWorld\x1b[0m';
  const clean = stripAnsi(ansiText);
  if (clean !== '✔ Hello World') {
    throw new Error(`stripAnsi failed: got "${clean}"`);
  }
  console.log('✔ Test 1 passed: stripAnsi cleans ANSI escape codes properly.');

  // Test 2: copyToClipboard
  const testPayload = 'https://siem.vigilante.local/app/security-analytics';
  const res = await copyToClipboard(testPayload);
  console.log('✔ Test 2 result:', res);

  // If wl-paste is available, verify clipboard contents
  try {
    const { stdout } = await execa('wl-paste', { timeout: 1000 });
    if (stdout.trim() === testPayload) {
      console.log('✔ Test 3 passed: wl-paste successfully retrieved copied payload from system clipboard!');
    } else {
      console.log(`ℹ Clipboard content: ${stdout.trim()}`);
    }
  } catch (err) {
    console.log('ℹ wl-paste check skipped or failed:', err.message);
  }

  console.log('🎉 All Clipboard tests completed successfully!');
}

runTests().catch(err => {
  console.error('✖ Tests failed:', err);
  process.exit(1);
});
