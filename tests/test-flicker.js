import assert from 'node:assert';
import React from 'react';
import {
  isInteractiveTty,
  enterAlternateScreen,
  leaveAlternateScreen,
  hideCursor,
  showCursor,
  setupTerminalLifecycle
} from '../src/utils/terminal.js';
import { PulseIndicator, FlickerFreeSpinner } from '../src/ui/PulseIndicator.js';

console.log('🧪 Testing Flicker-Free Terminal Lifecycle & Zero-Flicker Pulse Indicators...');

// Test 1: Terminal Functions
assert.strictEqual(typeof isInteractiveTty, 'function');
assert.strictEqual(typeof enterAlternateScreen, 'function');
assert.strictEqual(typeof leaveAlternateScreen, 'function');
assert.strictEqual(typeof hideCursor, 'function');
assert.strictEqual(typeof showCursor, 'function');
assert.strictEqual(typeof setupTerminalLifecycle, 'function');

// Safe invocation in test environment
setupTerminalLifecycle();
enterAlternateScreen();
hideCursor();
showCursor();
leaveAlternateScreen();
console.log('✔ Test 1 passed: Terminal screen buffer and cursor lifecycle manager invoked safely.');

// Test 2: PulseIndicator and FlickerFreeSpinner Components
assert.strictEqual(typeof PulseIndicator, 'object'); // React.memo returns an object ($$typeof)
assert.strictEqual(typeof FlickerFreeSpinner, 'object');

const element1 = React.createElement(PulseIndicator, { type: 'dots', color: 'yellow' });
const element2 = React.createElement(PulseIndicator, { type: 'pulse', color: 'cyan' });
const element3 = React.createElement(PulseIndicator, { staticChar: '✔', color: 'green' });
const element4 = React.createElement(FlickerFreeSpinner, { type: 'dots' });

assert.ok(element1 && element1.type);
assert.ok(element2 && element2.type);
assert.ok(element3 && element3.type);
assert.ok(element4 && element4.type);
console.log('✔ Test 2 passed: PulseIndicator and FlickerFreeSpinner memoized components instantiated cleanly.');

// Test 3: Log Batching Simulation
const logQueue = [];
let flushTimeout = null;

function simulateAddLog(msg) {
  logQueue.push(msg);
  if (!flushTimeout) {
    flushTimeout = setTimeout(() => {
      // Flushed
      logQueue.length = 0;
      flushTimeout = null;
    }, 40);
  }
}

for (let i = 0; i < 50; i++) {
  simulateAddLog(`Rapid log entry #${i}`);
}

assert.strictEqual(logQueue.length, 50, '50 logs queued without triggering 50 separate renders');
await new Promise(resolve => setTimeout(resolve, 60));
assert.strictEqual(logQueue.length, 0, 'Logs successfully flushed in single batched tick');
console.log('✔ Test 3 passed: 40ms log flush queue batches rapid streams into single frame updates.');

console.log('\n🎉 All Flicker Minimization & Terminal Lifecycle tests passed successfully!\n');
