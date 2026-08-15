import { EventEmitter } from 'node:events';

export class Logger extends EventEmitter {
  constructor() {
    super();
    this.logs = [];
  }

  log(message, type = 'info') {
    const entry = {
      timestamp: new Date(),
      message,
      type
    };
    this.logs.push(entry);
    this.emit('log', entry);
  }

  info(message) {
    this.log(message, 'info');
  }

  success(message) {
    this.log(message, 'success');
  }

  warn(message) {
    this.log(message, 'warn');
  }

  error(message) {
    this.log(message, 'error');
  }

  getLogs() {
    return this.logs;
  }

  clear() {
    this.logs = [];
    this.emit('clear');
  }
}

export const globalLogger = new Logger();
