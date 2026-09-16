import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { VERSION } from './version';

export class Backend {
  process: ChildProcess | null = null;
  endpoint: URL | null = null;
  readonly token = randomBytes(32).toString('hex');
  readonly instance = randomUUID();
  readonly logPath: string;
  stopping = false;

  constructor(readonly executable: string, readonly resources: string, readonly userData: string,
    readonly onCrash: (message: string) => void) {
    const logs = path.join(userData, 'logs');
    mkdirSync(logs, { recursive: true });
    this.logPath = path.join(logs, 'desktop.log');
  }

  log(message: string): void {
    appendFileSync(this.logPath, new Date().toISOString() + ' ' + message + '\n');
  }

  async start(timeout = 45000): Promise<URL> {
    this.log('Starting embedded backend');
    this.process = spawn(this.executable, ['--parent-pipe'], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env,
        EVIDENCEMESH_DB: path.join(this.userData, 'evidencemesh.sqlite3'),
        EVIDENCEMESH_WORKSPACE: this.userData,
        EVIDENCEMESH_TSHARK: path.join(this.resources, 'tshark', 'tshark.exe'),
        EVIDENCEMESH_SESSION_TOKEN: this.token, EVIDENCEMESH_INSTANCE: this.instance,
        PYTHONUNBUFFERED: '1',
      },
    });
    const child = this.process;
    let fatal: Error | null = null;
    child.on('error', (error) => { fatal = error; this.log('Backend spawn failed: ' + error.message); });
    child.on('exit', (code, signal) => {
      this.log('Backend exit code=' + code + ' signal=' + signal);
      fatal = new Error('The analysis backend stopped (code ' + code + ').');
      if (!this.stopping && this.endpoint) this.onCrash(fatal.message);
    });
    // Startup diagnostics only; parser evidence is recorded by the backend audit, not this log.
    child.stderr?.on('data', () => this.log('Backend wrote diagnostic output; see backend.log.'));
    const reader = createInterface({ input: child.stdout! });
    let candidate: URL | null = null;
    reader.on('line', (line) => {
      try {
        const message = JSON.parse(line) as { type?: string; host?: string; port?: number; version?: string };
        if (message.type === 'backend-address' && message.host === '127.0.0.1'
          && Number.isInteger(message.port) && message.port! > 0 && message.port! <= 65535
          && message.version === VERSION) candidate = new URL('http://127.0.0.1:' + message.port);
      } catch { /* Volatility/progress output is not an address message. */ }
    });
    const began = Date.now();
    try {
      while (Date.now() - began < timeout) {
        if (fatal) throw fatal;
        if (candidate) {
          try {
            const response = await fetch(new URL('/health', candidate), {
              headers: { 'X-EvidenceMesh-Token': this.token }, signal: AbortSignal.timeout(1000),
              redirect: 'error',
            });
            const data = await response.json() as { instance?: string; version?: string };
            if (response.ok && data.instance === this.instance && data.version === VERSION) {
              this.endpoint = candidate;
              writeFileSync(path.join(this.userData, 'runtime.json'), JSON.stringify({
                endpoint: String(candidate), pid: child.pid, version: VERSION,
              }));
              this.log('Backend ready at ' + String(candidate));
              return candidate;
            }
          } catch { /* Only this instance's successful health response establishes readiness. */ }
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error('The analysis backend did not become ready within ' + timeout / 1000 + ' seconds.');
    } catch (error) {
      await this.stop();
      throw error;
    }
  }

  async stop(): Promise<void> {
    this.stopping = true;
    const child = this.process;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
    child.stdin?.end('quit\n');
    await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 5000))]);
    if (child.exitCode === null && child.signalCode === null && child.pid) {
      if (process.platform === 'win32') {
        await new Promise<void>((resolve) => {
          const killer = spawn(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'),
            ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
          killer.once('error', () => resolve());
          killer.once('exit', () => resolve());
        });
      } else child.kill('SIGKILL');
      await Promise.race([exited, new Promise<void>((resolve) => setTimeout(resolve, 3000))]);
    }
    this.log('Backend stopped');
  }
}
