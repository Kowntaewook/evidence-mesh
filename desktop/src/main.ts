import { app, BrowserWindow, dialog, ipcMain, session } from 'electron';
import { readFile } from 'node:fs/promises';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const endpoint = new URL(process.env.EVIDENCEMESH_API ?? 'http://127.0.0.1:8765');
if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)
    || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) {
  throw new Error('EVIDENCEMESH_API must be a local HTTP origin');
}
const entry = pathToFileURL(path.join(__dirname, 'index.html')).href;
const allowedPath = /^\/(health|samples\/load|parsers\/volatility|cases(?:\/[a-zA-Z0-9-]+(?:\/(?:events|correlate|correlations|graph|timeline|processes|files|network|parser-runs|imports|import\/(?:memory|disk|network)))?)?)(?:\?[a-zA-Z0-9_=%&.-]*)?$/;

async function request(method: string, route: string, body?: unknown): Promise<unknown> {
  if (!['GET', 'POST'].includes(method) || !allowedPath.test(route)) throw new Error('Unsupported API request');
  const response = await fetch(new URL(route, endpoint), {
    method, headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(120000),
    redirect: 'error',
  });
  const data = JSON.parse(await response.text(), (_key: string, value: unknown, context?: { source: string }) => {
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) {
      if (!context?.source) throw new Error('Cannot preserve a large source integer in this runtime');
      return context.source;
    }
    return value;
  }) as { detail?: unknown };
  if (!response.ok) throw new Error(`${response.status}: ${typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)}`);
  return data;
}

function trusted(event: Electron.IpcMainInvokeEvent): void {
  if (event.senderFrame?.url !== entry || event.senderFrame !== event.sender.mainFrame) throw new Error('Untrusted renderer');
}


let backendProcess: ChildProcess | null = null;

function startPackagedBackend(): void {
  if (!app.isPackaged) return;

  const backendPath = path.join(
    process.resourcesPath,
    'backend',
    'evidencemesh-backend.exe',
  );

  backendProcess = spawn(backendPath, [], {
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...process.env,
      EVIDENCEMESH_DB: path.join(
        app.getPath('userData'),
        'evidencemesh.sqlite3',
      ),
    },
  });

  backendProcess.stderr?.on('data', (data) => {
    console.error(`[EvidenceMesh backend] ${data.toString()}`);
  });

  backendProcess.on('error', (error) => {
    console.error('Failed to start EvidenceMesh backend:', error);
  });
}

async function waitForBackend(): Promise<void> {
  const healthUrl = new URL('/health', endpoint);

  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(healthUrl, {
        signal: AbortSignal.timeout(1000),
      });

      if (response.ok) return;
    } catch {
      // Backend may still be starting.
    }

    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error('EvidenceMesh backend did not become ready');
}

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({ width: 1440, height: 900, minWidth: 1120, minHeight: 720,
    backgroundColor: '#080808', title: 'EvidenceMesh',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event) => event.preventDefault());
  void window.loadURL(entry);
  return window;
}

app.whenReady().then(async () => {
  if (app.isPackaged) {
    startPackagedBackend();
    await waitForBackend();
  }

  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  ipcMain.handle('api:request', (event, method: string, route: string, body?: unknown) => {
    trusted(event);
    return request(method, route, body);
  });
  ipcMain.handle('evidence:import', async (event, caseId: string) => {
    trusted(event);
    if (!/^[a-zA-Z0-9-]+$/.test(caseId)) throw new Error('Invalid case ID');
    const choice = await dialog.showOpenDialog({ title: 'Import normalized event JSON',
      filters: [{ name: 'Event JSON', extensions: ['json'] }], properties: ['openFile', 'multiSelections'] });
    if (choice.canceled) return null;
    const records: unknown[] = [];
    for (const filename of choice.filePaths) {
      const bytes = await readFile(filename);
      const content = JSON.parse(bytes.toString('utf8')) as unknown;
      if (!Array.isArray(content) || content.length === 0) throw new Error('Expected a nonempty JSON event array');
      const digest = createHash('sha256').update(bytes).digest('hex');
      for (const [index, item] of content.entries()) {
        if (typeof item !== 'object' || item === null || Array.isArray(item)) throw new Error('Expected Event objects');
        const record = item as Record<string, unknown>;
        const attributes = record.attributes ?? {};
        if (typeof attributes !== 'object' || Array.isArray(attributes)) throw new Error('Expected attributes object');
        const metadata = attributes as Record<string, unknown>;
        if ('import_reference' in metadata) {
          const history = metadata.import_history ?? [];
          if (!Array.isArray(history)) throw new Error('Expected import_history array');
          metadata.import_history = [...history, metadata.import_reference];
        }
        metadata.import_reference = { path: filename, sha256: digest, json_pointer: `/${index}` };
        record.attributes = metadata;
        if (record.source_artifact == null && record.raw_reference == null) {
          record.source_artifact = { artifact_id: `sha256:${digest}`, kind: 'json_export', path: filename, sha256: digest };
          record.raw_reference = { artifact_id: `sha256:${digest}`, locator: `/${index}` };
        }
        record.parser ??= { name: 'evidencemesh-desktop-json', version: '0.1.0' };
        records.push(record);
      }
    }
    return request('POST', `/cases/${caseId}/events`, records);
  });
  ipcMain.handle('artifact:import', async (event, caseId: string, kind: string, context: unknown, format?: string) => {
    trusted(event);
    if (!/^[a-zA-Z0-9-]+$/.test(caseId) || !['memory', 'disk', 'network'].includes(kind)) throw new Error('Invalid artifact import');
    const choice = await dialog.showOpenDialog({ title: kind === 'memory' ? 'Select Volatility JSON export folder' : kind === 'network' ? 'Select PCAP or PCAPNG' : 'Select disk artifact',
      properties: kind === 'memory' ? ['openDirectory'] : ['openFile'] });
    if (choice.canceled || !choice.filePaths[0]) return null;
    return request('POST', `/cases/${caseId}/import/${kind}`, { path: choice.filePaths[0], format, context });
  });
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
}).catch((error: unknown) => { console.error(error); app.exit(1); });

app.on('before-quit', () => {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
