// Execute the installed product; Python/Node/TShark on the runner PATH are not
// available to the application under test. Node/Playwright only drive the test.
const { chromium } = require('playwright');
const { spawn, spawnSync } = require('node:child_process');
const { readFile, writeFile, mkdir, stat, access, readdir } = require('node:fs/promises');
const { createHash } = require('node:crypto');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '../..');
const output = path.join(root, 'data/windows-e2e');
const install = path.join(process.env.RUNNER_TEMP ?? process.env.TEMP, 'EvidenceMesh-install');
const userData = path.join(process.env.APPDATA, 'EvidenceMesh');
const database = path.join(userData, 'evidencemesh.sqlite3');
const system = path.join(process.env.SystemRoot, 'System32');
const powershell = path.join(system, 'WindowsPowerShell/v1.0/powershell.exe');
const report = { platform: process.platform, checks: [], status: 'RUNNING' };
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function command(executable, args, options = {}) {
  const result = spawnSync(executable, args, { timeout: 180000, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, `${executable}: ${result.error ?? ''}\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}
function pass(name, details) {
  report.checks.push({ name, status: 'PASS', details });
  console.log('PASS ' + name + (details ? ': ' + JSON.stringify(details) : ''));
}
async function digest(filename) {
  return createHash('sha256').update(await readFile(filename)).digest('hex');
}
function ownedProcesses() {
  return JSON.parse(command(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    "$items = @((Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'EvidenceMesh.exe' -or $_.Name -eq 'evidencemesh-backend.exe' }) | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath); ConvertTo-Json -InputObject $items -Compress"]).trim() || '[]');
}

async function main() {
  assert.equal(process.platform, 'win32', 'This is an actual Windows installer test');
  await mkdir(output, { recursive: true });
  const version = (await readFile(path.join(root, 'VERSION'), 'utf8')).trim();
  const installer = path.join(root, `desktop/release-installer/EvidenceMesh.Setup.${version}.exe`);
  const initial = ownedProcesses();
  assert.equal(initial.length, 0, 'Windows runner must start without EvidenceMesh processes');
  command(installer, ['/S', '/D=' + install]);
  const executable = path.join(install, 'EvidenceMesh.exe');
  await access(executable);
  pass('silent install', { installer: path.basename(installer), path: install, sha256: await digest(installer), size: (await stat(installer)).size });
  const tshark = path.join(install, 'resources/tshark/tshark.exe');
  const cdpPort = await freePort();
  const restricted = {
    ...process.env,
    PATH: system,
    ELECTRON_RUN_AS_NODE: '',
    CI: 'true',
    EVIDENCEMESH_E2E_CDP_PORT: String(cdpPort),
  };
  delete restricted.EVIDENCEMESH_API;
  delete restricted.EVIDENCEMESH_USER_DATA;
  delete restricted.EVIDENCEMESH_TSHARK;
  const absent = spawnSync(path.join(system, 'where.exe'), ['tshark'], { env: restricted, encoding: 'utf8' });
  assert.notEqual(absent.status, 0, 'System TShark must not be discoverable');
  assert.match(command(tshark, ['--version'], { env: restricted }), /TShark.*4\.6\.8/);
  pass('bundled TShark launches with restricted PATH');

  let browser;
  let appProcess;
  let appLogs = '';
  let window;
  let cleanShutdown = false;
  let databaseObserved = false;

  try {
    appProcess = spawn(executable, [], {
      cwd: install,
      env: restricted,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    appProcess.stdout.on('data', (chunk) => { appLogs += chunk.toString(); });
    appProcess.stderr.on('data', (chunk) => { appLogs += chunk.toString(); });

    let cdpReady = false;
    for (let attempt = 0; attempt < 180; attempt++) {
      if (appProcess.exitCode !== null) {
        throw new Error(
          `Installed EvidenceMesh exited before CDP startup: ${appProcess.exitCode}\n${appLogs}`
        );
      }
      try {
        const response = await fetch(`http://127.0.0.1:${cdpPort}/json/version`);
        if (response.ok) {
          cdpReady = true;
          break;
        }
      } catch {
        // bounded startup polling
      }
      await delay(500);
    }

    assert(cdpReady, `Installed EvidenceMesh CDP endpoint did not start\n${appLogs}`);

    browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`);
    const contexts = browser.contexts();
    assert(contexts.length > 0, 'Installed Electron app exposed no browser context');

    for (let attempt = 0; attempt < 120; attempt++) {
      const pages = contexts[0].pages();
      window = pages.find((page) => page.url().startsWith('file:')) ?? pages[0];
      if (window) break;
      if (appProcess.exitCode !== null) {
        throw new Error(
          `Installed EvidenceMesh exited before renderer startup: ${appProcess.exitCode}\n${appLogs}`
        );
      }
      await delay(250);
    }

    assert(window, `Installed Electron renderer did not appear\n${appLogs}`);
    window.setDefaultTimeout(60000);

    const errors = [];
    window.on('pageerror', (error) => errors.push(String(error)));

    await window.waitForFunction(
      () => document.querySelector('#status').textContent.includes('Engine connected')
    );

    const req = (method, route, body) =>
      window.evaluate(
        ([m, r, b]) => window.evidenceMesh.request(m, r, b),
        [method, route, body],
      );

    const health = await req('GET', '/health');
    assert.equal(health.version, version);

    const dependencies = await req('GET', '/runtime/dependencies');
    assert(dependencies.backend.embedded && dependencies.tshark.embedded);
    assert.equal(dependencies.tshark.path.toLowerCase(), tshark.toLowerCase());
    assert(Object.values(dependencies.components).every((c) => c.status === 'OK'));
    assert(Object.values(dependencies.data).every((value) => value === 'OK'));

    await access(database);
    databaseObserved = true;

    const runtime = JSON.parse(
      await readFile(path.join(userData, 'runtime.json'), 'utf8')
    );

    assert.equal(new URL(runtime.endpoint).hostname, '127.0.0.1');
    assert.equal((await fetch(new URL('/health', runtime.endpoint))).status, 401);

    pass(
      'installed app, automatic backend, loopback authentication, SQLite and dependencies',
      { executable, userData, version },
    );

    assert.equal(await window.evaluate(() => typeof window.require), 'undefined');

    await window.click('#load-sample');
    await window.waitForFunction(() => document.querySelector('#status').textContent.includes('Loaded 15 events'));
    await window.locator('#navigation [data-view="processes"]').click();
    await window.locator('#process-table [data-event-id="MEM-PS"]').click();
    await window.click('#analyze');
    await window.waitForFunction(() => document.querySelector('#status').textContent.includes('Analysis complete'));
    assert.equal(await window.locator('#correlation-table tbody tr').count(), 16);
    await window.locator('#correlation-table [data-key="MEM-SOCKET:NET-TLS"]').click();
    await window.click('[data-inspector="provenance"]');
    assert.match(await window.locator('#inspector-content').innerText(), /Original row/);
    await window.locator('#navigation [data-view="timeline"]').click();
    assert.equal(await window.locator('#timeline-table tbody tr').count(), 9);
    await window.locator('#navigation [data-view="graph"]').click();
    assert.equal(await window.locator('.graph-node').count(), 9);
    assert.equal(await window.locator('.graph-edge').count(), 16);
    await window.screenshot({ path: path.join(output, 'installed-sample.png'), fullPage: true });
    pass('installed sample UI, correlation, reasons, provenance, timeline and graph', { links: 16, incidentEvents: 9 });

    const discovery = await req('GET', '/parsers/volatility');
    assert(discovery.plugins.find((p) => p.plugin === 'windows.pslist')?.available, JSON.stringify(discovery));
    assert(discovery.plugins.find((p) => p.plugin === 'windows.callbacks')?.available);
    pass('bundled Volatility CLI and plugin discovery', { available: discovery.plugins.filter((p) => p.available).length, realMemoryValidation: 'NOT VALIDATED WITH REAL MEMORY IMAGE' });
    const testCase = await req('POST', '/cases', { name: 'Installed artifact E2E' });
    const prefix = '/cases/' + testCase.case_id;
    const context = { acquisition_id: 'installed-windows-e2e', extracted_at: '2026-09-16T09:35:00Z', timezone: 'UTC', hostname: 'e2e-host' };
    const inputs = [
      ['mft', 'tests/fixtures/disk/mft-record.bin'], ['usn', 'tests/fixtures/disk/usn-v2.bin'],
      ['prefetch', 'tests/fixtures/disk/sample-v30.pf'], ['evtx', 'data/compatibility/TestLogX.evtx'],
      ['amcache', 'data/compatibility/amcache-new.hve'],
      ...[3, 4].map((v) => ['usn', `data/windows-fixtures/usn-v${v}.bin`]),
      ...[17, 23, 26, 30, 31].map((v) => ['prefetch', `data/windows-fixtures/compressed-v${v}.pf`]),
    ];
    for (const [format, relative] of inputs) {
      const filename = path.join(root, relative);
      const before = await digest(filename);
      const imported = await req('POST', prefix + '/import/disk', { path: filename, format, context });
      assert.equal(imported.status, 'SUCCESS', JSON.stringify(imported));
      assert(imported.imported > 0);
      assert.equal(await digest(filename), before);
      pass('installed disk import ' + path.basename(filename), { events: imported.imported });
    }
    const memoryExports = await req('POST', prefix + '/import/memory', { path: path.join(root, 'tests/fixtures/volatility'), context });
    assert(memoryExports.imported > 0 && memoryExports.runs.some((run) => run.status === 'SUCCESS'));
    pass('Volatility structured output normalization', { events: memoryExports.imported });
    const image = path.join(root, 'data/windows-fixtures/inert-ntfs.img');
    const originalImage = await digest(image);
    const inspection = await req('POST', prefix + '/disk-images/inspect', { path: image, context });
    assert(inspection.read_only && inspection.volumes.some((v) => v.filesystem === 'NTFS'));
    const extracted = await req('POST', prefix + '/disk-images/import', { path: image, context, artifacts: ['mft', 'usn', 'prefetch'] });
    assert(extracted.imported > 0, JSON.stringify(extracted));
    assert.equal(await digest(image), originalImage);
    pass('installed read-only raw NTFS extraction', { events: extracted.imported });

    for (const extension of ['pcap', 'pcapng']) {
      const networkCase = await req('POST', '/cases', { name: 'Installed ' + extension });
      const capture = path.join(root, 'tests/fixtures/network/sample.' + extension);
      const before = await digest(capture);
      const imported = await req('POST', `/cases/${networkCase.case_id}/import/network`, { path: capture, context });
      assert.equal(imported.status, 'SUCCESS', JSON.stringify(imported));
      assert(imported.runs.every((run) => run.status === 'SUCCESS'));
      assert(imported.runs.some((run) => run.command[0]?.toLowerCase() === tshark.toLowerCase()));
      const events = await req('GET', `/cases/${networkCase.case_id}/events`);
      assert(events.some((e) => e.network?.dns_query));
      for (const protocol of ['TCP', 'UDP']) assert(events.some((e) => e.network?.protocol === protocol));
      assert(events.some((e) => e.network?.http));
      assert(events.some((e) => e.network?.tls));
      assert.equal(await digest(capture), before);
      pass('PATH-independent installed ' + extension + ' DNS/TCP/UDP/HTTP/TLS', { events: events.length });
    }
    const capture = path.join(root, 'data/windows-fixtures/encrypted.pcapng');
    const key = path.join(root, 'data/windows-fixtures/supplied-keys.log');
    const tlsCases = [];
    for (const withKey of [false, true]) {
      const tlsCase = await req('POST', '/cases', { name: 'Installed TLS ' + withKey });
      const imported = await req('POST', `/cases/${tlsCase.case_id}/import/network`, { path: capture, context: { ...context, ...(withKey ? { tls_keylog_file: key } : {}) } });
      assert.equal(imported.status, 'SUCCESS', JSON.stringify(imported));
      const events = await req('GET', `/cases/${tlsCase.case_id}/events`);
      const body = events.find((e) => e.network?.http?.body_sha256);
      assert.equal(Boolean(body), withKey);
      if (body) {
        assert(body.network.http.decrypted_with_supplied_key);
        assert.equal(await digest(body.network.http.recovered_path), await digest(path.join(root, 'data/windows-fixtures/body.bin')));
      }
      tlsCases.push({ keySupplied: withKey, recoveredBody: Boolean(body) });
    }
    pass('actual TLS with/without supplied keys and HTTP body recovery', tlsCases);

    const invalid = path.join(root, 'data/windows-fixtures/invalid-memory.raw');
    const before = await digest(invalid);

    let job = await req('POST', prefix + '/memory-jobs', {
      path: invalid,
      context,
      rerun: false,
      plugins: ['windows.pslist'],
    });

    for (
      let attempt = 0;
      attempt < 120 &&
      !['SUCCESS', 'FAILED', 'PARTIAL', 'CANCELLED'].includes(job.status);
      attempt++
    ) {
      await delay(500);
      job = await req('GET', prefix + '/memory-jobs/' + job.job_id);
    }

    assert.equal(job.completed, 1, JSON.stringify(job));
    assert.equal(
      job.plugins[0].status,
      'FAILED',
      'Invalid image must fail truthfully after actual bundled invocation',
    );

    assert.equal(await digest(invalid), before);

    pass(
      'installed bundled memory invocation and truthful invalid-image failure',
      { realMemoryValidation: 'NOT VALIDATED WITH REAL MEMORY IMAGE' },
    );
    assert.equal(errors.length, 0, errors.join('\n'));

    try {
      await window.close();
    } catch {
      // renderer may disappear while Electron is shutting down
    }
    window = undefined;

    for (let attempt = 0; attempt < 60 && ownedProcesses().length; attempt++) {
      await delay(500);
    }

    assert.equal(
      ownedProcesses().length,
      0,
      'App/backend/worker processes remain after normal window close',
    );

    cleanShutdown = true;

    try {
      await browser.close();
    } catch {
      // Electron may already have closed the CDP connection
    }
    browser = undefined;

    await assert.rejects(fetch(new URL('/health', runtime.endpoint)));
    await access(path.join(userData, 'logs/backend.log'));

    pass(
      'clean app/backend shutdown, closed port, no orphan workers and persistent logs',
    );
  } catch (error) {
    if (window) {
      try {
        await window.screenshot({ path: path.join(output, 'failure.png') });
      } catch {
        // preserve original failure
      }
    }
    if (appLogs) {
      console.error('Installed EvidenceMesh logs:\n' + appLogs);
    }
    throw error;
  } finally {
    if (!cleanShutdown) {
      for (const processInfo of ownedProcesses()) {
        spawnSync(
          path.join(system, 'taskkill.exe'),
          ['/PID', String(processInfo.ProcessId), '/T', '/F'],
          { encoding: 'utf8' },
        );
      }
      await delay(1000);
    }

    try {
      await browser?.close();
    } catch {
      // cleanup only
    }

    for (const filename of ['runtime.json', 'logs/backend.log', 'logs/desktop.log']) {
      try { await writeFile(path.join(output, path.basename(filename)), await readFile(path.join(userData, filename))); } catch { /* startup may fail before logs exist */ }
    }
    const uninstaller = (await readdir(install)).find((filename) => /^Uninstall.*\.exe$/i.test(filename));
    assert(uninstaller, 'Installed NSIS uninstaller missing');
    command(path.join(install, uninstaller), ['/S']);
    for (let attempt = 0; attempt < 60; attempt++) {
      try { await access(executable); } catch { break; }
      await delay(500);
    }
    await assert.rejects(access(executable));
    assert.equal(ownedProcesses().length, 0);
    // Evidence belongs to the user and is deliberately retained by uninstall.
    await access(path.join(userData, 'evidencemesh.sqlite3'));
    pass('silent uninstall removes program and preserves user evidence');
  }
  report.status = 'PASS';
}

main().catch((error) => { report.status = 'FAILED'; report.error = String(error.stack ?? error); console.error(error); process.exitCode = 1; })
  .finally(async () => { await mkdir(output, { recursive: true }); await writeFile(path.join(output, 'report.json'), JSON.stringify(report, null, 2)); });
