const { _electron: electron } = require('playwright');
const { spawn, spawnSync } = require('node:child_process');
const { mkdtemp, rm, readFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

async function main() {
  const root = path.resolve(__dirname, '../..');
  const temporary = await mkdtemp(path.join(tmpdir(), 'evidencemesh-v04-'));
  const python = process.env.EVIDENCEMESH_PYTHON ?? path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const disk = path.join(temporary, 'disk.img'), capture = path.join(temporary, 'encrypted.pcapng'), keylog = path.join(temporary, 'keys.log');
  const fixture = spawnSync(python, ['-c',
    'import runpy,sys; from pathlib import Path; d=runpy.run_path("tests/test_disk_images_v04.py"); Path(sys.argv[1]).write_bytes(d["ntfs_volume"]()); n=runpy.run_path("tests/test_network_v04.py"); n["tls_capture"](Path(sys.argv[2]), Path(sys.argv[3]))',
    disk, capture, keylog], { cwd: root, encoding: 'utf8' });
  assert.equal(fixture.status, 0, fixture.stderr);
  const original = await readFile(disk);
  const backend = spawn(python, ['-m', 'api.launcher', '--parent-pipe'], {
    cwd: root, env: { ...process.env, EVIDENCEMESH_DB: path.join(temporary, 'case.sqlite3'), EVIDENCEMESH_WORKSPACE: temporary },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let output = '', errors = '', desktop;
  backend.stdout.on('data', (data) => { output += data; }); backend.stderr.on('data', (data) => { errors += data; });
  try {
    let address;
    for (let i = 0; i < 100; i++) {
      address = output.split('\n').flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } }).find((item) => item.type === 'backend-address');
      if (address) break;
      if (backend.exitCode !== null) throw new Error(errors);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert(address, 'Backend address was not announced: ' + errors + output);
    const origin = `http://127.0.0.1:${address.port}`;
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(origin + '/health')).ok) break; } catch { }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const args = [path.resolve(__dirname, '..')];
    if (process.platform === 'linux' && process.getuid?.() === 0) args.unshift('--no-sandbox');
    desktop = await electron.launch({ args, env: { ...process.env, ELECTRON_RUN_AS_NODE: '', EVIDENCEMESH_API: origin,
      EVIDENCEMESH_USER_DATA: path.join(temporary, 'desktop') } });
    const window = await desktop.firstWindow();
    const pageErrors = []; window.on('pageerror', (error) => pageErrors.push(String(error)));
    await window.waitForFunction(() => document.querySelector('#status').textContent.includes('Engine connected'));
    await window.fill('#case-name', 'v0.4 workflow'); await window.click('#create-case');
    await window.waitForSelector('#inspect-disk-image');
    await window.fill('#import-acquisition_id', 'v04-e2e');
    await window.fill('#import-extracted_at', '2026-09-16T09:35:00Z');
    await window.fill('#import-mount_point', 'C:\\');
    await desktop.evaluate(({ dialog }, filename) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filename] }); }, disk);
    await window.click('#inspect-disk-image');
    await window.waitForSelector('#disk-image-panel');
    assert((await window.locator('#disk-image-panel').textContent()).includes('NTFS 12345678AABBCCDD'));
    for (const kind of ['mft', 'usn', 'evtx', 'amcache']) await window.locator(`[data-disk-kind="${kind}"]`).uncheck();
    await window.getByRole('button', { name: 'Extract selected artifacts', exact: true }).click();
    await window.waitForFunction(() => document.querySelector('#status').textContent.includes('imported 1 disk events'));
    assert.deepEqual(await readFile(disk), original);
    await window.getByRole('button', { name: 'Check dependencies', exact: true }).click();
    await window.waitForSelector('#dependencies-table');
    assert((await window.locator('#dependencies-table').textContent()).includes('Volatility 3'));
    await desktop.evaluate(({ dialog }, filename) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filename] }); }, keylog);
    await window.getByRole('button', { name: 'Choose key log', exact: true }).click();
    await window.waitForFunction((filename) => document.querySelector('#import-tls_keylog_file').value === filename, keylog);
    await desktop.evaluate(({ dialog }, filename) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filename] }); }, capture);
    await window.click('#import-network');
    await window.waitForFunction(() => document.querySelector('#status').textContent.includes('Parser Runs contains details'));
    const cases = await window.evaluate(() => window.evidenceMesh.request('GET', '/cases'));
    const events = await window.evaluate((id) => window.evidenceMesh.request('GET', `/cases/${id}/events`), cases[0].case_id);
    const decrypted = events.find((event) => event.network?.http?.body_sha256);
    assert(decrypted?.network.http.decrypted_with_supplied_key);
    assert.equal(decrypted.network.http.body_size, 25);
    assert(events.some((event) => event.artifact_type === 'Prefetch' && event.provenance.length >= 2));
    const generated = spawnSync(python, ['scripts/generate_ui_benchmark.py', '--database', path.join(temporary, 'case.sqlite3')], { cwd: root, encoding: 'utf8', timeout: 180000 });
    assert.equal(generated.status, 0, generated.stderr);
    const performanceCases = JSON.parse(generated.stdout);
    await window.click('#refresh');
    await window.waitForFunction(() => !document.querySelector('#refresh').disabled);
    for (const testCase of performanceCases) {
      const started = Date.now();
      await window.selectOption('#case-select', testCase.case_id);
      await window.waitForFunction((id) => document.querySelector('#case-id').textContent === id && !document.querySelector('#refresh').disabled, testCase.case_id);
      assert((await window.locator('#status').textContent()).includes('100 events per page'));
      for (const view of ['processes', 'files', 'connections', 'timeline']) {
        await window.locator(`#navigation [data-view="${view}"]`).click();
        await window.waitForSelector('#server-pagination');
        await window.waitForFunction(() => document.querySelector('#workspace-content').getAttribute('aria-busy') === 'false');
        const tableId = view === 'processes' ? 'process-table' : view === 'timeline' ? 'timeline-table' : 'evidence-table';
        assert.equal(await window.locator(`#${tableId} tbody tr`).count(), 100, `${testCase.count} ${view}`);
        assert.equal(await window.evaluate('events.length'), 100);
        const first = await window.locator(`#${tableId} tbody tr`).first().getAttribute('data-event-id');
        await window.click('#next-event-page');
        await window.waitForFunction(() => document.querySelector('#server-pagination').textContent.includes('101–200'));
        assert.notEqual(await window.locator(`#${tableId} tbody tr`).first().getAttribute('data-event-id'), first);
      }
      console.log(`PASS UI ${testCase.count}: process/files/network/timeline, 100 events buffered, next page, ${Date.now() - started} ms`);
    }
    assert.equal(pageErrors.length, 0, pageErrors.join('\n'));
    console.log('PASS v0.4 desktop: native disk picker, volume tree, artifact selection, read-only extraction, dependencies, supplied TLS key picker, actual decrypted body import, provenance');
  } finally {
    await desktop?.close();
    backend.stdin.end('quit\n');
    await Promise.race([new Promise((resolve) => backend.once('exit', resolve)), new Promise((resolve) => setTimeout(resolve, 5000))]);
    if (backend.exitCode === null) backend.kill('SIGKILL');
    if (process.env.EVIDENCEMESH_KEEP_E2E_DATA) console.log('E2E workspace: ' + temporary);
    else await rm(temporary, { recursive: true, force: true });
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
