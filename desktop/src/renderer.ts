type EvidenceEvent = import('./types').EventRecord;
type EvidenceCase = import('./types').CaseRecord;
type EvidenceCorrelation = import('./types').Correlation;
type EvidenceGraph = import('./types').Graph;
type EvidenceAnalysis = import('./types').Analysis;
type EvidenceRun = import('./types').ParserRun;
type InspectorSelection = { event: EvidenceEvent } | { edge: EvidenceCorrelation } | { run: EvidenceRun } | { relationship: import('./types').GraphEdge };
type View = 'case' | 'evidence' | 'processes' | 'memory-network' | 'dlls' | 'handles' | 'regions' | 'services' | 'modules' | 'memory-registry' | 'files' | 'mft' | 'usn' | 'prefetch' | 'event-logs' | 'amcache' | 'connections' | 'dns' | 'http' | 'tls' | 'correlations' | 'timeline' | 'graph' | 'parser-runs';

const U = MeshUI;
const element = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const found = document.getElementById(id); if (!found) throw new Error(`Missing UI element ${id}`); return found as T;
};
const api = async <T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> =>
  window.evidenceMesh.request(method, path, body) as Promise<T>;
const titles: Record<View, string> = { case: 'Case / Evidence', evidence: 'All evidence', processes: 'Processes',
  'memory-network': 'Memory sockets', dlls: 'Loaded DLLs', files: 'Disk files', mft: '$MFT records', usn: '$UsnJrnl records',
  prefetch: 'Prefetch references', connections: 'Network connections', dns: 'DNS observations', http: 'HTTP observations',
  tls: 'TLS observations', correlations: 'Correlations', timeline: 'Timeline', graph: 'Incident Graph',
  handles: 'Handles / File objects', regions: 'Memory regions', services: 'Services', modules: 'Modules / Drivers / Callbacks',
  'memory-registry': 'Memory registry artifacts', 'event-logs': 'Event logs', amcache: 'Disk Amcache', 'parser-runs': 'Parser Runs' };
let currentCase: EvidenceCase | undefined, events: EvidenceEvent[] = [], cases: EvidenceCase[] = [];
let root: EvidenceEvent | undefined, selection: InspectorSelection | undefined, graph: EvidenceGraph | undefined;
let analysis: EvidenceAnalysis | undefined, incidentEvents: EvidenceEvent[] = [];
let view: View = 'case', inspectorTab = 'Overview', graphMode = 'events', onlyIncident = true, busy = false;
let parserRuns: EvidenceRun[] = [], timelineSource = '', timelineCategory = '', processTab = 'Overview';
let savedImportContext: Record<string, string> = {};
type EventPage = { events: EvidenceEvent[]; total: number; offset: number; limit: number;
  counts: Record<string, number> & { sources: Record<string, number> }; revision: number };
let eventPage: EventPage | undefined;
let pageSearchTimer: ReturnType<typeof setTimeout> | undefined;
let graphDepth = 2, graphLimit = 500, graphScore = 0, graphTypes = '';
const largeCase = (): boolean => (currentCase?.event_count ?? 0) > 2000;
const pagedRoute = (route: View): boolean => largeCase() && !['case', 'graph', 'correlations', 'parser-runs'].includes(route)
  && !(route === 'timeline' && onlyIncident && !!analysis);
const sourceCount = (source: string): number => largeCase() ? eventPage?.counts.sources[source] ?? 0 : events.filter((event) => event.source === source).length;

async function loadEventPage(route: View, offset = 0): Promise<void> {
  if (!currentCase) return;
  const id = currentCase.case_id;
  const parameters = new URLSearchParams({ view: route, limit: '100', offset: String(offset), query: element<HTMLInputElement>('search').value.trim() });
  if (route === 'timeline') {
    if (timelineSource) parameters.set('source', timelineSource);
    if (timelineCategory) parameters.set('category', timelineCategory);
  }
  const result = await api<EventPage>('GET', `/cases/${id}/event-page?${parameters}`);
  if (currentCase?.case_id !== id) return;
  eventPage = result; events = result.events;
}
function refreshPagedView(offset = 0): void {
  if (pageSearchTimer) clearTimeout(pageSearchTimer);
  if (busy) { pageSearchTimer = setTimeout(() => refreshPagedView(offset), 200); return; }
  if (!pagedRoute(view)) { renderWorkspace(); return; }
  void action(async () => { await loadEventPage(view, offset); renderNavigation(); renderWorkspace(); });
}

function setStatus(message: string, error = false): void { element('status').textContent = message; element('status').classList.toggle('error', error); }
function controls(): void {
  for (const id of ['load-sample', 'refresh']) element<HTMLButtonElement>(id).disabled = busy;
  element<HTMLSelectElement>('case-select').disabled = busy;
  element<HTMLButtonElement>('analyze').disabled = busy || !root;
  element<HTMLButtonElement>('import-events').disabled = busy || !currentCase;
  for (const kind of ['memory', 'disk', 'network']) { const button = document.getElementById(`import-${kind}`) as HTMLButtonElement | null; if (button) button.disabled = busy || !currentCase; }
  for (const id of ['analyze-memory-image', 'inspect-disk-image']) {
    const button = document.getElementById(id) as HTMLButtonElement | null; if (button) button.disabled = busy || !currentCase;
  }
  const previousPage = document.getElementById('previous-event-page') as HTMLButtonElement | null;
  const nextPage = document.getElementById('next-event-page') as HTMLButtonElement | null;
  if (previousPage) previousPage.disabled = busy || !eventPage || eventPage.offset === 0;
  if (nextPage) nextPage.disabled = busy || !eventPage || eventPage.offset + 100 >= eventPage.total;
  const create = document.getElementById('create-case') as HTMLButtonElement | null; if (create) create.disabled = busy;
  element('workspace-content').setAttribute('aria-busy', String(busy));
}
async function action(work: () => Promise<void>): Promise<void> {
  if (busy) return; busy = true; controls();
  try { await work(); } catch (error) { setStatus(error instanceof Error ? error.message : String(error), true); }
  finally { busy = false; controls(); }
}
function eventById(id: string): EvidenceEvent | undefined { return events.find((item) => item.event_id === id)
  ?? incidentEvents.find((item) => item.event_id === id) ?? graph?.supporting_events?.find((item) => item.event_id === id)
  ?? (root?.event_id === id ? root : undefined); }
function eventKind(event?: EvidenceEvent): string {
  if (!event) return 'Event';
  if (event.service) return 'Service'; if (event.memory_region) return 'MemoryRegion'; if (event.registry) return 'RegistryArtifact';
  if (event.network?.dns_query) return 'Domain'; if (event.network) return 'IP'; if (event.file) return 'File';
  if (event.process) return 'Process'; return 'Event';
}
function label(event?: EvidenceEvent): string {
  if (!event) return 'Unknown event';
  if (event.service) return event.service.name; if (event.network?.tls?.sni) return event.network.tls.sni;
  if (event.memory_region) return `${event.memory_region.start} ${event.memory_region.protection ?? ''}`;
  if (event.driver) return event.driver.name ?? 'Driver'; if (event.callback) return `${event.callback.type} ${event.callback.address}`;
  if (event.network?.dns_query) return event.network.dns_query;
  if (event.network) {
    const ip = event.network.dst_ip ?? event.network.src_ip ?? '*', port = event.network.dst_ip ? event.network.dst_port : event.network.src_port;
    return `${ip.includes(':') ? `[${ip}]` : ip}:${port ?? '*'}`;
  }
  if (event.file) return event.file.path?.split(/[\\/]/).pop() ?? event.file.name ?? event.type;
  return event.process ? event.process.name ?? `PID ${event.process.pid}` : event.type;
}
function time(value?: string | null, full = false): string {
  if (!value) return '—'; const date = new Date(value); if (Number.isNaN(date.valueOf())) return value;
  return full ? date.toISOString().replace('T', ' ') : date.toISOString().slice(11, 23);
}
function processes(): EvidenceEvent[] {
  const records = events.filter((event) => event.source === 'memory' && event.process && ['process_start', 'process_observation', 'process'].includes(event.type));
  return records.length ? records : events.filter((event) => event.source === 'memory' && event.process);
}
function visibleEvents(route: View): EvidenceEvent[] {
  switch (route) {
    case 'processes': return processes();
    case 'memory-network': return events.filter((event) => event.source === 'memory' && event.network);
    case 'dlls': return events.filter((event) => event.type === 'module_load');
    case 'handles': return events.filter((event) => event.handle || event.type === 'file_object_observation');
    case 'regions': return events.filter((event) => event.memory_region);
    case 'services': return events.filter((event) => event.service);
    case 'modules': return events.filter((event) => event.module && !event.process || event.driver || event.callback);
    case 'memory-registry': return events.filter((event) => event.source === 'memory' && event.registry);
    case 'files': return events.filter((event) => event.source === 'disk' && event.file);
    case 'mft': return events.filter((event) => event.source_artifact?.kind === '$MFT');
    case 'usn': return events.filter((event) => event.source_artifact?.kind === '$UsnJrnl');
    case 'prefetch': return events.filter((event) => event.type === 'prefetch' || event.source_artifact?.kind === 'Prefetch');
    case 'event-logs': return events.filter((event) => event.event_log);
    case 'amcache': return events.filter((event) => event.source === 'disk' && event.registry?.artifact === 'amcache');
    case 'connections': return events.filter((event) => event.source === 'network' && event.network && !event.network.dns_query);
    case 'dns': return events.filter((event) => event.network?.dns_query);
    case 'http': return events.filter((event) => event.type.startsWith('http'));
    case 'tls': return events.filter((event) => event.type.startsWith('tls'));
    case 'timeline': return (analysis && onlyIncident ? incidentEvents : events).filter((event) =>
      (!timelineSource || event.source === timelineSource) && (!timelineCategory ||
        (timelineCategory === 'dns' ? !!event.network?.dns_query : timelineCategory === 'connection' ? !!event.network && !event.network.dns_query :
          !!event[timelineCategory as 'process' | 'file' | 'registry' | 'service'])));
    default: return events;
  }
}
function filter<T>(records: T[]): T[] {
  const query = element<HTMLInputElement>('search').value.trim().toLowerCase();
  return query ? records.filter((record) => JSON.stringify(record).toLowerCase().includes(query)) : records;
}
function clearAnalysis(): void { analysis = undefined; graph = undefined; incidentEvents = []; }
function revealInspector(): void {
  document.querySelector('.app-shell')?.classList.remove('inspector-collapsed');
  const control = document.querySelector<HTMLButtonElement>('[data-expand-graph]');
  if (control) control.textContent = 'Expand graph';
}
function navigate(route: View): void {
  if (busy) return; view = route; document.querySelector('.app-shell')?.classList.remove('inspector-collapsed');
  element<HTMLInputElement>('search').value = '';
  if (pagedRoute(route)) refreshPagedView(); else { renderNavigation(); renderWorkspace(); }
}
function navButton(route: View, name: string, kind = 'Event', count?: number): HTMLButtonElement {
  const button = U.button('', () => navigate(route), route === view ? 'active' : ''); button.dataset.view = route;
  button.setAttribute('aria-current', String(route === view)); button.append(U.icon(kind, 13), U.el('span', name));
  if (count !== undefined) button.append(U.el('span', String(count), 'count')); return button;
}
function renderNavigation(): void {
  const rail = element('rail'); rail.replaceChildren();
  for (const [route, name, kind] of [['case', 'CASE', 'Case'], ['processes', 'PROCESS', 'Process'], ['connections', 'NETWORK', 'IP'], ['timeline', 'TIMELINE', 'Timeline'], ['graph', 'GRAPH', 'Graph']] as [View, string, string][]) {
    const button = navButton(route, name, kind); button.replaceChildren(U.icon(kind, 21), U.el('span', name)); rail.append(button);
  }
  rail.append(U.el('div', 'LOCAL\nENGINE', 'rail-footer'));
  const navigation = element('navigation');
  const openGroups = new Set([...navigation.querySelectorAll<HTMLDetailsElement>('details[open]')].map((group) => group.dataset.group));
  const first = navigation.childElementCount === 0; navigation.replaceChildren();
  navigation.append(U.el('div', 'EVIDENCE', 'nav-section-label'), navButton('evidence', 'All evidence', 'Case', currentCase?.event_count ?? events.length));
  const groups: [string, string, [View, string, string][]][] = [
    ['Memory', 'memory', [['processes', 'Processes', 'Process'], ['memory-network', 'Network', 'IP'], ['dlls', 'DLLs', 'File'], ['handles', 'Handles / Files', 'File'], ['regions', 'Memory Regions', 'Event'], ['services', 'Services', 'Process'], ['modules', 'Modules / Drivers', 'File'], ['memory-registry', 'Registry Artifacts', 'Registry']]],
    ['Disk', 'disk', [['files', 'Files', 'File'], ['mft', 'MFT', 'File'], ['usn', 'USN', 'File'], ['prefetch', 'Prefetch', 'Event'], ['event-logs', 'Event Logs', 'Event'], ['amcache', 'Amcache', 'Registry']]],
    ['Network', 'network', [['connections', 'Flows / Connections', 'IP'], ['dns', 'DNS', 'Domain'], ['http', 'HTTP', 'Event'], ['tls', 'TLS', 'Event']]],
  ];
  for (const [name, source, children] of groups) {
    const group = U.el('details'); group.dataset.group = source; group.open = first || openGroups.has(source);
    const count = sourceCount(source);
    const summary = U.el('summary', name); summary.append(U.badge(count ? `${count} LOADED` : 'EMPTY', count ? 'success' : 'neutral'));
    const container = U.el('div', '', 'nav-children');
    for (const [route, title, kind] of children) container.append(navButton(route, title, kind, largeCase() ? eventPage?.counts[route] ?? 0 : visibleEvents(route).length));
    group.append(summary, container); navigation.append(group);
  }
  navigation.append(U.el('div', 'INVESTIGATION', 'nav-section-label'), navButton('correlations', 'Correlations', 'Graph', analysis?.correlation_count),
    navButton('timeline', 'Timeline', 'Timeline'), navButton('graph', 'Incident Graph', 'Graph'), navButton('parser-runs', 'Parser Runs', 'Event', parserRuns.length));
  const tabs = element('workspace-tabs'); tabs.replaceChildren();
  for (const route of ['case', 'processes', 'evidence', 'correlations', 'timeline', 'graph'] as View[]) {
    const button = U.button(titles[route], () => navigate(route), route === view ? 'active' : ''); button.dataset.view = route; tabs.append(button);
  }
}
function renderRoot(): void {
  const summary = element('root-summary'); summary.replaceChildren(U.el('span', 'SELECTED PROCESS', 'eyebrow'));
  if (root) summary.append(U.el('h3', label(root)), U.el('span', `PID ${root.process?.pid} · MEMORY`, 'mono small'), U.el('p', root.process?.command_line ?? 'Command line not recorded', 'mono muted'));
  else summary.append(U.el('p', 'Select a process to trace its evidence.', 'muted'));
}
function selectEvent(event: EvidenceEvent, asRoot = false): void {
  if (busy) return;
  revealInspector();
  if (asRoot && root?.event_id !== event.event_id) { root = event; clearAnalysis(); renderRoot(); renderNavigation(); }
  selection = { event }; inspectorTab = 'Overview'; processTab = 'Overview'; renderInspector(); controls();
  if (asRoot) setStatus(`Selected ${label(event)} · PID ${event.process?.pid}. Ready to correlate.`);
}
function selectEdge(edge: EvidenceCorrelation): void {
  if (busy) return; selection = { edge }; inspectorTab = 'Overview'; renderInspector();
  revealInspector();
  for (const path of document.querySelectorAll<SVGPathElement>('.graph-edge')) path.classList.toggle('selected', path.dataset.pair === `${edge.source_event}:${edge.target_event}`);
}
async function refreshCases(): Promise<void> {
  cases = await api<EvidenceCase[]>('GET', '/cases');
  const select = element<HTMLSelectElement>('case-select'); select.replaceChildren(new Option('Select a case', ''));
  for (const item of cases) select.add(new Option(`${item.name} (${item.event_count})`, item.case_id)); select.value = currentCase?.case_id ?? '';
}
async function openCase(id: string): Promise<void> {
  [currentCase, parserRuns] = await Promise.all([api<EvidenceCase>('GET', `/cases/${id}`), api<EvidenceRun[]>('GET', `/cases/${id}/parser-runs`)]);
  eventPage = undefined; element<HTMLInputElement>('search').value = '';
  if (largeCase()) await loadEventPage('evidence');
  else events = await api<EvidenceEvent[]>('GET', `/cases/${id}/events?limit=2000`);
  await refreshMemoryJobs(id);
  root = undefined; selection = undefined; clearAnalysis();
  element('case-title').textContent = currentCase.name; element('case-id').textContent = currentCase.case_id;
  element('status-counts').textContent = ['memory', 'disk', 'network'].map((source) => `${source.toUpperCase()} ${sourceCount(source)}`).join(' · ');
  await refreshCases(); view = 'case'; element<HTMLInputElement>('search').value = '';
  renderRoot(); renderNavigation(); renderWorkspace(); renderInspector(); setStatus(largeCase() ? `${currentCase.event_count.toLocaleString()} events available. Tables load 100 events per page.` : `Loaded ${events.length} events. Select a memory process to analyze.`);
}
function section(title: string): HTMLElement { const node = U.el('div', '', 'inspector-section'); node.append(U.el('h3', title)); return node; }
function artifactImportForm(): HTMLElement {
  const form = U.el('form', '', 'artifact-import'); form.append(U.el('h3', 'Import source artifacts'));
  const fields = U.el('div', '', 'import-fields');
  const inputs: Record<string, HTMLInputElement> = {};
  for (const [key, name, placeholder, required] of [
    ['acquisition_id', 'Acquisition / image ID', 'case-01-memory', true],
    ['extracted_at', 'Extraction timestamp with timezone', '2026-09-16T09:35:00Z', true],
    ['hostname', 'Evidence host (optional)', 'workstation-01', false],
    ['volume_id', 'Disk volume ID (optional)', 'volume-C', false],
    ['mount_point', 'Known disk drive mapping (optional)', 'C:\\', false],
    ['recovered_directory', 'Recovered files folder (dumpfiles)', '/analysis/recovered', false],
    ['timezone', 'Source timezone for naive timestamps', 'UTC', false],
    ['logical_path', 'Original path for a recovered disk file', 'C:\\Users\\test\\AppData\\Local\\Temp\\a.ps1', false],
    ['tls_keylog_file', 'Supplied TLS key log (optional)', 'Choose a key log to enable TLS decryption', false],
  ] as [string, string, string, boolean][]) {
    const label = U.el('label', name), input = U.el('input'); input.id = `import-${key}`; input.placeholder = placeholder;
    input.required = required; input.value = savedImportContext[key] ?? ''; inputs[key] = input; label.append(input); fields.append(label);
    if (key === 'logical_path') label.hidden = true;
  }
  const format = U.el('select'); format.id = 'disk-format'; format.setAttribute('aria-label', 'Disk artifact format');
  for (const kind of ['mft', 'usn', 'prefetch', 'evtx', 'amcache', 'file']) format.add(new Option(kind.toUpperCase(), kind));
  format.addEventListener('change', () => { inputs.logical_path.parentElement!.hidden = format.value !== 'file'; });
  const actions = U.el('div', '', 'import-actions');
  for (const [kind, title] of [['memory', 'Import Memory'], ['disk', 'Import Disk'], ['network', 'Import PCAP']]) {
    const button = U.button(title, () => {
      if (!form.reportValidity()) return;
      savedImportContext = Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value.trim()]));
      void action(async () => {
        if (!currentCase) return;
        const context = { acquisition_id: inputs.acquisition_id.value.trim(), extracted_at: inputs.extracted_at.value.trim(),
          hostname: inputs.hostname.value.trim() || null, volume_id: inputs.volume_id.value.trim() || null,
          recovered_directory: inputs.recovered_directory.value.trim() || null, timezone: inputs.timezone.value.trim() || null };
        const supplied = { ...context, logical_path: inputs.logical_path.value.trim() || null,
          mount_point: inputs.mount_point.value.trim() || null,
          tls_keylog_file: kind === 'network' ? inputs.tls_keylog_file.value.trim() || null : null };
        setStatus(`Importing ${kind} evidence…`);
        const result = await window.evidenceMesh.importArtifact(currentCase.case_id, kind, supplied, kind === 'disk' ? format.value : undefined);
        if (result) {
          await openCase(currentCase.case_id);
          setStatus(`${result.status}: imported ${result.imported} events. Parser Runs contains details.`, result.status === 'FAILED');
          if (result.status !== 'SUCCESS') { view = 'parser-runs'; renderNavigation(); renderWorkspace(); }
        }
      });
    }); button.id = `import-${kind}`; button.disabled = busy; actions.append(button);
    if (kind === 'disk') actions.append(format);
  }
  const rawOptions = U.el('details'); rawOptions.append(U.el('summary', 'Raw memory options'));
  inputs.tls_keylog_file.parentElement!.append(U.button('Choose key log', () => {
    void window.evidenceMesh.selectTLSKeylog().then((path) => {
      if (path) { inputs.tls_keylog_file.value = path; savedImportContext.tls_keylog_file = path; }
    }).catch((error) => setStatus(String(error), true));
  }));
  const pluginOptions = U.el('div', '', 'import-fields');
  const selectedPlugins = rawMemoryPlugins.map((plugin) => {
    const label = U.el('label', plugin), input = U.el('input'); input.type = 'checkbox'; input.checked = true;
    label.prepend(input); pluginOptions.append(label); return { plugin, input };
  });
  const rerunLabel = U.el('label', 'Re-run plugins instead of using verified cache'), rerun = U.el('input');
  rerun.type = 'checkbox'; rerunLabel.prepend(rerun);
  const objectsLabel = U.el('label', 'Optional FILE_OBJECT virtual addresses to extract (hex, comma separated)');
  const objects = U.el('input'); objects.id = 'memory-file-objects'; objectsLabel.append(objects);
  rawOptions.append(pluginOptions, rerunLabel, objectsLabel);
  const rawButton = U.button('Analyze memory image', () => {
    if (!form.reportValidity()) return;
    savedImportContext = Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value.trim()]));
    void action(async () => {
      if (!currentCase) return;
      const fileObjects = objects.value.split(',').map((value) => value.trim()).filter(Boolean);
      const plugins = selectedPlugins.filter((choice) => choice.input.checked).map((choice) => choice.plugin);
      if (fileObjects.length) plugins.push('windows.dumpfiles');
      const result = await window.evidenceMesh.startMemoryAnalysis(currentCase.case_id, {
        context: { acquisition_id: inputs.acquisition_id.value.trim(), extracted_at: inputs.extracted_at.value.trim(),
          hostname: inputs.hostname.value.trim() || null, timezone: inputs.timezone.value.trim() || null },
        plugins, rerun: rerun.checked, file_objects: fileObjects,
      });
      if (result) {
        memoryJobs.push(result); renderWorkspace(); await refreshMemoryJobs(currentCase.case_id);
        setStatus('Memory analysis started. Progress and cancellation are available in the case workspace.');
      }
    });
  }); rawButton.id = 'analyze-memory-image'; rawButton.disabled = busy;
  const diskButton = U.button('Inspect disk image', () => {
    if (!form.reportValidity()) return;
    savedImportContext = Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value.trim()]));
    void action(async () => {
      if (!currentCase) return;
      const caseId = currentCase.case_id;
      const context = { acquisition_id: inputs.acquisition_id.value.trim(), extracted_at: inputs.extracted_at.value.trim(),
        hostname: inputs.hostname.value.trim() || null, mount_point: inputs.mount_point.value.trim() || null,
        timezone: inputs.timezone.value.trim() || null };
      setStatus('Reading disk partitions and discovering NTFS artifacts…');
      const report = await window.evidenceMesh.inspectDiskImage(caseId, context);
      if (report && currentCase?.case_id === caseId) {
        diskInspection = { caseId, report, context }; renderWorkspace();
        setStatus(`Detected ${report.volumes.length} volumes. Choose volumes and artifacts to extract.`);
      }
    });
  }); diskButton.id = 'inspect-disk-image'; diskButton.disabled = busy;
  actions.append(rawButton, diskButton); form.append(rawOptions);
  form.append(fields, actions, U.el('p', 'Select a Volatility export folder, disk artifact or packet capture. Originals remain read-only.', 'muted small'));
  if (diskInspection?.caseId === currentCase?.case_id) form.append(diskImagePanel());
  form.addEventListener('submit', (event) => event.preventDefault()); return form;
}
function renderCase(): HTMLElement {
  const container = U.el('div', '', 'case-overview'), heading = U.el('div', '', 'section-heading');
  heading.append(U.el('h2', 'Investigation workspace'));
  const form = U.el('form', '', 'case-form'), input = U.el('input'); input.id = 'case-name'; input.placeholder = 'New case name'; input.maxLength = 200; input.required = true; input.setAttribute('aria-label', 'New case name');
  const create = U.el('button', '＋ Create case'); create.id = 'create-case'; create.type = 'submit'; form.append(input, create);
  form.addEventListener('submit', (event) => { event.preventDefault(); void action(async () => { const name = input.value.trim(); if (!name) throw new Error('Enter a case name.'); const created = await api<EvidenceCase>('POST', '/cases', { name }); await openCase(created.case_id); }); });
  heading.append(form); container.append(heading);
  if (currentCase) {
    const facts = U.el('div', '', 'case-facts'); facts.append(U.fields([['CASE', currentCase.name], ['IDENTIFIER', currentCase.case_id]]),
      U.fields([['EVIDENCE REVISION', currentCase.revision], ['ANALYSIS', analysis ? `${analysis.correlation_count} links · current selection` : currentCase.analysis_revision === currentCase.revision ? 'Stored analysis available; select a process to analyze' : 'Analysis required']]));
    container.append(facts, artifactImportForm(), memoryJobPanel());
  } else container.append(U.el('p', 'Open an existing case, create an investigation, or load the synthetic sample evidence.', 'muted'));
  const sourceRows = ['memory', 'disk', 'network'].map((source) => ({ source, count: sourceCount(source),
    artifacts: largeCase() ? 'See Parser Runs' : new Set(events.filter((event) => event.source === source).map((event) => event.source_artifact?.artifact_id).filter(Boolean)).size }));
  container.append(U.table(sourceRows, [
    { label: 'EVIDENCE SOURCE', value: (row) => U.named(row.source === 'memory' ? 'Process' : row.source === 'disk' ? 'File' : 'IP', row.source.toUpperCase()) },
    { label: 'EVENTS', value: (row) => row.count }, { label: 'ARTIFACTS', value: (row) => row.artifacts },
    { label: 'STATUS', value: (row) => U.badge(row.count ? '✓ Loaded' : 'No events', row.count ? 'success' : 'neutral') },
    { label: 'NEXT ACTION', value: (row) => row.source === 'memory' ? 'Select process → Analyze' : 'Inspect normalized evidence' },
  ], (row) => row.source, (row) => navigate(row.source === 'memory' ? 'processes' : row.source === 'disk' ? 'files' : 'connections'), undefined, 'source-table'));
  container.append(U.el('p', 'Analysis path: Process → Related evidence → Score & reasons → Provenance → Timeline / Graph', 'muted small'));
  container.append(runtimePanel());
  return container;
}
function eventColumns(): MeshUI.Column<EvidenceEvent>[] {
  if (view === 'processes') return [
    { label: 'PID', value: (event) => U.mono(event.process?.pid), sort: (event) => event.process?.pid ?? 0 },
    { label: 'PPID', value: (event) => U.mono(event.process?.ppid), sort: (event) => event.process?.ppid ?? 0 },
    { label: 'PROCESS', value: (event) => U.named('Process', label(event)) },
    { label: 'CREATED · UTC', value: (event) => U.mono(time(event.process?.creation_time)), sort: (event) => event.process?.creation_time ?? '' },
    { label: 'HOST', value: (event) => U.mono(event.hostname) },
    { label: 'SOURCE', value: (event) => U.badge(event.source.toUpperCase()) },
    { label: 'ORIGINAL ROWS', value: (event) => event.provenance?.length || 1 },
  ];
  const common: MeshUI.Column<EvidenceEvent>[] = [
    { label: 'TIME · UTC', value: (event) => U.mono(time(event.timestamp)), sort: (event) => Date.parse(event.timestamp) },
    { label: 'SOURCE', value: (event) => U.badge(event.source.toUpperCase()) },
    { label: 'EVIDENCE', value: (event) => U.named(eventKind(event), label(event)) },
  ];
  if (view === 'dlls') return [...common,
    { label: 'PID', value: (event) => U.mono(event.process?.pid) },
    { label: 'BASE ADDRESS', value: (event) => U.mono(event.module?.base_address_hex ?? (event.module?.base_address != null ? `0x${BigInt(event.module.base_address).toString(16)}` : null)) },
    { label: 'SIZE', value: (event) => U.mono(event.module?.size) },
    { label: 'DLL PATH', value: (event) => U.mono(event.file?.path) },
  ];
  if (view === 'memory-network' || view === 'connections') return [...common,
    { label: 'PID / OWNER', value: (event) => U.mono(event.process ? `${event.process.pid} / ${event.process.name ?? '—'}` : 'Not recorded') },
    { label: 'LOCAL', value: (event) => U.mono(`${event.network?.src_ip ?? '*'}:${event.network?.src_port ?? '*'}`) },
    { label: 'PROTOCOL', value: (event) => U.mono(event.network?.protocol) },
    { label: 'STATE', value: (event) => U.mono(event.network?.state) },
    { label: 'PACKETS / BYTES', value: (event) => U.mono(`${event.network?.packet_count ?? '—'} / ${event.network?.byte_count ?? '—'}`) },
  ];
  return [...common, { label: 'EVENT TYPE', value: (event) => U.mono(event.type) },
    { label: 'ARTIFACT / PLUGIN', value: (event) => event.provenance?.map((row) => row.plugin).filter((name, index, all) => all.indexOf(name) === index).join(', ') || event.source_artifact?.kind || 'Not recorded' },
    { label: 'EVENT ID', value: (event) => U.mono(event.event_id) },
  ];
}
function incidentContext(): HTMLElement {
  const bar = U.el('div', '', 'incident-context'), symbol = U.el('span', '', 'process-symbol'); symbol.append(U.icon('Process', 20));
  const info = U.el('div'); info.append(U.el('h3', label(root)), U.el('span', `PID ${root?.process?.pid} · MEMORY`, 'mono muted'));
  bar.append(symbol, info, U.badge(`${incidentEvents.length} EVENTS`), U.el('span', 'Scores belong to direct links. Related evidence can be reached through intermediate observations.', 'muted')); return bar;
}
function delta(edge: EvidenceCorrelation): string {
  const a = eventById(edge.source_event), b = eventById(edge.target_event);
  if (!a || !b || [a.timestamp_semantics, b.timestamp_semantics].includes('extraction_time')) return 'Unknown (extraction time)';
  return `${(Math.abs(Date.parse(a.timestamp) - Date.parse(b.timestamp)) / 1000).toFixed(3)} sec`;
}
function renderWorkspace(): void {
  const content = element('workspace-content'); content.replaceChildren();
  element<HTMLInputElement>('search').disabled = view === 'case' || view === 'graph';
  element('view-title').textContent = titles[view]; element('breadcrumb').textContent = `EvidenceMesh / ${currentCase?.name ?? 'Investigation'} / ${titles[view]}`;
  element('view-context').textContent = root && ['correlations', 'timeline', 'graph'].includes(view) ? `${label(root)} · PID ${root.process?.pid}` : currentCase?.name ?? 'No case selected';
  let count = 0;
  if (view === 'case') { content.append(renderCase()); count = events.length; }
  else if (!currentCase) content.append(U.empty('No case selected', 'Load Sample Evidence or create a case to begin.'));
  else if (view === 'parser-runs') {
    count = parserRuns.length;
    if (!count) content.append(U.empty('No parser runs recorded', 'Import source artifacts to record parser outcomes.'));
    else content.append(U.table(filter(parserRuns), [
      { label: 'PARSER / PLUGIN', value: (run) => run.plugin ?? run.parser },
      { label: 'SOURCE', value: (run) => run.source.toUpperCase() },
      { label: 'STATUS', value: (run) => U.badge(run.status, run.status === 'SUCCESS' ? 'success' : 'warning') },
      { label: 'EVENTS / ROWS', value: (run) => `${run.event_count} / ${run.row_count}` },
      { label: 'ARTIFACT', value: (run) => run.artifact?.path ?? 'Not recorded' },
      { label: 'DETAIL', value: (run) => run.error ?? run.warnings.join(' · ') },
    ], (run) => run.run_id, (run) => { selection = { run }; inspectorTab = 'Overview'; revealInspector(); renderInspector(); }, undefined, 'parser-runs-table'));
  }
  else if (view === 'correlations' || view === 'graph') {
    if (!analysis) content.append(U.empty('Select a process and analyze', 'Open Processes, choose an observation, and run Analyze Evidence to find related disk and network evidence.'));
    else {
      content.append(incidentContext()); count = analysis.correlation_count;
      if (view === 'graph') renderGraph(content);
      else if (!analysis.correlations.length) content.append(U.empty('No matching evidence', 'No pair met the rule requirements and score threshold for this selected process.'));
      else content.append(U.table(filter(analysis.correlations), [
        { label: 'SCORE / 100', value: (edge) => U.el('span', String(edge.score), `score-badge ${edge.score >= 80 ? 'score-high' : ''}`), sort: (edge) => edge.score },
        { label: 'FROM', value: (edge) => U.named(eventKind(eventById(edge.source_event)!), label(eventById(edge.source_event))) },
        { label: 'TO', value: (edge) => U.named(eventKind(eventById(edge.target_event)!), label(eventById(edge.target_event))) },
        { label: 'TIME DELTA', value: (edge) => U.mono(delta(edge)) },
        { label: 'EVIDENCE RULES', value: (edge) => edge.reasons.map((reason) => reason.rule.replaceAll('_', ' ')).join(' · ') },
      ], (edge) => `${edge.source_event}:${edge.target_event}`, selectEdge, selection && 'edge' in selection ? `${selection.edge.source_event}:${selection.edge.target_event}` : undefined, 'correlation-table'));
    }
  } else {
    if (view === 'timeline') {
      const options = U.el('div', '', 'view-options'), label = U.el('label'), input = U.el('input'); input.type = 'checkbox'; input.id = 'incident-only'; input.checked = onlyIncident && !!analysis; input.disabled = !analysis;
      input.addEventListener('change', () => { onlyIncident = input.checked; refreshPagedView(); }); label.append(input, U.el('span', 'Selected incident only'));
      options.append(label);
      for (const [id, values, selected] of [
        ['timeline-source', ['', 'memory', 'disk', 'network'], timelineSource],
        ['timeline-category', ['', 'process', 'file', 'registry', 'dns', 'connection', 'service'], timelineCategory],
      ] as [string, string[], string][]) {
        const select = U.el('select'); select.id = id; select.setAttribute('aria-label', id.replace('-', ' '));
        for (const value of values) select.add(new Option(value ? value.toUpperCase() : 'ALL ' + id.split('-')[1].toUpperCase(), value));
        select.value = selected; select.addEventListener('change', () => { if (id.endsWith('source')) timelineSource = select.value; else timelineCategory = select.value; refreshPagedView(); }); options.append(select);
      }
      content.append(options);
    }
    const records = filter(visibleEvents(view)); count = records.length;
    if (pagedRoute(view) && eventPage) {
      const paging = U.el('div', '', 'view-options'); paging.id = 'server-pagination';
      const previous = U.button('Previous 100', () => refreshPagedView(Math.max(0, eventPage!.offset - 100)));
      const next = U.button('Next 100', () => refreshPagedView(eventPage!.offset + 100));
      previous.id = 'previous-event-page'; next.id = 'next-event-page';
      previous.disabled = busy || eventPage.offset === 0; next.disabled = busy || eventPage.offset + 100 >= eventPage.total;
      paging.append(previous, U.el('span', `${eventPage.total ? eventPage.offset + 1 : 0}–${Math.min(eventPage.offset + events.length, eventPage.total)} of ${eventPage.total.toLocaleString()} · sorting applies to this page`), next);
      content.append(paging);
    }
    if (records.length) content.append(U.table(records, eventColumns(), (event) => event.event_id, (event) => selectEvent(event, view === 'processes'),
      selection && 'event' in selection ? selection.event.event_id : root?.event_id, view === 'processes' ? 'process-table' : view === 'timeline' ? 'timeline-table' : 'evidence-table'));
    else content.append(U.empty(`No ${titles[view].toLowerCase()} in this view`, element<HTMLInputElement>('search').value ? 'Change the filter to see other imported evidence.' : 'This view only shows imported observations. No records have been invented for this category.'));
  }
  element('view-count').textContent = `${count} ${view === 'correlations' || view === 'graph' ? 'links' : 'events'}`;
  element('result-summary').textContent = `${count} displayed · ${currentCase?.event_count ?? events.length} total events · ${currentCase ? `revision ${currentCase.revision}` : 'no case'}`; controls();
}

function provenanceView(event: EvidenceEvent): HTMLElement {
  const panel = U.el('div');
  if (event.provenance?.length) {
    for (const [index, reference] of event.provenance.entries()) {
      const entry = U.el('details', '', 'provenance-entry'); entry.open = index === 0;
      entry.append(U.el('summary', `${reference.plugin ?? reference.source_artifact.kind} · ${reference.raw_reference.locator} · ${reference.source_artifact.path?.split(/[\\/]/).pop() ?? 'Source artifact'}`));
      const fields = U.el('div'); fields.append(U.fields([
        ['Source type', event.source], ['Adapter', `${reference.parser.name} ${reference.parser.version}`],
        ['Tool / version', `${reference.tool} ${reference.tool_version ?? '(version not recorded)'}`], ['Plugin', reference.plugin],
        ['Acquisition identifier', reference.memory_image_id ?? reference.acquisition_id], ['Original artifact', reference.source_artifact.path],
        ['Original row', `${reference.row_index} · ${reference.raw_reference.locator}`], ['Extraction timestamp', time(reference.extraction_timestamp, true)],
        ['Artifact SHA-256', reference.source_artifact.sha256],
        ['Artifact bytes', reference.source_artifact.size], ['Imported at', reference.source_artifact.imported_at],
      ])); entry.append(fields); panel.append(entry);
    }
  } else panel.append(U.fields([
    ['Source type', event.source], ['Adapter', event.parser ? `${event.parser.name} ${event.parser.version}` : null],
    ['Artifact kind', event.source_artifact?.kind], ['Original source', event.source_artifact?.path],
    ['Artifact ID', event.source_artifact?.artifact_id], ['Original row', event.raw_reference?.locator],
    ['Artifact SHA-256', event.source_artifact?.sha256], ['Observed timestamp', time(event.timestamp, true)],
  ]));
  const imported = event.attributes?.import_reference;
  if (imported) { const section = U.el('details', '', 'provenance-entry'); section.append(U.el('summary', 'JSON import reference'), U.el('pre', JSON.stringify(imported, null, 2), 'raw')); panel.append(section); }
  return panel;
}
function eventOverview(event: EvidenceEvent): HTMLElement {
  const grid = U.el('div', '', 'inspect-grid'), details = section(event.process ? 'Process / evidence detail' : 'Evidence detail');
  const values: [string, unknown][] = [['Event ID', event.event_id], ['Source / type', `${event.source.toUpperCase()} / ${event.type}`],
    ['Timestamp', time(event.timestamp, true)], ['Time meaning', event.timestamp_semantics ?? 'event_time']];
  if (event.process) values.push(['PID / PPID', `${event.process.pid} / ${event.process.ppid ?? '—'}`], ['Process', event.process.name],
    ['Created', time(event.process.creation_time, true)], ['Executable', event.process.path], ['Instance', event.process.instance_id]);
  if (event.network) values.push(['Local endpoint', `${event.network.src_ip ?? '*'}:${event.network.src_port ?? '*'}`],
    ['Remote endpoint', `${event.network.dst_ip ?? '*'}:${event.network.dst_port ?? '*'}`], ['Protocol / state', `${event.network.protocol ?? '—'} / ${event.network.state ?? '—'}`],
    ['DNS query', event.network.dns_query], ['Resolved IPs', event.network.resolved_ips?.join(', ')]);
  if (event.file) values.push(['File path', event.file.path], ['SHA-256', event.file.sha256]);
  if (event.module) values.push(['Base address', event.module.base_address_hex ?? (event.module.base_address != null ? `0x${BigInt(event.module.base_address).toString(16)}` : null)], ['Module size', event.module.size]);
  if (event.handle) values.push(['Handle type', event.handle.type], ['Handle value', event.handle.value], ['FILE_OBJECT', event.handle.object_address]);
  if (event.memory_region) values.push(['Region start / end', `${event.memory_region.start} / ${event.memory_region.end ?? '?'}`], ['Protection', event.memory_region.protection]);
  if (event.service) values.push(['Service', event.service.name], ['State', event.service.state], ['Binary', event.service.binary_path]);
  if (event.registry) values.push(['Registry artifact', event.registry.artifact], ['Hive / key', `${event.registry.hive ?? ''} ${event.registry.path ?? ''}`]);
  if (event.network?.tls) values.push(['TLS SNI', event.network.tls.sni], ['TLS version', event.network.tls.version],
    ['TLS content', event.network.tls.decryption === 'decrypted_with_supplied_key' ? 'Decrypted using supplied key log' : 'Encrypted - metadata only'],
    ['Key log', event.network.tls.key_log_supplied ? 'Supplied' : 'Not supplied']);
  if (event.network?.http) values.push(['HTTP method / status', `${event.network.http.method ?? ''} ${event.network.http.status ?? ''}`], ['Host / URI', `${event.network.http.host ?? ''}${event.network.http.uri ?? ''}`]);
  if (event.network?.http?.body_sha256) values.push(['Recovered HTTP body', event.network.http.recovered_path],
    ['Body SHA-256', event.network.http.body_sha256], ['Body bytes', event.network.http.body_size]);
  if (event.network?.http?.decrypted_with_supplied_key) values.push(['TLS content', 'Decrypted using supplied key log']);
  if (event.network?.packet_count != null) values.push(['Packets / bytes', `${event.network.packet_count} / ${event.network.byte_count}`], ['Flow end', time(event.network.end_time, true)]);
  if (event.event_log) values.push(['Provider / event ID', `${event.event_log.provider} / ${event.event_log.event_id}`], ['Record ID', event.event_log.record_id]);
  if (event.prefetch) values.push(['Executable', event.prefetch.executable], ['Run count', event.prefetch.run_count]);
  if (event.metadata && Object.keys(event.metadata).some((key) => key.includes('signal') || key.includes('found'))) values.push(['Comparison signals', JSON.stringify(event.metadata)]);
  if (event.timestamp_semantics === 'extraction_time') details.append(U.badge('⚠ Event time unknown · extraction time shown', 'warning'));
  details.append(U.fields(values));
  if (event.process?.command_line) details.append(U.el('pre', event.process.command_line, 'command-line mono'));
  const source = section('Provenance'); source.append(provenanceView(event)); grid.append(details, source); return grid;
}
function processDetails(event: EvidenceEvent): HTMLElement {
  const container = U.el('div'), tabs = U.el('div', '', 'process-detail-tabs');
  for (const name of ['Overview', 'Command Line', 'Parent / Children', 'DLLs', 'Handles', 'Files', 'Memory Regions', 'Sockets', 'Related Memory', 'Related Disk', 'Related Network']) {
    const button = U.button(name, () => { processTab = name; renderInspector(); }, processTab === name ? 'active' : '');
    button.dataset.processTab = name; tabs.append(button);
  }
  container.append(tabs);
  if (processTab === 'Overview') { container.append(eventOverview(event)); return container; }
  if (processTab === 'Command Line') { container.append(U.el('pre', event.process?.command_line ?? 'Command line not recorded', 'command-line mono')); return container; }
  const process = event.process!;
  const memory = events.filter((item) => item.source === 'memory' && item.event_id !== event.event_id && item.process && (
    process.instance_id && item.process.instance_id === process.instance_id ||
    !process.instance_id && item.hostname === event.hostname && item.process.pid === process.pid &&
    process.creation_time && item.process.creation_time === process.creation_time));
  const families = events.filter((item) => item.event_id !== event.event_id && item.process && ['process_start', 'process_observation'].includes(item.type) && (
    process.parent_instance_id && process.parent_instance_id === item.process.instance_id ||
    process.instance_id && process.instance_id === item.process.parent_instance_id));
  const filters: Record<string, (item: EvidenceEvent) => boolean> = {
    DLLs: (item) => !!item.module, Handles: (item) => !!item.handle, Files: (item) => !!item.file,
    'Memory Regions': (item) => !!item.memory_region, Sockets: (item) => !!item.network,
  };
  let related = processTab === 'Parent / Children' ? families : memory.filter(filters[processTab] ?? (() => true));
  if (processTab === 'Related Disk' || processTab === 'Related Network') {
    related = root?.event_id === event.event_id && analysis ? incidentEvents.filter((item) => item.source === (processTab === 'Related Disk' ? 'disk' : 'network')) : [];
    if (!analysis || root?.event_id !== event.event_id) container.append(U.el('p', 'Select this process and run Analyze Evidence to show its related sources.', 'muted small'));
  }
  container.append(U.el('p', `${related.length} observations · select to inspect provenance`, 'muted small'));
  if (related.length) container.append(U.table(related, [
    { label: 'TIME / SOURCE', value: (item) => `${time(item.timestamp)} ${item.source.toUpperCase()}` },
    { label: 'OBSERVATION', value: (item) => `${label(item)} · ${item.type}` },
  ], (item) => item.event_id, (item) => selectEvent(item), undefined, 'process-related-table'));
  return container;
}

function renderInspector(): void {
  const panel = element('inspector-content'), tabs = element('inspector-tabs'); panel.replaceChildren(); tabs.replaceChildren();
  for (const name of ['Overview', 'Provenance', 'Raw']) {
    const button = U.button(name, () => { inspectorTab = name; renderInspector(); }, inspectorTab === name ? 'active' : '');
    button.dataset.inspector = name.toLowerCase(); tabs.append(button);
  }
  if (!selection) { element('inspector-kind').textContent = 'EVIDENCE INSPECTOR'; element('inspector-title').textContent = 'Select an event or a connection'; panel.append(U.el('p', 'Select a table row or graph node to inspect its original source. Select a correlation to review its rule-based score and reasons.', 'muted small')); return; }
  if ('run' in selection) {
    const run = selection.run; element('inspector-kind').textContent = 'PARSER RUN'; element('inspector-title').textContent = run.plugin ?? run.parser;
    if (inspectorTab === 'Raw' || inspectorTab === 'Provenance') panel.append(U.el('pre', JSON.stringify(inspectorTab === 'Raw' ? run : run.artifact, null, 2), 'raw'));
    else panel.append(U.badge(run.status, run.status === 'SUCCESS' ? 'success' : 'warning'), U.fields([
      ['Source', run.source], ['Events / rows', `${run.event_count} / ${run.row_count}`], ['Error', run.error], ['Warnings', run.warnings.join('\n')], ['Artifact', run.artifact?.path],
    ]), U.el('pre', run.stderr ?? 'No stderr recorded', 'raw'), U.el('pre', JSON.stringify(run.command), 'raw'));
    return;
  }
  if ('relationship' in selection) {
    const edge = selection.relationship; element('inspector-kind').textContent = 'ENTITY RELATIONSHIP'; element('inspector-title').textContent = edge.kind;
    if (inspectorTab === 'Raw') panel.append(U.el('pre', JSON.stringify(edge, null, 2), 'raw'));
    else {
      panel.append(U.fields([['Relationship', edge.kind], ['Correlation Score', edge.score], ['Timestamp', time(edge.timestamp, true)]]));
      if ((edge.support_count ?? 1) > 1) panel.append(U.el('p', `${edge.support_count} supporting observations/links. Score and reasons show the strongest direct support; provenance includes all source events.`, 'muted small'));
      for (const reason of edge.reasons) panel.append(U.el('p', `${reason.score >= 0 ? '+' : ''}${reason.score} ${reason.rule}: ${reason.details}`, 'small'));
      for (const id of edge.event_ids) { const event = eventById(id); if (event) panel.append(U.button(`${event.source.toUpperCase()} · ${label(event)}`, () => selectEvent(event), 'source-link'), provenanceView(event)); }
    }
    return;
  }
  if ('event' in selection) {
    const event = selection.event; element('inspector-kind').textContent = `${eventKind(event).toUpperCase()} DETAIL`; element('inspector-title').textContent = `${label(event)} · ${event.event_id}`;
    if (inspectorTab === 'Provenance') panel.append(provenanceView(event));
    else if (inspectorTab === 'Raw') panel.append(U.el('p', 'Large source integers are displayed as decimal text to preserve their exact value.', 'muted small'), U.el('pre', JSON.stringify(event, null, 2), 'raw'));
    else if (event.process && ['process_start', 'process_observation', 'process_scan'].includes(event.type)) panel.append(processDetails(event));
    else panel.append(eventOverview(event));
    return;
  }
  const edge = selection.edge, a = eventById(edge.source_event), b = eventById(edge.target_event);
  element('inspector-kind').textContent = 'CORRELATION'; element('inspector-title').textContent = `${label(a)} ↔ ${label(b)}`;
  if (inspectorTab === 'Raw') { panel.append(U.el('pre', JSON.stringify(edge, null, 2), 'raw')); return; }
  if (inspectorTab === 'Provenance') {
    const grid = U.el('div', '', 'inspect-grid'); for (const event of [a, b]) if (event) { const source = section(`${label(event)} · ${event.source}`); source.append(provenanceView(event)); grid.append(source); } panel.append(grid); return;
  }
  const grid = U.el('div', '', 'correlation-inspector'), score = section('Correlation score');
  const number = U.el('div', String(edge.score), 'score-large'); number.append(U.el('small', ' /100'));
  score.append(number, U.el('p', 'Rule-based correlation score. Not AI confidence.', 'score-caption'), U.fields([['Time delta', delta(edge)]]));
  const reasons = section('Reasons');
  for (const reason of edge.reasons) {
    const row = U.el('div', '', 'reason'), detail = U.el('div');
    detail.append(U.el('span', reason.rule.replaceAll('_', ' ')), U.el('div', reason.details, 'details'));
    row.append(U.el('b', `${reason.score >= 0 ? '+' : ''}${reason.score}`, reason.score < 0 ? 'negative-score' : ''), detail); reasons.append(row);
  }
  const total = edge.reasons.reduce((sum, reason) => sum + reason.score, 0);
  reasons.append(U.el('p', `Raw score ${edge.raw_score ?? total}; final score ${edge.score}/100.`, 'muted small'));
  const sources = section('Source evidence');
  for (const event of [a, b]) if (event) {
    sources.append(U.button(`${event.source.toUpperCase()} · ${label(event)} ↗`, () => selectEvent(event), 'source-link'),
      U.fields([['Event', event.event_id], ['Artifact / plugin', event.provenance?.map((item) => item.plugin).filter((value, index, all) => all.indexOf(value) === index).join(', ') || event.source_artifact?.kind], ['Original row', event.raw_reference?.locator]]));
  }
  grid.append(score, reasons, sources); panel.append(grid);
}

function renderGraph(container: HTMLElement): void {
  if (!graph || !analysis) return;
  const toolbar = U.el('div', '', 'graph-toolbar'), modes = U.el('div');
  for (const [mode, name] of [['events', 'Correlation links'], ['entities', 'Entity relationships']]) {
    const button = U.button(name, () => { graphMode = mode; renderWorkspace(); }, graphMode === mode ? 'active' : ''); button.dataset.graphMode = mode; modes.append(button);
  }
  const expand = U.button(document.querySelector('.app-shell')?.classList.contains('inspector-collapsed') ? 'Show inspector' : 'Expand graph', () => {
    document.querySelector('.app-shell')?.classList.toggle('inspector-collapsed'); renderWorkspace();
  }); expand.dataset.expandGraph = ''; modes.append(expand);
  const legend = U.el('div', '', 'graph-legend');
  for (const kind of ['Process', 'File', 'Domain', 'IP']) { const item = U.el('span', kind); item.prepend(U.icon(kind, 12)); legend.append(item); }
  toolbar.append(modes, legend); container.append(toolbar);
  const bounds = U.el('div', '', 'view-options');
  const depth = U.el('input'), limit = U.el('input'), score = U.el('input'), types = U.el('select');
  for (const [name, input, value, minimum, maximum] of [
    ['Depth', depth, graphDepth, 0, 8], ['Maximum nodes', limit, graphLimit, 1, 2000], ['Minimum score', score, graphScore, 0, 100],
  ] as [string, HTMLInputElement, number, number, number][]) {
    const label = U.el('label', name); input.type = 'number'; input.value = String(value); input.min = String(minimum); input.max = String(maximum);
    input.setAttribute('aria-label', name); label.append(input); bounds.append(label);
  }
  for (const kind of ['', 'Event', 'Process', 'File', 'IP', 'Domain', 'Module', 'Driver', 'MemoryRegion', 'RegistryArtifact']) types.add(new Option(kind || 'All node types', kind));
  types.value = graphTypes; types.setAttribute('aria-label', 'Graph node type'); bounds.append(types);
  bounds.append(U.button('Apply graph limits', () => { void action(async () => {
    if (!currentCase || !root || !depth.reportValidity() || !limit.reportValidity() || !score.reportValidity()) return;
    graphDepth = Number(depth.value); graphLimit = Number(limit.value); graphScore = Number(score.value); graphTypes = types.value;
    const parameters = new URLSearchParams({ root_event_id: root.event_id, depth: String(graphDepth), limit: String(graphLimit), min_score: String(graphScore) });
    if (graphTypes) parameters.set('node_types', graphTypes);
    graph = await api<EvidenceGraph>('GET', `/cases/${currentCase.case_id}/graph?${parameters}`);
    if (graphTypes) graphMode = graphTypes === 'Event' ? 'events' : 'entities'; renderWorkspace();
  }); })); container.append(bounds);
  if (graph.truncated) container.append(U.el('p', 'Graph is bounded by the selected depth and node limit. Change these settings to inspect more evidence.', 'muted small'));
  const isEvents = graphMode === 'events';
  const allNodes = graph.nodes.filter((node) => isEvents ? node.kind === 'Event' : node.kind !== 'Event');
  const nodes = allNodes.slice(0, 200), ids = new Set(nodes.map((node) => node.id));
  const allEdges = graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target) && (isEvents ? edge.kind === 'CORRELATED_WITH' : !['OBSERVED', 'CORRELATED_WITH'].includes(edge.kind)));
  const edges = allEdges.slice(0, 400);
  if (allNodes.length > nodes.length || allEdges.length > edges.length) container.append(U.el('p', `Showing ${nodes.length}/${allNodes.length} nodes and ${edges.length}/${allEdges.length} links. Select a narrower process scope to inspect other evidence.`, 'muted small'));
  const positions = new Map<string, { x: number; y: number; kind: string; event?: EvidenceEvent }>();
  const counts = [0, 0, 0];
  const sorted = [...nodes].sort((a, b) => (eventById(a.event_ids[0])?.timestamp ?? '').localeCompare(eventById(b.event_ids[0])?.timestamp ?? '') || a.id.localeCompare(b.id));
  for (const node of sorted) {
    const event = eventById(node.event_ids[0]), kind = isEvents && event ? eventKind(event) : node.kind;
    const col = kind === 'Process' ? 0 : ['File', 'Registry', 'RegistryArtifact', 'DLL', 'Module', 'MFTRecord', 'FileObject'].includes(kind) ? 1 : 2;
    positions.set(node.id, { x: 175 + col * 335, y: 77 + counts[col]++ * 94, kind, event });
  }
  const height = Math.max(350, Math.max(...counts) * 94 + 65), svg = U.svg('svg', { viewBox: `0 0 1100 ${height}`, class: 'incident-graph', id: 'graph', role: 'group', 'aria-label': 'Incident graph' });
  ['PROCESSES', 'FILES / MODULES', 'NETWORK / ENTITIES'].forEach((name, index) => { const title = U.svg('text', { x: 40 + index * 335, y: 25, class: 'graph-column' }); title.textContent = name; svg.append(title); });
  const labelPositions: { x: number; y: number; width: number }[] = [];
  for (const edge of edges) {
    const a = positions.get(edge.source), b = positions.get(edge.target); if (!a || !b) continue;
    const sameColumn = a.x === b.x, forward = a.x <= b.x;
    const ax = a.x + (forward ? 133 : -133), bx = b.x + (sameColumn || !forward ? 133 : -133);
    const mid = sameColumn ? ax + 42 : (ax + bx) / 2;
    const d = `M ${ax} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${bx} ${b.y}`;
    const pair = `${edge.event_ids[0]}:${edge.event_ids[1]}`;
    const line = U.svg('path', { d, class: `graph-edge ${(edge.score ?? 0) >= 80 ? 'high' : ''}` }); line.dataset.pair = pair;
    const hit = U.svg('path', { d, class: 'graph-hit', tabindex: 0, role: 'button', 'aria-label': `${edge.kind} ${edge.score ?? ''}` });
    const choose = (): void => {
      const correlation = analysis?.correlations.find((item) => `event:${item.source_event}` === edge.source && `event:${item.target_event}` === edge.target);
      if (correlation) selectEdge(correlation); else { selection = { relationship: edge }; inspectorTab = 'Overview'; revealInspector(); renderInspector(); }
    };
    hit.addEventListener('click', choose); hit.addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); choose(); } });
    const title = U.svg('title'); title.textContent = `${edge.kind}${edge.score == null ? '' : ` · ${edge.score}/100`}`; hit.append(title);
    const scoreText = isEvents ? String(edge.score ?? '') : edge.kind, scoreX = sameColumn ? mid + 2 : mid;
    let scoreY = (a.y + b.y) / 2 - 5;
    const scoreWidth = scoreText.length * 6;
    while (labelPositions.some((p) => Math.abs(p.x - scoreX) < (p.width + scoreWidth) / 2 + 4 && Math.abs(p.y - scoreY) < 13)) scoreY += 14;
    labelPositions.push({ x: scoreX, y: scoreY, width: scoreWidth });
    const score = U.svg('text', { x: scoreX, y: scoreY, class: 'graph-score', 'text-anchor': 'middle' }); score.textContent = scoreText;
    svg.append(line, hit, score);
  }
  for (const node of sorted) {
    const { x, y, kind, event } = positions.get(node.id)!;
    const group = U.svg('g', { transform: `translate(${x - 132},${y - 29})`, class: `graph-node ${node.event_ids.includes(root?.event_id ?? '') ? 'root' : ''}`, tabindex: 0, role: 'button', 'aria-label': `${kind}: ${node.label}` });
    group.dataset.nodeId = node.id; group.dataset.kind = kind;
    group.append(U.svg('rect', { width: 264, height: 58, rx: 2, class: 'node-body' }));
    const icon = U.icon(kind, 22); icon.setAttribute('x', '12'); icon.setAttribute('y', '17');
    const caption = U.svg('text', { x: 45, y: 24, class: 'graph-label' });
    const displayLabel = isEvents ? label(event) : ['File', 'DLL'].includes(kind) ? node.label.split(/[\\/]/).pop() ?? node.label : node.label;
    caption.textContent = displayLabel.slice(0, 28);
    const fullLabel = U.svg('title'); fullLabel.textContent = node.label; group.append(fullLabel);
    const subtitle = U.svg('text', { x: 45, y: 41, class: 'graph-subtitle' });
    subtitle.textContent = `${kind.toUpperCase()} · ${event?.source.toUpperCase() ?? ''} · ${isEvents ? event?.source_artifact?.kind ?? event?.type ?? '' : `${node.event_ids.length} observations`}`.slice(0, 47);
    group.append(icon, caption, subtitle);
    const choose = (): void => {
      if (!event) return; selectEvent(event);
      for (const sibling of svg.querySelectorAll('.graph-node')) sibling.classList.toggle('selected', sibling === group);
    };
    group.addEventListener('click', choose); group.addEventListener('keydown', (key) => { if (['Enter', ' '].includes(key.key)) { key.preventDefault(); choose(); } }); svg.append(group);
  }
  const scroll = U.el('div', '', 'graph-scroll'); scroll.append(svg); container.append(scroll);
}

element('brand').addEventListener('click', () => navigate('case'));
element('load-sample').addEventListener('click', () => void action(async () => {
  setStatus('Loading synthetic sample evidence…'); const sampleCase = await api<EvidenceCase>('POST', '/samples/load'); await openCase(sampleCase.case_id);
}));
element('refresh').addEventListener('click', () => void action(async () => {
  if (currentCase) await openCase(currentCase.case_id); else { await refreshCases(); renderWorkspace(); setStatus('Case list refreshed.'); }
}));
element('case-select').addEventListener('change', () => void action(async () => {
  const input = element<HTMLSelectElement>('case-select'); if (input.value) await openCase(input.value); else input.value = currentCase?.case_id ?? '';
}));
element('search').addEventListener('input', () => {
  if (pageSearchTimer) clearTimeout(pageSearchTimer);
  if (pagedRoute(view)) pageSearchTimer = setTimeout(() => refreshPagedView(), 250); else renderWorkspace();
});
element('import-events').addEventListener('click', () => void action(async () => {
  if (!currentCase) return; const result = await window.evidenceMesh.importEvents(currentCase.case_id);
  if (result) { await openCase(currentCase.case_id); setStatus(`Imported ${result.imported} events. Select a process and analyze.`); }
}));
element('analyze').addEventListener('click', () => void action(async () => {
  if (!currentCase || !root) return; clearAnalysis(); selection = { event: root }; renderInspector();
  setStatus('Correlating normalized evidence…');
  const base = `/cases/${currentCase.case_id}`, query = `?root_event_id=${encodeURIComponent(root.event_id)}`;
  const result = await api<EvidenceAnalysis>('POST', `${base}/correlate`, { root_event_id: root.event_id, result_limit: 2000 });
  graphDepth = largeCase() ? 2 : 8; graphLimit = 500; graphScore = 0; graphTypes = '';
  const [newGraph, timeline] = await Promise.all([api<EvidenceGraph>('GET', `${base}/graph${query}&depth=${graphDepth}&limit=${graphLimit}`), api<{ events: EvidenceEvent[] }>('GET', `${base}/timeline${query}&limit=${largeCase() ? 500 : 2000}`)]);
  analysis = result; graph = newGraph; incidentEvents = timeline.events; currentCase.analysis_revision = currentCase.revision;
  view = 'correlations'; onlyIncident = true; element<HTMLInputElement>('search').value = '';
  if (result.correlations[0]) selection = { edge: result.correlations[0] };
  inspectorTab = 'Overview'; renderNavigation(); renderWorkspace(); renderInspector();
  setStatus(result.status === 'no_matches' ? 'No matching evidence at the current score threshold.' : `${incidentEvents.length} related events · ${result.correlation_count} explained links. Analysis complete.`);
}));

const rawMemoryPlugins = ['pslist', 'psscan', 'pstree', 'cmdline', 'envars', 'dlllist', 'handles', 'filescan',
  'vadinfo', 'netscan', 'malware.malfind', 'svcscan', 'svclist', 'registry.amcache', 'registry.userassist',
  'shimcachemem', 'modules', 'modscan', 'driverscan', 'callbacks'].map((name) => 'windows.' + name);
let memoryJobs: import('./types').MemoryJob[] = [];
let jobPoll: ReturnType<typeof setTimeout> | undefined;
let dependencyReport: Record<string, unknown> | undefined;
let diskInspection: { caseId: string; report: import('./types').DiskInspection; context: import('./types').ArtifactContext } | undefined;

function diskImagePanel(): HTMLElement {
  const panel = U.el('section'); panel.id = 'disk-image-panel';
  if (!diskInspection) return panel;
  const inspection = diskInspection;
  panel.append(U.el('h3', 'Disk image → Detected volumes'), U.el('p', inspection.report.path, 'mono small'));
  for (const warning of inspection.report.warnings) panel.append(U.el('p', warning, 'muted small'));
  const volumeChoices: { id: string; input: HTMLInputElement }[] = [];
  for (const volume of inspection.report.volumes.slice(0, 200)) {
    const details = U.el('details'); details.open = true;
    const summary = U.el('summary'), label = U.el('label'), input = U.el('input'); input.type = 'checkbox';
    input.checked = ['SUCCESS', 'PARTIAL'].includes(volume.status); input.disabled = !input.checked;
    label.append(input, document.createTextNode(`${volume.filesystem} ${volume.serial ?? volume.partition} · ${volume.status} · offset ${volume.offset}`));
    summary.append(label); details.append(summary);
    if (volume.error) details.append(U.el('p', volume.error, 'negative-score'));
    for (const warning of volume.warnings ?? []) details.append(U.el('p', warning, 'muted small'));
    const list = U.el('ul');
    for (const item of volume.artifacts.slice(0, 100)) list.append(U.el('li', `${item.kind.toUpperCase()} · ${item.path} · ${item.size.toLocaleString()} bytes`, 'mono small'));
    details.append(list);
    if (volume.artifacts.length > 100) details.append(U.el('p', `${volume.artifacts.length - 100} additional artifacts discovered. Selection includes all matching artifacts.`, 'muted small'));
    panel.append(details); volumeChoices.push({ id: volume.id, input });
  }
  if (inspection.report.volumes.length > 200) panel.append(U.el('p', 'Showing the first 200 volumes. Use the API to select additional volumes.', 'muted small'));
  const choices = U.el('div', '', 'import-fields');
  const kinds = ['mft', 'usn', 'prefetch', 'evtx', 'amcache'].map((kind) => {
    const label = U.el('label', kind.toUpperCase()), input = U.el('input'); input.type = 'checkbox'; input.checked = true;
    input.dataset.diskKind = kind; label.prepend(input); choices.append(label); return { kind, input };
  });
  panel.append(choices, U.button('Extract selected artifacts', () => { void action(async () => {
    const volumes = volumeChoices.filter((choice) => choice.input.checked).map((choice) => choice.id);
    const artifacts = kinds.filter((choice) => choice.input.checked).map((choice) => choice.kind);
    if (!volumes.length || !artifacts.length) throw new Error('Select at least one supported volume and artifact kind.');
    setStatus('Hashing original disk image and extracting selected artifacts…');
    const result = await api<import('./types').ImportReport>('POST', `/cases/${inspection.caseId}/disk-images/import`, {
      path: inspection.report.path, context: inspection.context, volumes, artifacts,
    });
    await openCase(inspection.caseId);
    setStatus(`${result.status}: imported ${result.imported} disk events. Provenance links derived files to the original image.`, result.status === 'FAILED');
  }); }));
  return panel;
}

function terminalJob(status: string): boolean {
  return ['SUCCESS', 'PARTIAL', 'FAILED', 'CANCELLED', 'UNAVAILABLE'].includes(status);
}
async function refreshMemoryJobs(caseId: string): Promise<void> {
  if (jobPoll) clearTimeout(jobPoll);
  const jobs = await api<import('./types').MemoryJob[]>('GET', `/cases/${caseId}/memory-jobs`);
  if (currentCase?.case_id !== caseId) return;
  memoryJobs = jobs;
  const panel = document.getElementById('memory-job-panel');
  if (panel) panel.replaceWith(memoryJobPanel());
  if (jobs.some((job) => !terminalJob(job.status))) {
    jobPoll = setTimeout(() => { void refreshMemoryJobs(caseId).catch((error) => setStatus(String(error), true)); }, 1000);
  }
}
function memoryJobPanel(): HTMLElement {
  const panel = U.el('section', '', 'artifact-import'); panel.id = 'memory-job-panel';
  if (!memoryJobs.length) return panel;
  panel.append(U.el('h3', 'Memory analysis'));
  for (const job of memoryJobs.slice(-3).reverse()) {
    const heading = U.el('div', '', 'import-actions');
    heading.append(U.el('strong', `${job.status} · ${job.completed} / ${job.total}`),
      U.el('span', job.path, 'mono muted small'));
    if (!terminalJob(job.status)) heading.append(U.button('Cancel analysis', () => {
      void api('POST', `/cases/${job.case_id}/memory-jobs/${job.job_id}/cancel`)
        .then(() => refreshMemoryJobs(job.case_id)).catch((error) => setStatus(String(error), true));
    }));
    else if (job.report?.imported) heading.append(U.button('Load analysis results', () => {
      void action(async () => { await openCase(job.case_id); navigate('processes'); });
    }));
    panel.append(heading);
    if (job.error) panel.append(U.el('p', job.error, 'negative-score'));
    panel.append(U.table(job.plugins, [
      { label: 'PLUGIN', value: (row) => row.plugin },
      { label: 'STATUS', value: (row) => U.badge(row.status, row.status === 'SUCCESS' ? 'success' : 'neutral') },
      { label: 'OUTPUT', value: (row) => row.cached ? 'Verified cache' : 'Current run' },
      { label: 'DETAIL', value: (row) => row.error ?? '—' },
    ], (row) => row.plugin, () => undefined, undefined, 'memory-job-' + job.job_id));
  }
  return panel;
}
function runtimePanel(): HTMLElement {
  const panel = U.el('section', '', 'artifact-import'); panel.append(U.el('h3', 'Runtime dependencies'));
  panel.append(U.button('Check dependencies', () => { void action(async () => {
    dependencyReport = await api<Record<string, unknown>>('GET', '/runtime/dependencies');
    renderWorkspace();
  }); }));
  if (dependencyReport) {
    const backend = dependencyReport.backend as { embedded: boolean; python: string; status: string };
    const tshark = dependencyReport.tshark as { embedded: boolean; version?: string; status: string };
    const components = dependencyReport.components as Record<string, { version?: string; status: string }>;
    const rows = [
      { name: 'Python Backend', mode: backend.embedded ? 'Embedded' : 'Development', version: backend.python, status: backend.status },
      { name: 'Volatility 3', mode: backend.embedded ? 'Embedded' : 'Development', ...components.volatility3 },
      { name: 'TShark', mode: tshark.embedded ? 'Embedded' : 'System', version: tshark.version, status: tshark.status },
      { name: 'SQLite', mode: 'Backend runtime', ...(dependencyReport.sqlite as { version: string; status: string }) },
    ];
    panel.append(U.table(rows, [{ label: 'COMPONENT', value: (row) => row.name },
      { label: 'RUNTIME', value: (row) => row.mode }, { label: 'VERSION', value: (row) => row.version ?? 'Unknown' },
      { label: 'STATUS', value: (row) => row.status }], (row) => row.name, () => undefined, undefined, 'dependencies-table'));
    panel.append(U.el('p', 'Workspace: ' + String(dependencyReport.workspace), 'mono muted small'));
  }
  return panel;
}

renderNavigation(); renderRoot(); renderWorkspace(); renderInspector();
void action(async () => {
  await api('GET', '/health'); await refreshCases();
  element('connection-state').replaceChildren(U.el('i'), document.createTextNode('LOCAL')); element('connection-state').classList.add('online');
  setStatus('Engine connected. Load Sample Evidence or open a case.');
});
