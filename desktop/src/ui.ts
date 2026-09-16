/** Small native DOM widgets; no runtime framework or borrowed APEX components. */
namespace MeshUI {
  export const svgNS = 'http://www.w3.org/2000/svg';
  export function el<K extends keyof HTMLElementTagNameMap>(tag: K, value = '', className = ''): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag); node.textContent = value; node.className = className; return node;
  }
  export function svg<K extends keyof SVGElementTagNameMap>(tag: K, attributes: Record<string, string | number> = {}): SVGElementTagNameMap[K] {
    const node = document.createElementNS(svgNS, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    return node;
  }
  export function icon(kind: string, size = 16): SVGSVGElement {
    const node = svg('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.4, 'aria-hidden': 'true' });
    const paths: Record<string, string[]> = {
      Process: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M9 8l7 4-7 4z'],
      File: ['M5 3h9l5 5v13H5z', 'M14 3v6h5', 'M8 13h8M8 17h6'],
      Domain: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M3 12h18M12 3c-5 5-5 13 0 18M12 3c5 5 5 13 0 18'],
      IP: ['M8 3h8v6H8zM3 16h6v5H3zM15 16h6v5h-6z', 'M12 9v4M6 16v-3h12v3'],
      User: ['M12 3a4 4 0 1 0 0 8a4 4 0 1 0 0-8', 'M4 21v-3c0-6 16-6 16 0v3'],
      Registry: ['M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z'],
      Event: ['M5 4h14v16H5zM8 8h8M8 12h8M8 16h5'],
      Case: ['M3 7h18v14H3zM8 7V3h8v4M3 12h18'],
      Timeline: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M12 6v6l4 3'],
      Graph: ['M5 5l14 6-10 9-4-15M5 5l4 15', 'M5 3a2 2 0 1 0 0 4a2 2 0 1 0 0-4M19 9a2 2 0 1 0 0 4a2 2 0 1 0 0-4M9 18a2 2 0 1 0 0 4a2 2 0 1 0 0-4'],
    };
    for (const d of paths[kind] ?? paths.Event) node.append(svg('path', { d, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
    return node;
  }
  export function button(label: string, action: () => void, className = ''): HTMLButtonElement {
    const node = el('button', label, className); node.type = 'button'; node.addEventListener('click', action); return node;
  }
  export function badge(label: string, kind = 'neutral'): HTMLSpanElement { return el('span', label, `badge ${kind}`); }
  export function mono(value: unknown): HTMLSpanElement { return el('span', value == null ? '—' : String(value), 'mono'); }
  export function fields(items: [string, unknown][]): HTMLDListElement {
    const list = el('dl');
    for (const [label, value] of items) {
      const field = el('div', '', 'field');
      field.append(el('dt', label), el('dd', value == null || value === '' ? 'Not recorded' : String(value)));
      list.append(field);
    }
    return list;
  }
  export function empty(title: string, description: string): HTMLElement {
    const node = el('div', '', 'empty'); node.append(icon('Event', 25), el('h3', title), el('p', description)); return node;
  }
  export function named(kind: string, label: string): HTMLElement {
    const node = el('span', '', 'cell-name'); node.append(icon(kind), el('span', label)); return node;
  }
  export interface Column<T> { label: string; value: (row: T) => string | number | HTMLElement; sort?: (row: T) => string | number }
  export function table<T>(rows: T[], columns: Column<T>[], key: (row: T) => string, select: (row: T) => void,
                           selected?: string, id?: string): HTMLDivElement {
    const wrap = el('div', '', 'table-scroll'), table = el('table'), head = el('thead'), body = el('tbody');
    if (id) table.id = id;
    table.setAttribute('aria-label', id?.replaceAll('-', ' ') ?? 'Evidence table');
    let ordered = [...rows], sortIndex = -1, ascending = true, page = 0;
    const pageSize = 100, pager = el('div', '', 'table-pager');
    function renderPager(): void {
      pager.replaceChildren();
      if (ordered.length <= pageSize) return;
      const previous = button('Previous', () => { page--; renderRows(); }); previous.disabled = page === 0;
      const next = button('Next', () => { page++; renderRows(); }); next.disabled = (page + 1) * pageSize >= ordered.length;
      pager.append(previous, el('span', `Page ${page + 1} / ${Math.ceil(ordered.length / pageSize)} · ${ordered.length} rows · ${pageSize} per page`), next);
    }
    function renderRows(): void {
      body.replaceChildren();
      renderPager();
      for (const row of ordered.slice(page * pageSize, (page + 1) * pageSize)) {
        const tr = el('tr'); tr.dataset.key = key(row); tr.dataset.eventId = key(row);
        tr.tabIndex = 0; tr.classList.toggle('selected', key(row) === selected); tr.setAttribute('aria-selected', String(key(row) === selected));
        function choose(): void {
          selected = key(row);
          for (const sibling of body.rows) { const match = sibling === tr; sibling.classList.toggle('selected', match); sibling.setAttribute('aria-selected', String(match)); }
          select(row);
        }
        tr.addEventListener('click', choose);
        tr.addEventListener('keydown', (event) => {
          if (['Enter', ' '].includes(event.key)) { event.preventDefault(); choose(); }
          const directions: Record<string, number> = { ArrowDown: 1, ArrowUp: -1 };
          if (event.key in directions || ['Home', 'End'].includes(event.key)) {
            event.preventDefault();
            const index = event.key === 'Home' ? 0 : event.key === 'End' ? body.rows.length - 1 : tr.sectionRowIndex + directions[event.key];
            const next = body.rows[Math.max(0, Math.min(body.rows.length - 1, index))];
            next?.focus(); next?.click();
          }
        });
        for (const column of columns) {
          const cell = el('td'), value = column.value(row);
          if (value instanceof HTMLElement) cell.append(value); else cell.textContent = String(value);
          cell.title = cell.textContent ?? ''; tr.append(cell);
        }
        body.append(tr);
      }
    }
    const header = el('tr');
    columns.forEach((column, index) => {
      const th = el('th'); th.scope = 'col'; th.setAttribute('aria-sort', 'none');
      const control = button(`${column.label} ↕`, () => {
        ascending = sortIndex === index ? !ascending : true; sortIndex = index;
        const value = (row: T): string | number => { const v = column.sort?.(row) ?? column.value(row); return v instanceof HTMLElement ? v.textContent ?? '' : v; };
        ordered.sort((a, b) => { const left = value(a), right = value(b); return (typeof left === 'number' && typeof right === 'number' ? left - right : String(left).localeCompare(String(right))) * (ascending ? 1 : -1); });
        for (const sibling of header.cells) sibling.setAttribute('aria-sort', sibling === th ? ascending ? 'ascending' : 'descending' : 'none');
        page = 0; renderRows();
      }); th.append(control); header.append(th);
    });
    head.append(header); table.append(head, body); wrap.append(pager, table); renderRows(); return wrap;
  }
}
