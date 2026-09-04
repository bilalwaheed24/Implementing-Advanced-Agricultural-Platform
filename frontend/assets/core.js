/* Core utilities: DOM building, API client with token refresh, formatting, charts.
 * Every DOM write uses textContent (never innerHTML with data) — ADR-004, T-20. */

/* ---------------- DOM ---------------- */
export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else if (key === 'html') throw new Error('raw HTML is not permitted');
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'dataset') {
      for (const [dk, dv] of Object.entries(value)) node.dataset[dk] = dv;
    } else node.setAttribute(key, String(value));
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* First cell of a key/value row: a real <th scope="row"> so a screen reader announces
 * the value with its name, styled as a body cell (see th.row-header in styles.css). */
export function rowHeader(text) {
  return el('th', { scope: 'row', class: 'row-header', text });
}

/* A labelled form control.  The label is bound to the control with for/id rather than
 * sitting beside it, so assistive technology can name the field and clicking the label
 * moves focus into it (WCAG 1.3.1, 3.3.2, 4.1.2).  Ids are generated from a counter, so
 * they stay unique even when several views mount fields with the same caption.
 * Markup is deliberately identical to what the views built by hand: div.field > label + control. */
let fieldSequence = 0;

export function field(labelText, control, extras = []) {
  if (control && !control.id) control.id = `fld-${++fieldSequence}`;
  return el('div', { class: 'field' }, [
    el('label', { for: control ? control.id : null, text: labelText }),
    control,
    ...[].concat(extras),
  ]);
}

/* ---------------- formatting ---------------- */
export function fmtDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}
export function fmtDay(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value)
    : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}
export function fmtNum(value, digits = 2) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  return Number.isNaN(number) ? String(value)
    : number.toLocaleString(undefined, { maximumFractionDigits: digits });
}
export function fmtPct(value, digits = 0) {
  if (value === null || value === undefined) return '—';
  return `${(Number(value) * 100).toFixed(digits)}%`;
}
export function shortId(value) { return value ? String(value).slice(0, 8) : '—'; }
/* Domain acronyms that must not be title-cased into "Gmo" / "Durc" / "Ndvi". */
const ACRONYMS = new Set(['GMO', 'DURC', 'GS1', 'NDVI', 'CRISPR', 'DNA', 'RNA', 'AI',
  'IOT', 'QR', 'CVE', 'EPCIS', 'GTIN', 'SSCC', 'MSP', 'USDA', 'FDA', 'EU', 'PAM', 'ID']);

export function titleCase(value) {
  return String(value || '')
    .replace(/_/g, ' ')
    .split(' ')
    .map((word) => (ACRONYMS.has(word.toUpperCase())
      ? word.toUpperCase()
      : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()))
    .join(' ');
}

/* ---------------- severity ---------------- */
const SEVERITY_CLASS = {
  INFO: 'info', LOW: 'info', WARNING: 'warning', MEDIUM: 'warning', MODERATE: 'warning',
  HIGH: 'high', CRITICAL: 'critical', PROHIBITED: 'critical',
  VERIFIED: 'verified', COMPLIANT: 'verified', CLEAR: 'verified', ACTIVE: 'verified',
  APPROVED_AUTO: 'verified', APPROVED_BY_REVIEW: 'verified', ANCHORED: 'verified',
  MATCH: 'verified', OK: 'verified',
  SUSPECT: 'warning', CONDITIONAL: 'warning', FLAG: 'warning', PENDING_REVIEW: 'warning',
  PENDING: 'warning', QUARANTINED: 'critical', BLOCKED: 'critical', BLOCK: 'critical',
  FAILED: 'critical', NON_COMPLIANT: 'critical', MISMATCH: 'critical', REVOKED: 'critical',
  REJECTED: 'critical', RETIRED: 'neutral', SUSPENDED: 'warning', PROVISIONED: 'info',
};
const SEVERITY_ICON = {
  info: 'i', warning: '!', high: '!', critical: '×', verified: '✓', neutral: '·',
};
export function badge(value, fallback = 'neutral') {
  const key = String(value || '').toUpperCase();
  const kind = SEVERITY_CLASS[key] || fallback;
  return el('span', { class: `badge ${kind}` }, [
    el('span', { class: 'icon', 'aria-hidden': 'true', text: SEVERITY_ICON[kind] || '·' }),
    titleCase(value || 'unknown'),
  ]);
}

/* ---------------- toasts ---------------- */
let toastStack = null;
export function toast(message, kind = '') {
  if (!toastStack) {
    toastStack = el('div', { class: 'toast-stack', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastStack);
  }
  const node = el('div', { class: `toast ${kind}`.trim(), text: message });
  toastStack.appendChild(node);
  setTimeout(() => node.remove(), kind === 'error' ? 9000 : 4500);
}

/* ---------------- session ---------------- */
const STORE = 'absp.session';
export const session = {
  read() {
    try { return JSON.parse(localStorage.getItem(STORE) || 'null'); } catch { return null; }
  },
  write(value) {
    try { localStorage.setItem(STORE, JSON.stringify(value)); } catch { /* ignore */ }
  },
  clear() { try { localStorage.removeItem(STORE); } catch { /* ignore */ } },
};

/* ---------------- API client ---------------- */
export const API = '/api/v1';

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || body?.title || `Request failed (${status})`);
    this.status = status;
    this.body = body || {};
    this.correlationId = body?.correlation_id;
    this.fields = body?.errors || [];
  }
}

let refreshing = null;

async function refreshTokens() {
  const current = session.read();
  if (!current?.refresh_token) throw new ApiError(401, { detail: 'Session expired' });
  if (!refreshing) {
    refreshing = fetch(`${API}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: current.refresh_token }),
    }).then(async (response) => {
      if (!response.ok) { session.clear(); throw new ApiError(401, await safeJson(response)); }
      const tokens = await response.json();
      session.write({ ...current, ...tokens });
      return tokens;
    }).finally(() => { refreshing = null; });
  }
  return refreshing;
}

async function safeJson(response) {
  try { return await response.json(); } catch { return {}; }
}

export async function api(path, { method = 'GET', body, retry = true, raw = false } = {}) {
  const current = session.read();
  const headers = { 'Content-Type': 'application/json' };
  if (current?.access_token) headers.Authorization = `Bearer ${current.access_token}`;

  const response = await fetch(path.startsWith('/api') ? path : API + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && retry && current?.refresh_token) {
    try {
      await refreshTokens();
      return api(path, { method, body, retry: false, raw });
    } catch (error) {
      session.clear();
      window.location.hash = '#/login';
      throw error;
    }
  }
  if (!response.ok) throw new ApiError(response.status, await safeJson(response));
  if (raw) return response;
  if (response.status === 204) return null;
  return safeJson(response);
}

/* ---------------- permissions ---------------- */
export function can(permission) {
  const current = session.read();
  return Boolean(current?.permissions?.includes(permission));
}
export function role() { return session.read()?.role || ''; }

/* ---------------- rendering helpers ---------------- */
export function loading(label = 'Loading…') {
  return el('div', { class: 'loading', 'aria-busy': 'true' }, [
    label,
    el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' }),
    el('div', { class: 'skeleton' }),
  ]);
}

export function empty(title, message, action) {
  return el('div', { class: 'empty' }, [
    el('h3', { text: title }), el('p', { text: message }), action || null,
  ]);
}

/* The single unauthorized state. The server is the authorization control: it returns 403
 * and no data. This is only how that refusal is presented, so every view that hits a
 * role boundary says the same thing rather than showing an empty panel. */
export function unauthorizedCard() {
  return el('div', { class: 'card', role: 'alert' }, [
    el('h1', { text: 'Not available to your role' }),
    el('p', { text: 'Your role does not carry the permission this view requires. '
      + 'The server enforces this; hiding the link is only a convenience.' }),
  ]);
}

export function errorBox(error) {
  // A role refusal is not a load failure, and must not be reported as one.
  if (error?.status === 403) return unauthorizedCard();
  const parts = [el('strong', { text: 'Could not load this view. ' }),
    el('span', { text: error.message })];
  if (error.correlationId) {
    parts.push(el('div', { class: 'hint mono', text: `Correlation id: ${error.correlationId}` }));
  }
  for (const field of error.fields || []) {
    parts.push(el('div', { class: 'error-text', text: `${field.field}: ${field.message}` }));
  }
  return el('div', { class: 'card', role: 'alert' }, parts);
}

export function tile(label, value, hint) {
  return el('div', { class: 'tile' }, [
    el('div', { class: 'label', text: label }),
    el('div', { class: 'value', text: value === undefined || value === null ? '—' : String(value) }),
    hint ? el('div', { class: 'hint', text: hint }) : null,
  ]);
}

export function table(columns, rows, options = {}) {
  if (!rows.length) {
    return empty(options.emptyTitle || 'Nothing here yet',
      options.emptyMessage || 'No records match the current filters.');
  }
  const head = el('tr', {}, columns.map((column) =>
    el('th', { class: column.numeric ? 'num' : '', text: column.label })));
  const body = rows.map((row) => el('tr', {}, columns.map((column) => {
    const value = column.render ? column.render(row) : row[column.key];
    return el('td', { class: column.numeric ? 'num' : '', dataset: { label: column.label } },
      [value === null || value === undefined ? '—' :
        (typeof value === 'object' ? value : String(value))]);
  })));
  return el('div', { class: 'table-wrap' }, [
    el('table', {}, [el('thead', {}, [head]), el('tbody', {}, body)]),
  ]);
}

export function reasonList(reasons, negativeByDefault = true) {
  const items = (reasons || []).map((reason) => {
    if (typeof reason === 'string') {
      return el('li', { class: negativeByDefault ? '' : 'good', text: reason });
    }
    const text = reason.detail || reason.message || JSON.stringify(reason);
    const label = reason.rule ? `${titleCase(reason.rule)}: ${text}` : text;
    const kind = reason.rule === 'none' ? 'good' : 'bad';
    return el('li', { class: kind, text: label });
  });
  return el('ul', { class: 'reasons' }, items);
}

export function pager(page, pageSize, total, onChange) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return el('div', { class: 'row u-mt-12' }, [
    el('button', {
      disabled: page <= 1, onClick: () => onChange(page - 1), text: 'Previous',
    }),
    el('span', { class: 'hint', text: `Page ${page} of ${pages} — ${total} record(s)` }),
    el('button', {
      disabled: page >= pages, onClick: () => onChange(page + 1), text: 'Next',
    }),
  ]);
}

/* ---------------- charts (hand-rendered inline SVG) ---------------- */
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  return node;
}

/** Line chart with optional threshold band. Includes a text summary and data table
 *  fallback so it is not colour- or vision-dependent. */
export function lineChart(points, { valueKey, label, threshold, height = 180 } = {}) {
  const width = 720;
  const padding = { top: 14, right: 14, bottom: 26, left: 44 };
  const usable = points.filter((point) => typeof point[valueKey] === 'number');
  if (usable.length < 2) {
    return empty('Not enough data to chart', `At least two ${label} readings are needed.`);
  }
  const values = usable.map((point) => point[valueKey]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = (max - min) || 1;
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;

  const x = (index) => padding.left + (index / (usable.length - 1)) * innerW;
  const y = (value) => padding.top + innerH - ((value - min) / span) * innerH;

  const svg = svgEl('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${height}`, role: 'img',
    'aria-label': `${label}: ${usable.length} readings from ${fmtNum(min)} to ${fmtNum(max)}`,
  });

  svg.appendChild(svgEl('line', {
    x1: padding.left, y1: padding.top + innerH, x2: width - padding.right,
    y2: padding.top + innerH, stroke: 'var(--border)', 'stroke-width': 1,
  }));
  for (const fraction of [0, 0.5, 1]) {
    const value = min + span * fraction;
    const yy = y(value);
    svg.appendChild(svgEl('line', {
      x1: padding.left, y1: yy, x2: width - padding.right, y2: yy,
      stroke: 'var(--border)', 'stroke-width': 0.5, 'stroke-dasharray': '3 3',
    }));
    const text = svgEl('text', {
      x: padding.left - 6, y: yy + 3, 'text-anchor': 'end',
      fill: 'var(--text-muted)', 'font-size': 10,
    });
    text.textContent = fmtNum(value, 1);
    svg.appendChild(text);
  }

  if (typeof threshold === 'number' && threshold >= min && threshold <= max) {
    svg.appendChild(svgEl('line', {
      x1: padding.left, y1: y(threshold), x2: width - padding.right, y2: y(threshold),
      stroke: 'var(--critical)', 'stroke-width': 1, 'stroke-dasharray': '5 4',
    }));
  }

  const path = usable.map((point, index) =>
    `${index === 0 ? 'M' : 'L'}${x(index).toFixed(1)},${y(point[valueKey]).toFixed(1)}`).join(' ');
  svg.appendChild(svgEl('path', {
    d: path, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 2,
    'stroke-linejoin': 'round',
  }));

  usable.forEach((point, index) => {
    const flagged = typeof threshold === 'number' && point[valueKey] >= threshold;
    if (flagged || index % Math.ceil(usable.length / 24) === 0) {
      svg.appendChild(svgEl('circle', {
        cx: x(index), cy: y(point[valueKey]), r: flagged ? 3.5 : 2,
        fill: flagged ? 'var(--critical)' : 'var(--accent)',
      }));
    }
  });

  const summary = el('p', { class: 'hint' }, [
    `${label}: ${usable.length} readings, from ${fmtNum(min)} to ${fmtNum(max)}.`,
    typeof threshold === 'number' ?
      ` Dashed line marks the alert threshold of ${fmtNum(threshold)}.` : '',
  ]);
  return el('div', {}, [svg, summary]);
}

/** Horizontal bar chart from {label, value} pairs. */
export function barChart(items, { label = 'Distribution', height } = {}) {
  const rows = items.filter((item) => item.value > 0);
  if (!rows.length) return empty('Nothing to chart', `No ${label.toLowerCase()} recorded yet.`);
  const width = 720;
  const rowHeight = 26;
  const total = height || rows.length * rowHeight + 10;
  const max = Math.max(...rows.map((row) => row.value));
  const labelWidth = 150;
  const svg = svgEl('svg', {
    class: 'chart', viewBox: `0 0 ${width} ${total}`, role: 'img',
    'aria-label': `${label}: ${rows.map((r) => `${r.label} ${r.value}`).join(', ')}`,
  });
  rows.forEach((row, index) => {
    const y = index * rowHeight + 6;
    const barWidth = Math.max(2, (row.value / max) * (width - labelWidth - 60));
    const text = svgEl('text', {
      x: 0, y: y + 13, fill: 'var(--text)', 'font-size': 11,
    });
    text.textContent = row.label;
    svg.appendChild(text);
    svg.appendChild(svgEl('rect', {
      x: labelWidth, y, width: barWidth, height: rowHeight - 10, rx: 3,
      fill: row.colour || 'var(--accent)',
    }));
    const value = svgEl('text', {
      x: labelWidth + barWidth + 6, y: y + 13, fill: 'var(--text-muted)', 'font-size': 11,
    });
    value.textContent = String(row.value);
    svg.appendChild(value);
  });
  return svg;
}

export function severityColour(name) {
  const map = {
    INFO: 'var(--info)', LOW: 'var(--info)', WARNING: 'var(--warning)',
    MEDIUM: 'var(--warning)', HIGH: 'var(--high)', CRITICAL: 'var(--critical)',
  };
  return map[String(name).toUpperCase()] || 'var(--accent)';
}

export function confirmDialog(message) {
  // eslint-disable-next-line no-alert
  return window.confirm(message);
}
