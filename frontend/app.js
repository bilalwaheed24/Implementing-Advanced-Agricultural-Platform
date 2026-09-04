/* Application shell: hash router, role-filtered navigation, view mounting. */
import { el, clear, session, api, can, toast, errorBox, loading,
         unauthorizedCard } from '/static/assets/core.js';

const NAV = [
  { group: 'Overview', items: [
    { path: '#/dashboard', label: 'Dashboard', permission: null },
  ] },
  { group: 'Farm Operations', items: [
    { path: '#/farms', label: 'Farms & Fields', permission: 'farm:read' },
    { path: '#/devices', label: 'Devices', permission: 'device:read' },
    { path: '#/telemetry', label: 'Telemetry', permission: 'telemetry:read' },
    { path: '#/satellite', label: 'Satellite & NDVI', permission: 'telemetry:read' },
  ] },
  { group: 'Intelligence', items: [
    { path: '#/ai', label: 'AI Insights', permission: 'ai:read' },
    { path: '#/alerts', label: 'Alerts', permission: 'alert:read' },
    { path: '#/incidents', label: 'Incidents', permission: 'incident:read' },
  ] },
  { group: 'Biosecurity', items: [
    { path: '#/screenings', label: 'Sequence Screening', permission: 'biosecurity:read' },
    { path: '#/review-queue', label: 'Review Queue', permission: 'biosecurity:review' },
    { path: '#/crispr', label: 'CRISPR Risk', permission: 'biosecurity:read' },
  ] },
  { group: 'Biotechnology', items: [
    { path: '#/gmo', label: 'GMO Registry', permission: 'gmo:read' },
    { path: '#/seed-lots', label: 'Seed Lots', permission: 'gmo:read' },
  ] },
  { group: 'Supply Chain', items: [
    { path: '#/batches', label: 'Batches', permission: 'supply:read' },
    { path: '#/products', label: 'Products', permission: 'supply:read' },
    { path: '#/shipments', label: 'Shipments', permission: 'supply:read' },
    { path: '#/certifications', label: 'Certifications', permission: 'cert:read' },
    { path: '#/fraud', label: 'Fraud Assessments', permission: 'supply:read' },
  ] },
  { group: 'Trust', items: [
    { path: '#/blockchain', label: 'Blockchain', permission: 'blockchain:read' },
    { path: '#/compliance', label: 'Compliance', permission: 'compliance:read' },
    { path: '#/audit', label: 'Audit Trail', permission: 'audit:read' },
  ] },
  { group: 'Administration', items: [
    { path: '#/users', label: 'Users & Orgs', permission: 'user:read' },
    { path: '#/settings', label: 'Settings', permission: null },
  ] },
];

const ROUTES = {
  '#/login': () => import('/static/views/login.js'),
  '#/dashboard': () => import('/static/views/dashboard.js'),
  '#/farms': () => import('/static/views/farms.js'),
  '#/devices': () => import('/static/views/devices.js'),
  '#/device': () => import('/static/views/device-detail.js'),
  '#/telemetry': () => import('/static/views/telemetry.js'),
  '#/satellite': () => import('/static/views/satellite.js'),
  '#/ai': () => import('/static/views/ai.js'),
  '#/alerts': () => import('/static/views/alerts.js'),
  '#/incidents': () => import('/static/views/incidents.js'),
  '#/incident': () => import('/static/views/incident-detail.js'),
  '#/screenings': () => import('/static/views/screenings.js'),
  '#/screening': () => import('/static/views/screening-detail.js'),
  '#/review-queue': () => import('/static/views/review-queue.js'),
  '#/crispr': () => import('/static/views/crispr.js'),
  '#/gmo': () => import('/static/views/gmo.js'),
  '#/seed-lots': () => import('/static/views/seed-lots.js'),
  '#/batches': () => import('/static/views/batches.js'),
  '#/batch': () => import('/static/views/batch-detail.js'),
  '#/products': () => import('/static/views/products.js'),
  '#/shipments': () => import('/static/views/shipments.js'),
  '#/certifications': () => import('/static/views/certifications.js'),
  '#/fraud': () => import('/static/views/fraud.js'),
  '#/blockchain': () => import('/static/views/blockchain.js'),
  '#/compliance': () => import('/static/views/compliance.js'),
  '#/audit': () => import('/static/views/audit.js'),
  '#/users': () => import('/static/views/users.js'),
  '#/settings': () => import('/static/views/settings.js'),
};

const root = document.getElementById('root');
let unreadTimer = null;

function parseHash() {
  const raw = window.location.hash || '#/dashboard';
  const [path, query] = raw.split('?');
  const segments = path.split('/').filter(Boolean);
  const base = `#/${segments[1] || 'dashboard'}`;
  return {
    base,
    id: segments[2] || null,
    params: new URLSearchParams(query || ''),
  };
}

function sidebar(current) {
  const groups = [];
  for (const group of NAV) {
    const items = group.items.filter((item) => !item.permission || can(item.permission));
    if (!items.length) continue;
    groups.push(el('div', { class: 'nav-group' }, [
      el('h2', { text: group.group }),
      el('nav', { class: 'nav' }, items.map((item) => el('a', {
        href: item.path,
        'aria-current': item.path === current ? 'page' : null,
        text: item.label,
      }))),
    ]));
  }
  const user = session.read();
  return el('aside', { class: 'sidebar' }, [
    el('div', { class: 'brand' }, [
      'ABSP',
      el('small', { text: 'Agricultural Biotechnology Security Platform' }),
    ]),
    el('span', { class: 'demo-flag', title: 'Synthetic data; single-node ledger',
      text: 'DEMO / SIMULATION' }),
    ...groups,
    el('div', { class: 'u-push-top' }, [
      el('div', { class: 'hint', text: user?.full_name || '' }),
      el('div', { class: 'hint mono', text: user?.role || '' }),
      el('button', { class: 'u-mt-8 u-full-width', text: 'Sign out',
        onClick: signOut }),
    ]),
  ]);
}

function topbar(title) {
  const badgeNode = el('span', { class: 'badge neutral', id: 'unread-badge',
    text: 'Notifications' });
  return el('header', { class: 'topbar' }, [
    el('strong', { text: title }),
    el('div', { class: 'spacer' }),
    el('a', { href: '/verify.html', target: '_blank', rel: 'noopener',
      class: 'hint', text: 'Public verification page ↗' }),
    badgeNode,
  ]);
}

async function refreshUnread() {
  if (!session.read()?.access_token) return;
  try {
    const result = await api('/notifications/unread-count');
    const node = document.getElementById('unread-badge');
    if (!node) return;
    clear(node);
    node.className = result.unread > 0 ? 'badge high' : 'badge neutral';
    node.textContent = result.unread > 0
      ? `${result.unread} unread notification${result.unread === 1 ? '' : 's'}`
      : 'No unread notifications';
  } catch { /* non-fatal */ }
}

export function signOut() {
  api('/auth/logout', { method: 'POST' }).catch(() => {});
  session.clear();
  window.location.hash = '#/login';
}

export function navigate(hash) { window.location.hash = hash; }

/* Renders are asynchronous, so two can overlap (a fast hashchange, or the initial load).
 * Only the newest render is allowed to touch the DOM: an older one that resumes after
 * its await returns without mounting anything. Without this the login view mounted
 * twice and produced duplicate id="email"/"password", which breaks label-for binding. */
let renderToken = 0;

async function render() {
  const token = ++renderToken;
  const { base, id, params } = parseHash();
  const authenticated = Boolean(session.read()?.access_token);

  if (!authenticated && base !== '#/login') { window.location.hash = '#/login'; return; }
  if (authenticated && base === '#/login') { window.location.hash = '#/dashboard'; return; }

  const loader = ROUTES[base];
  if (!loader) {
    clear(root);
    root.appendChild(el('div', { class: 'centre' }, [
      el('div', { class: 'card' }, [
        el('h1', { text: 'Page not found' }),
        el('p', { text: `No view is registered for ${base}.` }),
        el('a', { href: '#/dashboard', text: 'Return to the dashboard' }),
      ]),
    ]));
    return;
  }

  if (base === '#/login') {
    const module = await loader();
    if (token !== renderToken) return;
    const view = await module.render({ params });
    if (token !== renderToken) return;
    clear(root);
    root.appendChild(view);
    return;
  }

  clear(root);
  const content = el('main', { class: 'content', id: 'view' }, [loading()]);
  // Skip link: first thing in the tab order, so a keyboard user can jump past the
  // navigation. Focus is moved programmatically instead of letting the browser follow
  // the fragment, because this application routes on the hash and setting it to
  // "#view" would navigate away.
  const skipLink = el('a', {
    href: '#view',
    class: 'skip-link',
    text: 'Skip to main content',
    onClick: (event) => {
      event.preventDefault();
      content.setAttribute('tabindex', '-1');
      content.focus();
    },
  });
  const shell = el('div', { class: 'app' }, [
    skipLink,
    sidebar(base),
    el('div', { class: 'main' }, [topbar('Loading…'), content]),
  ]);
  root.appendChild(shell);
  refreshUnread();

  try {
    const module = await loader();
    if (token !== renderToken) return;
    const view = await module.render({ id, params, navigate });
    if (token !== renderToken) return;
    clear(content);
    content.appendChild(view);
    const heading = content.querySelector('h1');
    const bar = root.querySelector('.topbar strong');
    if (heading && bar) bar.textContent = heading.textContent;
    document.title = heading
      ? `${heading.textContent} — ABSP` : 'Agricultural Biotechnology Security Platform';
  } catch (error) {
    clear(content);
    if (error.status === 401) { session.clear(); window.location.hash = '#/login'; return; }
    if (error.status === 403) {
      content.appendChild(unauthorizedCard());
      return;
    }
    content.appendChild(errorBox(error));
    toast(error.message, 'error');
  }
}

window.addEventListener('hashchange', render);
// Exactly one initial render: listen only while the document is still parsing.
if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', render, { once: true });
} else {
  render();
}
unreadTimer = setInterval(refreshUnread, 30000);
window.addEventListener('beforeunload', () => clearInterval(unreadTimer));
