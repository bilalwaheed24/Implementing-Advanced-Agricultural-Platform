import { el, api, tile, badge, barChart, severityColour, empty, can, session,
         fmtNum, titleCase, humanize, humanizeText, entityHref,
         roleLabel } from '/static/assets/core.js';

/* The server decides which tiles a role gets (only those that mean something to it); this
 * only lays them out, each one a link to the list it counts. */
function buildTiles(dash) {
  const tiles = [];
  const role = dash.role;
  const sc = dash.supply_chain;
  const certs = dash.certifications;

  // A processor's day: what it holds, what is on the road, what has arrived unconfirmed.
  if (sc && role === 'SUPPLY_CHAIN_OPERATOR') {
    tiles.push(tile('Batches held', sc.held, 'In your custody now', '#/batches'));
    tiles.push(tile('Shipments in transit', sc.shipments_in_transit, 'Dispatched, not yet arrived',
      '#/shipments'));
    tiles.push(tile('Hand-overs to book in', sc.pending_handovers,
      'Received batches with no receiving event yet', '#/batches'));
  }
  // A certifier's day: its certificates and where they are claimed.
  if (certs) {
    tiles.push(tile('Certificates issued', certs.issued, `${certs.active} currently valid`,
      '#/certifications'));
    tiles.push(tile('Expiring soon', certs.expiring,
      `Valid certificates ending within ${certs.expiry_window_days} days`, '#/certifications'));
    tiles.push(tile('Claimed on batches', certs.claimed, 'Batches that cite your certificates',
      '#/certifications'));
  }
  if (dash.devices) {
    // `offline` is newer than the other device counts; shown only when the API sends it.
    const offline = typeof dash.devices.offline === 'number'
      ? `, ${dash.devices.offline} offline` : '';
    tiles.push(tile('Devices', dash.devices.total,
      `${dash.devices.active} active, ${dash.devices.quarantined} quarantined${offline}`,
      '#/devices'));
  }
  if (dash.telemetry) {
    tiles.push(tile('Telemetry readings', fmtNum(dash.telemetry.readings, 0),
      `${dash.telemetry.suspect} suspect or quarantined`, '#/telemetry'));
  }
  if (dash.alerts) {
    tiles.push(tile('Open alerts', dash.alerts.open,
      `${dash.alerts.critical_open} critical`, '#/alerts?status=OPEN'));
  }
  if (dash.biosecurity) {
    tiles.push(tile('Screenings', dash.biosecurity.screenings,
      `${dash.biosecurity.pending_review} awaiting review, ${dash.biosecurity.blocked} blocked`,
      can('biosecurity:review') && dash.biosecurity.pending_review
        ? '#/review-queue' : '#/screenings'));
  }
  if (dash.gmo) {
    tiles.push(tile('GMO events', dash.gmo.events, 'Registered and anchored', '#/gmo'));
  }
  if (dash.gmo_holdings) {
    tiles.push(tile('GMO seed lots', dash.gmo_holdings.seed_lots,
      'GMO seed supplied to or held by you', '#/seed-lots'));
    tiles.push(tile('GMO batches', dash.gmo_holdings.batches,
      'Batches with a GMO lineage', '#/batches'));
  }
  if (sc && role !== 'SUPPLY_CHAIN_OPERATOR') {
    tiles.push(tile('Batches', sc.batches, `${sc.events} chain events`, '#/batches'));
  }
  if (sc) {
    tiles.push(tile('Integrity failures', sc.integrity_failed,
      `${sc.integrity_suspect} suspect`, '#/batches?integrity=FAILED'));
  }
  if (dash.ledger) {
    tiles.push(tile('Ledger height', dash.ledger.height,
      `${dash.ledger.transactions} transactions recorded`,
      can('blockchain:explore') ? '#/blockchain' : null));
  }
  tiles.push(tile('Unread notifications', dash.notifications_unread, 'In your inbox',
    '#/notifications'));
  return tiles;
}

function alertItem(alert) {
  const target = entityHref(alert.entity_type, alert.entity_id);
  return el('li', { class: 'bad' }, [
    badge(alert.severity), ' ',
    el('a', { href: target || '#/alerts?status=OPEN', text: alert.title }),
    el('div', { class: 'hint',
      text: `${humanize(alert.category)} — ${humanizeText(alert.detail || '')}` }),
  ]);
}

export async function render() {
  const [dash, alerts] = await Promise.all([
    api('/dashboard'),
    can('alert:read') ? api('/security/alerts?page_size=6&status=OPEN').catch(() => null) : null,
  ]);
  const user = session.read();

  const grid = el('div', { class: 'grid cols-4' }, buildTiles(dash));
  // Counts move while the page is open (a device registered in another tab, an alert raised
  // by telemetry), so they are refreshed when the tab regains focus and on a slow timer.
  // Stops itself once the grid has been mounted and then removed (the user navigated away).
  let mounted = false;
  const gone = () => {
    if (grid.isConnected) mounted = true;
    return mounted && !grid.isConnected;
  };
  const refresh = async () => {
    try { grid.replaceChildren(...buildTiles(await api('/dashboard'))); } catch { /* keep */ }
  };
  const timer = setInterval(() => {
    if (gone()) { clearInterval(timer); return; }
    if (grid.isConnected && document.visibilityState === 'visible') refresh();
  }, 30000);
  const onVisible = () => {
    if (gone()) { document.removeEventListener('visibilitychange', onVisible); return; }
    if (grid.isConnected && document.visibilityState === 'visible') refresh();
  };
  document.addEventListener('visibilitychange', onVisible);

  const sections = [
    el('h1', { text: `Welcome, ${user?.full_name || 'operator'}` }),
    el('p', { class: 'subtitle' }, [
      `Signed in as ${roleLabel(dash.role).toLowerCase()}`
        + (user?.org_name ? ` at ${user.org_name}` : '') + '. ',
      el('span', { class: 'demo-flag', text: 'All data is synthetic' }),
    ]),
    grid,
  ];

  if (alerts?.items?.length) {
    const bySeverity = {};
    for (const alert of alerts.items) {
      bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
    }
    sections.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Open alerts needing attention' }),
      barChart(Object.entries(bySeverity).map(([label, value]) => ({
        label: titleCase(label), value, colour: severityColour(label),
      })), { label: 'Open alerts by severity' }),
      el('ul', { class: 'reasons' }, alerts.items.map(alertItem)),
      el('a', { href: '#/alerts', text: 'View all alerts →' }),
    ]));
  } else if (can('alert:read')) {
    sections.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Alerts' }),
      empty('No open alerts', 'Nothing currently needs attention.'),
    ]));
  }

  sections.push(el('div', { class: 'card' }, [
    el('h2', { text: 'What this platform demonstrates' }),
    el('ul', {}, [
      el('li', { text: 'Agricultural IoT devices with real cryptographic identity, '
        + 'authenticated telemetry and replay protection.' }),
      el('li', { text: 'Biosecurity screening of nucleotide sequences, CRISPR risk '
        + 'assessment and dual-use research monitoring.' }),
      el('li', { text: 'GMO registration and food provenance anchored to a permissioned '
        + 'ledger, verifiable by a regulator or a consumer.' }),
      el('li', { text: 'Automated food-fraud detection and regulatory compliance '
        + 'evaluation with citable rule references.' }),
    ]),
  ]));

  return el('div', {}, sections);
}
