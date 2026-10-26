import { el, api, tile, badge, barChart, severityColour, empty, can, session,
         fmtNum, titleCase, humanize, humanizeText, entityHref,
         roleLabel } from '/static/assets/core.js';

/* Unresolved = OPEN or ACKNOWLEDGED, the status set the "Open alerts" tile counts. */
const UNRESOLVED_ALERTS = '#/alerts?status=UNRESOLVED';

/* The server decides which tiles a role gets (only those that mean something to it); this
 * only lays them out, each one a link to the list it counts. */
function buildTiles(dash) {
  const tiles = [];
  const role = dash.role;
  const sc = dash.supply_chain;
  const certs = dash.certifications;

  // A processor's day: what it holds, what is on the road, what has arrived unconfirmed.
  if (sc && role === 'SUPPLY_CHAIN_OPERATOR') {
    // Linked to the held-only list (same rule server-side), not to every batch it can read.
    tiles.push(tile('Batches held', sc.held, 'In your custody now', '#/batches?held=true'));
    tiles.push(tile('Shipments in transit', sc.shipments_in_transit,
      'Sent or coming to you, not yet arrived', '#/shipments?status=IN_TRANSIT'));
    if (sc.awaiting_arrival) {
      tiles.push(tile('Awaiting your arrival', sc.awaiting_arrival,
        'In transit to you — mark them arrived when they reach you',
        '#/shipments?status=IN_TRANSIT&incoming=true'));
    }
    // Batches already with the operator (not in transit — those are counted above) that it
    // has not received, stored or processed yet, e.g. handed over without a shipment.
    if (sc.pending_handovers) {
      tiles.push(tile('Hand-overs to book in', sc.pending_handovers,
        'Handed to you, no receiving or storing event yet', '#/batches?awaiting_receipt=true'));
    }
  }
  // A certifier's day: its certificates and where they are claimed. Each tile opens the list
  // filtered to exactly what it counts (the server applies the same rules).
  if (certs) {
    const mine = role === 'REGULATOR' ? '' : 'issued_by_me=true';
    const join = (...parts) => `#/certifications?${parts.filter(Boolean).join('&')}`;
    tiles.push(tile('Certificates issued', certs.issued, `${certs.active} currently valid`,
      join(mine)));
    tiles.push(tile('Expiring soon', certs.expiring,
      `Valid certificates ending within ${certs.expiry_window_days} days`,
      join(`expiring_within_days=${certs.expiry_window_days}`, mine)));
    tiles.push(tile('Claimed on batches', certs.claimed, 'Batches that cite your certificates',
      join('claimed=true', mine)));
  }
  if (dash.devices) {
    // `offline` is newer than the other device counts; shown only when the API sends it.
    const offline = typeof dash.devices.offline === 'number'
      ? `, ${dash.devices.offline} offline` : '';
    tiles.push(tile('Devices', dash.devices.total,
      `${dash.devices.active} active, ${dash.devices.quarantined} quarantined${offline}`,
      '#/devices'));
    // A silent fleet is the thing to act on, so it gets its own tile that opens the list
    // filtered to it.
    if (dash.devices.offline) {
      tiles.push(tile('Devices offline', dash.devices.offline,
        'Active devices that have stopped reporting', '#/devices?offline=true'));
    }
  }
  if (dash.telemetry) {
    tiles.push(tile('Telemetry readings', fmtNum(dash.telemetry.readings, 0),
      `${dash.telemetry.suspect} suspect or quarantined`, '#/telemetry'));
  }
  if (dash.alerts) {
    // Open or acknowledged: the tile, its link and the alert card below share one definition.
    tiles.push(tile('Open alerts', dash.alerts.open,
      `${dash.alerts.critical_open} critical — open or acknowledged`, UNRESOLVED_ALERTS));
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
      'Batches with a GMO lineage', '#/batches?gmo=true'));
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

/* The row's edge follows its severity: red for critical and high, amber for a warning,
 * the plain border for information. */
const ALERT_EDGE = { CRITICAL: 'bad', HIGH: 'bad', WARNING: 'warn' };

function alertItem(alert) {
  const target = entityHref(alert.entity_type, alert.entity_id);
  const edge = ALERT_EDGE[String(alert.severity || '').toUpperCase()] || '';
  return el('li', { class: edge }, [
    badge(alert.severity), ' ',
    el('a', { href: target || UNRESOLVED_ALERTS, text: alert.title }),
    el('div', { class: 'hint',
      text: `${humanize(alert.category)} — ${humanizeText(alert.detail || '')}` }),
  ]);
}

export async function render() {
  const [dash, alerts] = await Promise.all([
    api('/dashboard'),
    can('alert:read')
      ? api('/security/alerts?page_size=6&status=UNRESOLVED').catch(() => null) : null,
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
    // The chart covers every unresolved alert (the server's breakdown, the same set the tile
    // counts), not just the six listed below it.
    let bySeverity = dash.alerts?.by_severity;
    if (!bySeverity) {
      bySeverity = {};
      for (const alert of alerts.items) {
        bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
      }
    }
    const order = ['CRITICAL', 'HIGH', 'WARNING', 'INFO'];
    const rank = (severity) => (order.includes(severity) ? order.indexOf(severity) : order.length);
    const total = alerts.total ?? alerts.items.length;
    sections.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Open alerts needing attention' }),
      el('p', { class: 'hint', text: `${total} open or acknowledged`
        + (total > alerts.items.length ? `; the ${alerts.items.length} most recent are listed.`
          : '.') }),
      barChart(Object.entries(bySeverity)
        .sort(([a], [b]) => rank(a) - rank(b))
        .map(([label, value]) => ({
          label: humanize(label), value, colour: severityColour(label),
        })), { label: 'Open or acknowledged alerts by severity' }),
      el('ul', { class: 'reasons' }, alerts.items.map(alertItem)),
      el('a', { href: UNRESOLVED_ALERTS, text: 'View all open alerts →' }),
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
