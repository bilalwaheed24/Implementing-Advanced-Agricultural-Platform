import { el, api, tile, badge, barChart, severityColour, empty, can, session,
         fmtNum, titleCase } from '/static/assets/core.js';

export async function render() {
  const [dash, alerts] = await Promise.all([
    api('/dashboard'),
    can('alert:read') ? api('/security/alerts?page_size=6&status=OPEN').catch(() => null) : null,
  ]);
  const user = session.read();

  const tiles = [];
  if (dash.devices) {
    tiles.push(tile('Devices', dash.devices.total,
      `${dash.devices.active} active, ${dash.devices.quarantined} quarantined`));
  }
  if (dash.telemetry) {
    tiles.push(tile('Telemetry readings', fmtNum(dash.telemetry.readings, 0),
      `${dash.telemetry.suspect} suspect or quarantined`));
  }
  if (dash.alerts) {
    tiles.push(tile('Open alerts', dash.alerts.open,
      `${dash.alerts.critical_open} critical`));
  }
  if (dash.biosecurity) {
    tiles.push(tile('Screenings', dash.biosecurity.screenings,
      `${dash.biosecurity.pending_review} awaiting review, ${dash.biosecurity.blocked} blocked`));
  }
  if (dash.gmo) tiles.push(tile('GMO events', dash.gmo.events, 'Registered and anchored'));
  if (dash.supply_chain) {
    tiles.push(tile('Batches', dash.supply_chain.batches,
      `${dash.supply_chain.events} chain events`));
    tiles.push(tile('Integrity failures', dash.supply_chain.integrity_failed,
      `${dash.supply_chain.integrity_suspect} suspect`));
  }
  if (dash.ledger) {
    tiles.push(tile('Ledger height', dash.ledger.height,
      `${dash.ledger.transactions} transactions · ${dash.ledger.network}`));
  }
  tiles.push(tile('Unread notifications', dash.notifications_unread, 'In your inbox'));

  const sections = [
    el('h1', { text: `Welcome, ${user?.full_name || 'operator'}` }),
    el('p', { class: 'subtitle' }, [
      `Role ${dash.role.replace(/_/g, ' ').toLowerCase()}. `,
      'Tiles below are filtered to the permissions your role actually holds. ',
      el('span', { class: 'demo-flag', text: 'All data is synthetic' }),
    ]),
    el('div', { class: 'grid cols-4' }, tiles),
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
      el('ul', { class: 'reasons' }, alerts.items.map((alert) => el('li', { class: 'bad' }, [
        badge(alert.severity), ' ',
        el('strong', { text: alert.title }),
        el('div', { class: 'hint', text: `${titleCase(alert.category)} — ${alert.detail || ''}` }),
      ]))),
      el('a', { href: '#/alerts', text: 'View all alerts →' }),
    ]));
  } else if (can('alert:read')) {
    sections.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Alerts' }),
      empty('No open alerts', 'Nothing currently needs attention. '
        + 'Run the IoT simulator in spoof mode to raise one.'),
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
