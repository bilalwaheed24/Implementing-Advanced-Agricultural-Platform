import { el, api, badge, fmtDate, fmtNum, table, toast, can, empty, lineChart,
         confirmDialog, rowHeader, channelLabel,
         humanize, refreshView } from '/static/assets/core.js';
import { createPanel, choiceSelect } from '/static/views/formkit.js';
import { incidentLink, incidentTitle } from '/static/views/entity-links.js';

/* Keys of a series point that are not sensor channels. */
const NON_CHANNEL_KEYS = ['recorded_at', 'anomaly_score', 'quality'];

/* Seed data marks its sample findings "(demo data)"; that is provenance for the seed script,
 * not something an operator needs to read on every row. */
function cleanTitle(text) {
  return String(text || '').replace(/\s*\(demo data\)\s*$/i, '');
}

export function deviceName(device) {
  return `${device.model || humanize(device.device_type)} · ${device.id.slice(0, 8)}`;
}

async function containmentAction(id, action, promptText) {
  const reason = window.prompt(promptText);
  if (!reason) return false;
  await api(`/devices/${id}/${action}`, { method: 'POST', body: { reason } });
  return true;
}

function lifecycleActions(id, device) {
  const actions = [];
  if (can('device:write') && device.status === 'PROVISIONED') {
    actions.push(el('button', { class: 'primary', text: 'Activate', onClick: async () => {
      try {
        await api(`/devices/${id}/activate`, { method: 'POST' });
        toast('Device activated: it may now send telemetry', 'ok');
        refreshView();
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (can('device:write') && device.status === 'ACTIVE') {
    actions.push(el('button', { text: 'Rotate secret', onClick: async () => {
      try {
        const result = await api(`/devices/${id}/rotate-secret`, { method: 'POST' });
        window.prompt('New device secret (shown once — copy it now):', result.device_secret);
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  // Only the lifecycle moves the server actually permits from the current state are offered
  // (devices.LIFECYCLE): ACTIVE <-> SUSPENDED, and no route back out of RETIRED.
  if (can('device:contain') && device.status === 'ACTIVE') {
    actions.push(el('button', { text: 'Suspend', onClick: async () => {
      if (!confirmDialog('Suspend this device? It stops reporting until it is resumed. Use '
        + 'quarantine instead if you suspect the device is compromised.')) return;
      try {
        if (await containmentAction(id, 'suspend',
          'Reason for suspension (written to the audit trail):')) {
          toast('Device suspended', 'ok');
          refreshView();
        }
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (can('device:write') && device.status === 'SUSPENDED') {
    actions.push(el('button', { class: 'primary', text: 'Resume', onClick: async () => {
      try {
        await api(`/devices/${id}/activate`, { method: 'POST' });
        toast('Device resumed', 'ok');
        refreshView();
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (can('device:contain') && ['ACTIVE', 'SUSPENDED'].includes(device.status)) {
    actions.push(el('button', { class: 'danger', text: 'Quarantine', onClick: async () => {
      if (!confirmDialog('Quarantine this device? Its credential will be revoked immediately '
        + 'and further telemetry will be rejected. This is a containment action.')) return;
      try {
        if (await containmentAction(id, 'quarantine',
          'Reason for quarantine (written to the audit trail):')) {
          toast('Device quarantined', 'ok');
          refreshView();
        }
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (can('device:contain') && device.status !== 'RETIRED') {
    actions.push(el('button', { text: 'Retire', onClick: async () => {
      if (!confirmDialog('Retire this device permanently?')) return;
      try {
        if (await containmentAction(id, 'retire', 'Reason for retirement:')) {
          toast('Device retired', 'ok');
          refreshView();
        }
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  return actions;
}

function detailsTable(device, farm, fieldRow) {
  const farmCell = farm
    ? el('a', { href: `#/farm/${farm.id}`, text: `${farm.name} — ${farm.region}, ${farm.country}` })
    : el('span', { class: 'mono', text: device.farm_id.slice(0, 8) });
  let fieldCell = 'Whole farm';
  if (device.field_id) {
    fieldCell = fieldRow
      ? el('a', { href: `#/farm/${device.farm_id}`, text: `${fieldRow.name} (${fieldRow.area_ha} ha)` })
      : el('span', { class: 'mono', text: device.field_id.slice(0, 8) });
  }
  return el('table', {}, [
    el('tr', {}, [rowHeader('Type'), el('td', { text: humanize(device.device_type) })]),
    el('tr', {}, [rowHeader('Model'), el('td', { text: device.model })]),
    el('tr', {}, [rowHeader('Serial number'),
      el('td', { class: 'mono', text: device.serial_number || '—' })]),
    el('tr', {}, [rowHeader('Firmware'), el('td', { class: 'mono', text: device.firmware_version })]),
    el('tr', {}, [rowHeader('Farm'), el('td', {}, [farmCell])]),
    el('tr', {}, [rowHeader('Field'), el('td', {}, [fieldCell])]),
    el('tr', {}, [rowHeader('Reporting interval'),
      el('td', { text: `every ${device.interval_seconds} s` })]),
    el('tr', {}, [rowHeader('Last seen'), el('td', { text: fmtDate(device.last_seen_at) })]),
    el('tr', {}, [rowHeader('Device id'), el('td', { class: 'mono', text: device.id })]),
  ]);
}

function telemetryCharts(series) {
  const channels = [];
  for (const point of series.points) {
    for (const [key, value] of Object.entries(point)) {
      if (!NON_CHANNEL_KEYS.includes(key) && typeof value === 'number'
          && !channels.includes(key)) channels.push(key);
    }
  }
  if (!series.points.length || !channels.length) {
    return [empty('No telemetry', 'This device has not reported in the last 48 hours.')];
  }
  return channels.map((key) => el('div', { class: 'u-m-12-0' }, [
    el('h3', { text: channelLabel(key) }),
    lineChart(series.points, { valueKey: key, label: channelLabel(key), threshold: null }),
  ]));
}

function vulnerabilityForm(device) {
  const cve = el('input', { required: 'required', maxlength: '40', placeholder: 'CVE-2026-12345' });
  const title = el('input', { required: 'required', maxlength: '255',
    placeholder: 'What the weakness allows' });
  const severity = choiceSelect([['LOW', 'Low'], ['MEDIUM', 'Medium'], ['HIGH', 'High'],
    ['CRITICAL', 'Critical']], { value: 'MEDIUM' });
  const cvss = el('input', { type: 'number', min: '0', max: '10', step: '0.1',
    placeholder: 'optional' });
  const affected = el('input', { maxlength: '120', placeholder: `e.g. <= ${device.firmware_version}` });
  const fixed = el('input', { maxlength: '40', placeholder: 'optional' });
  return createPanel({
    toggleLabel: 'Record a vulnerability',
    submitLabel: 'Record vulnerability',
    primary: false,
    hint: 'A HIGH or CRITICAL finding raises an alert and opens an incident for this device.',
    controls: [
      ['CVE / advisory id', cve], ['Title', title], ['Severity', severity],
      ['CVSS score', cvss], ['Affected versions', affected], ['Fixed in', fixed],
    ],
    submit: async () => {
      await api('/devices/vulnerabilities', { method: 'POST', body: {
        device_id: device.id, cve_id: cve.value.trim(), title: title.value.trim(),
        severity: severity.value, cvss: cvss.value === '' ? null : Number(cvss.value),
        affected_versions: affected.value.trim() || null,
        fixed_in: fixed.value.trim() || null,
      } });
      return `${cve.value.trim()} recorded`;
    },
    onDone: refreshView,
  });
}

async function remediate(row) {
  const firmware = window.prompt('Firmware version now installed (leave blank to keep the '
    + 'recorded version):', row.fixed_in || '');
  if (firmware === null) return;
  try {
    await api(`/devices/vulnerabilities/${row.id}/remediate`, { method: 'POST',
      body: { new_firmware: firmware.trim() || null } });
    toast(`${row.cve_id} marked remediated`, 'ok');
    refreshView();
  } catch (error) { toast(error.message, 'error'); }
}

function vulnerabilitiesCard(device, vulns) {
  const writable = can('device:write');
  const columns = [
    { label: 'CVE', render: (row) => el('span', { class: 'mono', text: row.cve_id }) },
    { label: 'Title', render: (row) => cleanTitle(row.title) },
    { label: 'Severity', render: (row) => badge(row.severity) },
    { label: 'Fixed in', render: (row) => row.fixed_in || '—' },
    { label: 'Status', render: (row) => badge(row.status) },
  ];
  if (writable) {
    columns.push({ label: 'Actions', render: (row) => (row.status === 'OPEN'
      ? el('button', { text: 'Mark remediated', onClick: () => remediate(row) })
      : el('span', { class: 'hint', text: fmtDate(row.remediated_at) })) });
  }
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Vulnerabilities' }),
    writable && device.status !== 'RETIRED' ? vulnerabilityForm(device) : null,
    vulns.length ? table(columns, vulns)
      : empty('No known vulnerabilities', 'Nothing recorded against this device.'),
  ]);
}

function alertsCard(alerts) {
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Alerts' }),
    table([
      { label: 'Raised', render: (row) => fmtDate(row.created_at) },
      { label: 'Alert', render: (row) => el('div', {}, [
        el('strong', { text: row.title }),
        row.occurrences > 1 ? el('div', { class: 'hint',
          text: `Seen ${row.occurrences} times, last ${fmtDate(row.last_seen_at)}` }) : null,
      ]) },
      { label: 'Severity', render: (row) => badge(row.severity) },
      { label: 'Status', render: (row) => badge(row.status) },
      { label: 'Incident', render: (row) => incidentLink(row.incident_id) || '—' },
    ], alerts, { emptyTitle: 'No alerts', emptyMessage: 'Nothing has been raised for this device.' }),
    el('a', { href: '#/alerts', text: 'All alerts →' }),
  ]);
}

function incidentsCard(incidents) {
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Incidents' }),
    table([
      { label: 'Opened', render: (row) => fmtDate(row.created_at) },
      { label: 'Incident', render: (row) => incidentLink(row.id, incidentTitle(row.title)) },
      { label: 'Severity', render: (row) => badge(row.severity) },
      { label: 'Status', render: (row) => badge(row.status) },
    ], incidents, { emptyTitle: 'No incidents',
      emptyMessage: 'No incident has been opened for this device.' }),
  ]);
}

function provisionedNotice(device) {
  if (device.status !== 'PROVISIONED') return null;
  return el('div', { class: 'card', role: 'status' }, [
    el('strong', { text: 'Not yet active. ' }),
    'A provisioned device holds a secret but its telemetry is refused until it is activated. '
    + 'Load the secret issued at registration onto the device, then press Activate. '
    + (can('device:write') ? '' : 'Only the farm\'s operators can activate a device.'),
  ]);
}

function offlineNotice(device) {
  if (!device.offline_since || device.status !== 'ACTIVE') return null;
  return el('div', { class: 'card', role: 'status' }, [
    el('strong', { text: 'Not reporting. ' }),
    `No telemetry since ${fmtDate(device.offline_since)}. The device stays active so it can `
    + 'reconnect; its next accepted reading clears this.',
  ]);
}

export async function render({ id }) {
  if (!id) return empty('No device selected', 'Choose a device from the list.');
  const device = await api(`/devices/${id}`);
  const none = { items: [] };
  const [series, vulns, farm, fields, alerts, incidents] = await Promise.all([
    can('telemetry:read') ? api(`/telemetry/devices/${id}/series?hours=48`)
      .catch(() => ({ points: [] })) : { points: [] },
    api(`/devices/vulnerabilities?device_id=${id}&page_size=100`).catch(() => none),
    can('farm:read') ? api(`/farms/${device.farm_id}`).catch(() => null) : null,
    can('farm:read') && device.field_id
      ? api(`/fields?farm_id=${device.farm_id}&page_size=200`).catch(() => none) : none,
    can('alert:read') ? api(`/security/alerts?entity_id=${id}&page_size=50`).catch(() => none)
      : null,
    can('incident:read') ? api(`/security/incidents?entity_id=${id}&page_size=50`)
      .catch(() => none) : null,
  ]);
  const fieldRow = (fields.items || []).find((row) => row.id === device.field_id) || null;

  return el('div', {}, [
    el('h1', { text: deviceName(device) }),
    el('p', { class: 'subtitle' }, [
      humanize(device.device_type),
      farm ? ` on ${farm.name}` : '',
      fieldRow ? `, ${fieldRow.name}` : '',
      ' · ', badge(device.status),
      device.offline_since && device.status === 'ACTIVE' ? [' ', badge('OFFLINE', 'warning')] : null,
    ].flat()),
    device.quarantine_reason ? el('div', { class: 'card', role: 'alert' }, [
      el('strong', { text: 'Quarantined: ' }), device.quarantine_reason,
    ]) : null,
    provisionedNotice(device),
    offlineNotice(device),
    el('div', { class: 'grid cols-4' }, [
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Status' }),
        el('div', { class: 'u-mt-6' }, [badge(device.status)])]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Firmware' }),
        el('div', { class: 'value mono u-fs-16', text: device.firmware_version })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Battery' }),
        el('div', { class: 'value', text: device.battery_pct === null ? '—'
          : `${fmtNum(device.battery_pct, 0)}%` })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Auth failures' }),
        el('div', { class: 'value', text: device.auth_failures })]),
    ]),
    el('div', { class: 'row u-m-12-0' }, lifecycleActions(id, device)),
    el('div', { class: 'card' }, [el('h2', { text: 'Details' }),
      detailsTable(device, farm, fieldRow)]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Telemetry, last 48 hours' }),
      ...telemetryCharts(series),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Anomaly score' }),
      series.points.some((p) => p.anomaly_score !== null)
        ? lineChart(series.points, { valueKey: 'anomaly_score', label: 'Anomaly score',
          threshold: 0.65 })
        : empty('No scored readings', 'Anomaly scoring may be deferred; the health sweep '
          + 'scores readings that were stored while the AI service was unavailable.'),
    ]),
    alerts ? alertsCard(alerts.items || []) : null,
    incidents ? incidentsCard(incidents.items || []) : null,
    vulnerabilitiesCard(device, vulns.items || []),
    el('a', { href: '#/devices', text: '← All devices' }),
  ]);
}
