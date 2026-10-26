import { session, el, api, badge, can, fmtDate, fmtNum, tile, toast, humanize }
  from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, choiceSelect } from '/static/views/formkit.js';

/* Labelled with humanize, as the device page, telemetry picker and alert columns are, so a
 * type reads the same everywhere ("Cold-chain sensor", "Lab instrument"). */
const DEVICE_TYPES = ['SOIL_SENSOR', 'DRONE', 'WEATHER_STATION', 'YIELD_MONITOR',
  'IRRIGATION_CONTROLLER', 'COLD_CHAIN_SENSOR', 'LAB_INSTRUMENT']
  .map((code) => [code, humanize(code)]);

const deviceTypeLabel = (code) => humanize(code);

/* The provisioning secret is returned by the API exactly once. It is rendered here rather
 * than in a toast so the operator can copy it deliberately before dismissing it. */
function secretNotice(device, secret) {
  const value = el('code', { class: 'mono', text: secret });
  const panel = el('div', { class: 'card u-mb-16', role: 'alert' }, [
    el('h3', { text: `Secret for ${device.model} ${device.id.slice(0, 8)}` }),
    el('p', { class: 'hint', text: 'This is the only time this value is shown. Copy it into '
      + 'the device now — if it is lost the device must have its secret rotated.' }),
    el('p', { class: 'hint' }, ['The device is Provisioned: its telemetry is refused until '
      + 'you ', el('a', { href: `#/device/${device.id}`, text: 'open it and press Activate' }),
      '.']),
    value,
    el('div', { class: 'row' }, [
      el('button', { text: 'Copy', onClick: async () => {
        try {
          await navigator.clipboard.writeText(secret);
          toast('Secret copied to the clipboard', 'ok');
        } catch { toast('Select the value and copy it manually', 'error'); }
      } }),
      el('button', { text: 'Dismiss', onClick: () => panel.remove() }),
    ]),
  ]);
  return panel;
}

function registerForm(reload, host) {
  const farmSelect = remoteSelect({
    endpoint: '/farms', requires: 'farm:read', label: (row) => `${row.name} — ${row.region}, ${row.country}`,
    placeholder: 'Select a farm',
    // A device can only be registered on a farm of the caller's own organisation (the API
    // refuses any other), so a cross-tenant role must not be offered other tenants' farms.
    filter: (row) => row.org_id === session.read()?.org_id,
    emptyLabel: 'Your organisation has no farm — devices are registered by the farm that owns them',
  });
  const fieldSelect = remoteSelect({
    endpoint: '/fields', requires: 'farm:read', label: (row) => `${row.name} (${row.area_ha} ha)`,
    required: false, placeholder: 'Whole farm (no specific field)',
    emptyLabel: 'No fields — the device will cover the whole farm',
  });
  // The field list is tenant-scoped by the API; narrow it again to the chosen farm so an
  // operator cannot attach a device to a field on a different farm.
  let allFields = [];
  fieldSelect.whenReady.then((rows) => { allFields = rows; });
  farmSelect.addEventListener('change', () => {
    const chosen = farmSelect.value;
    const matching = allFields.filter((row) => !chosen || row.farm_id === chosen);
    fieldSelect.replaceChildren(
      el('option', { value: '', text: 'Whole farm (no specific field)' }),
      ...matching.map((row) => el('option', { value: row.id,
        text: `${row.name} (${row.area_ha} ha)` })));
    fieldSelect.disabled = false;
  });

  const typeSelect = choiceSelect(DEVICE_TYPES);
  const model = el('input', { required: 'required', maxlength: '120',
    placeholder: 'e.g. FieldProbe S2' });
  const firmware = el('input', { required: 'required', maxlength: '40', value: '1.0.0' });
  const serial = el('input', { maxlength: '120', placeholder: 'optional' });
  const interval = el('input', { type: 'number', min: '5', max: '86400', value: '900',
    required: 'required' });

  return createPanel({
    toggleLabel: 'Register a device',
    submitLabel: 'Register device',
    hint: 'The device is provisioned against your organisation. Its secret is displayed once '
      + 'on this screen, then only a rotation can issue a new one.',
    controls: [
      ['Device type', typeSelect],
      ['Model', model],
      ['Farm', farmSelect],
      ['Field', fieldSelect],
      ['Firmware version', firmware],
      ['Serial number', serial],
      ['Reporting interval (seconds)', interval,
        el('span', { class: 'hint', text: 'How often the device is expected to report. A '
          + 'device silent for three intervals is flagged by the health sweep.' })],
    ],
    submit: async () => {
      const created = await api('/devices', { method: 'POST', body: {
        device_type: typeSelect.value, model: model.value,
        firmware_version: firmware.value, farm_id: farmSelect.value,
        field_id: fieldSelect.value || null,
        serial_number: serial.value || null,
        interval_seconds: Number(interval.value),
      } });
      host.prepend(secretNotice(created.device, created.device_secret));
      return `Device ${created.device.id.slice(0, 8)} provisioned`;
    },
    onDone: reload,
  });
}

/* The fleet broken down with the dashboard's definitions: "active" is active and reporting,
 * a silent device (still status Active so it can come back) counts as offline instead, and
 * the order matches the dashboard tile ("12 active, 0 quarantined, 2 offline"). */
function fleetBreakdown(byStatus, offline) {
  const active = Math.max(0, (byStatus.ACTIVE || 0) - offline);
  const parts = [`${active} active`, `${byStatus.QUARANTINED || 0} quarantined`,
    `${offline} offline`];
  for (const status of ['PROVISIONED', 'SUSPENDED', 'RETIRED']) {
    if (byStatus[status]) parts.push(`${byStatus[status]} ${humanize(status).toLowerCase()}`);
  }
  return parts.join(', ');
}

async function postureCard() {
  try {
    const [posture, offlinePage] = await Promise.all([
      api('/devices/posture'),
      api('/devices?offline=true&status=ACTIVE&page=1&page_size=1').catch(() => null),
    ]);
    const severities = posture.open_by_severity || {};
    const offline = Number(offlinePage?.total) || 0;
    return el('div', { class: 'grid cols-4 u-mb-16' }, [
      tile('Fleet size', posture.devices_total,
        fleetBreakdown(posture.devices_by_status || {}, offline)),
      tile('Open vulnerabilities', posture.vulnerabilities_open,
        `${severities.CRITICAL || 0} critical, ${severities.HIGH || 0} high`),
      tile('Devices affected', posture.devices_affected,
        `${posture.devices_clean} clean`),
      tile('Remediation rate', `${Math.round((posture.remediation_rate || 0) * 100)}%`,
        `${posture.vulnerabilities_remediated} remediated`),
    ]);
  } catch {
    return null;
  }
}

/* Farm and field names for the list, loaded once per render. A role without farm:read sees
 * short ids instead. */
const places = { farms: new Map(), fields: new Map() };

async function loadPlaces() {
  places.farms.clear();
  places.fields.clear();
  if (!can('farm:read')) return;
  const [farms, fields] = await Promise.all([
    api('/farms?page=1&page_size=200').catch(() => ({ items: [] })),
    api('/fields?page=1&page_size=200').catch(() => ({ items: [] })),
  ]);
  for (const row of farms.items || []) places.farms.set(row.id, row.name);
  for (const row of fields.items || []) places.fields.set(row.id, row.name);
}

function locationCell(row) {
  const farm = places.farms.get(row.farm_id);
  const fieldName = row.field_id ? places.fields.get(row.field_id) : null;
  if (!farm) return el('span', { class: 'mono hint', text: row.farm_id.slice(0, 8) });
  return el('div', {}, [
    el('a', { href: `#/farm/${row.farm_id}`, text: farm }),
    el('div', { class: 'hint', text: row.field_id ? (fieldName || 'Field') : 'Whole farm' }),
  ]);
}

function statusCell(row) {
  if (row.status === 'PROVISIONED') {
    return el('div', {}, [badge(row.status), el('div', { class: 'hint',
      text: 'Load its secret, then open it and press Activate' })]);
  }
  if (row.status === 'ACTIVE' && row.offline_since) {
    return el('div', {}, [badge(row.status), ' ', badge('OFFLINE', 'warning'),
      el('div', { class: 'hint', text: `Silent since ${fmtDate(row.offline_since)}` })]);
  }
  return badge(row.status);
}

const listing = listView({
  title: 'Device trust centre',
  subtitle: 'Every device holds a cryptographic identity. Telemetry is HMAC-authenticated, '
    + 'replay-protected and range-validated before it is stored. A newly registered device '
    + 'is Provisioned: it is activated from its own page once its secret is loaded onto it.',
  endpoint: '/devices',
  extra: postureCard,
  actions: ({ reload, host }) => (can('device:write') ? registerForm(reload, host) : null),
  filters: [
    { key: 'device_type', label: 'Type', options: DEVICE_TYPES },
    { key: 'status', label: 'Status', options: ['PROVISIONED', 'ACTIVE', 'SUSPENDED',
      'QUARANTINED', 'RETIRED'] },
    // Silence is not a status (an offline device stays Active so it can come back), so it is
    // its own filter.
    { key: 'offline', label: 'Reporting', allLabel: 'All devices',
      options: [['true', 'Offline (silent)'], ['false', 'Reporting']] },
  ],
  // Client-side: the device list endpoint has no text search parameter.
  search: { placeholder: 'Model, serial number, farm or field',
    fields: (row) => [row.model, row.serial_number, row.id, row.firmware_version,
      places.farms.get(row.farm_id), places.fields.get(row.field_id)].filter(Boolean)
      .join(' ') },
  emptyFor: (active) => (active.offline === 'true'
    ? { title: 'No device is offline', message: 'Every active device has reported within '
      + 'three of its reporting intervals.' } : null),
  columns: [
    { label: 'Device', render: (row) => el('div', {}, [
      el('a', { href: `#/device/${row.id}`, text: row.model }),
      el('div', { class: 'hint mono', text: row.id.slice(0, 8) }),
    ]) },
    { label: 'Type', render: (row) => deviceTypeLabel(row.device_type) },
    { label: 'Location', render: (row) => locationCell(row) },
    { label: 'Firmware', render: (row) => el('span', { class: 'mono', text: row.firmware_version }) },
    { label: 'Status', render: (row) => statusCell(row) },
    { label: 'Battery', numeric: true, render: (row) =>
      row.battery_pct === null ? '—' : `${fmtNum(row.battery_pct, 0)}%` },
    { label: 'Auth failures', numeric: true, render: (row) => row.auth_failures },
    { label: 'Last seen', render: (row) => fmtDate(row.last_seen_at) },
  ],
  emptyTitle: 'No devices registered',
  emptyMessage: 'Register a device to receive its one-time secret, then activate it.',
});

export async function render(context = {}) {
  await loadPlaces();
  // An older link said ?status=OFFLINE, which is not a device status: read it as the
  // offline filter rather than sending a status no device has.
  const params = new URLSearchParams(context.params || '');
  if (params.get('status') === 'OFFLINE') {
    params.delete('status');
    params.set('offline', 'true');
  }
  return listing({ ...context, params });
}
