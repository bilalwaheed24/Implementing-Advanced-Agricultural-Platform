import { el, api, badge, can, fmtDate, fmtNum, tile, toast, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, choiceSelect } from '/static/views/formkit.js';

const DEVICE_TYPES = [
  ['SOIL_SENSOR', 'Soil sensor'],
  ['DRONE', 'Drone'],
  ['WEATHER_STATION', 'Weather station'],
  ['YIELD_MONITOR', 'Yield monitor'],
  ['IRRIGATION_CONTROLLER', 'Irrigation controller'],
  ['COLD_CHAIN_SENSOR', 'Cold-chain sensor'],
];

/* The provisioning secret is returned by the API exactly once. It is rendered here rather
 * than in a toast so the operator can copy it deliberately before dismissing it. */
function secretNotice(device, secret) {
  const value = el('code', { class: 'mono', text: secret });
  const panel = el('div', { class: 'card u-mb-16', role: 'alert' }, [
    el('h3', { text: `Secret for ${titleCase(device.device_type)} ${device.id.slice(0, 8)}` }),
    el('p', { class: 'hint', text: 'This is the only time this value is shown. Copy it into '
      + 'the device now — if it is lost the device must have its secret rotated.' }),
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
    placeholder: 'Select a farm', emptyLabel: 'Register a farm first',
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

async function postureCard() {
  try {
    const posture = await api('/devices/posture');
    const severities = posture.open_by_severity || {};
    return el('div', { class: 'grid cols-4 u-mb-16' }, [
      tile('Fleet size', posture.devices_total,
        Object.entries(posture.devices_by_status || {})
          .map(([k, v]) => `${v} ${k.toLowerCase()}`).join(', ')),
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

export const render = listView({
  title: 'Device trust centre',
  subtitle: 'Every device holds a cryptographic identity. Telemetry is HMAC-authenticated, '
    + 'replay-protected and range-validated before it is stored.',
  endpoint: '/devices',
  extra: postureCard,
  actions: ({ reload, host }) => (can('device:write') ? registerForm(reload, host) : null),
  filters: [
    { key: 'device_type', label: 'Type', options: ['DRONE', 'SOIL_SENSOR', 'WEATHER_STATION',
      'YIELD_MONITOR', 'IRRIGATION_CONTROLLER', 'COLD_CHAIN_SENSOR'] },
    { key: 'status', label: 'Status', options: ['PROVISIONED', 'ACTIVE', 'SUSPENDED',
      'QUARANTINED', 'RETIRED'] },
  ],
  columns: [
    { label: 'Device', render: (row) => el('a', { href: `#/device/${row.id}`,
      class: 'mono', text: row.id.slice(0, 8) }) },
    { label: 'Type', render: (row) => titleCase(row.device_type) },
    { label: 'Model', key: 'model' },
    { label: 'Firmware', render: (row) => el('span', { class: 'mono', text: row.firmware_version }) },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'Battery', numeric: true, render: (row) =>
      row.battery_pct === null ? '—' : `${fmtNum(row.battery_pct, 0)}%` },
    { label: 'Auth failures', numeric: true, render: (row) => row.auth_failures },
    { label: 'Last seen', render: (row) => fmtDate(row.last_seen_at) },
  ],
  emptyTitle: 'No devices registered',
  emptyMessage: 'Register a device to receive its one-time secret, then activate it.',
});
