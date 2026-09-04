import { el, api, badge, fmtDate, fmtNum, tile, toast, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

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
