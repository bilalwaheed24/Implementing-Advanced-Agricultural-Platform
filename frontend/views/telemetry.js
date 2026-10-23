import { el, api, badge, can, fmtDate, fmtNum, titleCase, channelReading }
  from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

/* The device filter offers this organisation's devices by name. */
async function deviceOptions() {
  if (!can('device:read')) return [];
  try {
    const page = await api('/devices?page=1&page_size=200');
    return (page.items || []).map((device) => [device.id,
      `${titleCase(device.device_type)} — ${device.model} (${device.id.slice(0, 8)})`]);
  } catch { return []; }
}

export const render = listView({
  title: 'Telemetry',
  subtitle: 'Payloads are encrypted at rest; only a non-sensitive numeric summary is shown '
    + 'here. Quality reflects range validation and anomaly scoring.',
  endpoint: '/telemetry',
  filters: [
    { key: 'device_id', label: 'Device', allLabel: 'All devices', options: deviceOptions },
    { key: 'quality', label: 'Quality', options: ['OK', 'SUSPECT', 'QUARANTINED'] },
  ],
  columns: [
    { label: 'Recorded', render: (row) => fmtDate(row.recorded_at) },
    { label: 'Device', render: (row) => el('a', { href: `#/device/${row.device_id}` }, [
      el('span', { text: row.device_type ? titleCase(row.device_type) : 'Device' }),
      el('span', { class: 'hint mono u-ml-6', text: row.device_id.slice(0, 8) }),
    ]) },
    { label: 'Quality', render: (row) => badge(row.quality) },
    { label: 'Anomaly', numeric: true, render: (row) =>
      row.anomaly_score === null ? 'Pending' : fmtNum(row.anomaly_score, 3) },
    { label: 'Readings', render: (row) => el('span', { class: 'hint',
      text: Object.entries(row.summary || {})
        .filter(([, value]) => typeof value === 'number').slice(0, 4)
        .map(([key, value]) => channelReading(key, value)).join(' · ') }) },
    { label: 'Backfilled', render: (row) => (row.backfilled
      ? el('span', { class: 'badge neutral', text: 'Sent late' }) : '—') },
  ],
  emptyTitle: 'No telemetry yet',
  emptyMessage: 'Readings appear here once a registered device starts reporting.',
});
