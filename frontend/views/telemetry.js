import { el, badge, fmtDate, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Telemetry',
  subtitle: 'Payloads are encrypted at rest; only a non-sensitive numeric summary is shown '
    + 'here. Quality reflects range validation and anomaly scoring.',
  endpoint: '/telemetry',
  filters: [{ key: 'quality', label: 'Quality', options: ['OK', 'SUSPECT', 'QUARANTINED'] }],
  columns: [
    { label: 'Recorded', render: (row) => fmtDate(row.recorded_at) },
    { label: 'Device', render: (row) => el('a', { href: `#/device/${row.device_id}`,
      class: 'mono', text: row.device_id.slice(0, 8) }) },
    { label: 'Quality', render: (row) => badge(row.quality) },
    { label: 'Anomaly', numeric: true, render: (row) =>
      row.anomaly_score === null ? 'pending' : fmtNum(row.anomaly_score, 3) },
    { label: 'Channels', render: (row) => el('span', { class: 'mono hint',
      text: Object.entries(row.summary || {}).slice(0, 4)
        .map(([k, v]) => `${k}=${fmtNum(v, 1)}`).join('  ') }) },
    { label: 'Backfilled', render: (row) => row.backfilled ? badge('WARNING') : '—' },
  ],
  emptyTitle: 'No telemetry yet',
  emptyMessage: 'Run: python3 iot/simulator.py --mode normal --count 20',
});
