import { el, api, badge, fmtDate, titleCase, toast, can } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function actionButtons(row, reload) {
  if (!can('alert:write') || row.status !== 'OPEN') {
    return el('span', { class: 'hint', text: titleCase(row.status) });
  }
  return el('div', { class: 'row' }, [
    el('button', { text: 'Acknowledge', onClick: async () => {
      try {
        await api(`/security/alerts/${row.id}/acknowledge`, { method: 'POST' });
        toast('Alert acknowledged', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }),
    el('button', { text: 'Resolve', onClick: async () => {
      try {
        await api(`/security/alerts/${row.id}/resolve`, { method: 'POST' });
        toast('Alert resolved', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }),
  ]);
}

export const render = listView({
  title: 'Security and agronomy alerts',
  subtitle: 'Raised by AI scoring, deterministic rules and scheduled sweeps. '
    + 'Every alert carries the reasons that produced it.',
  endpoint: '/security/alerts',
  filters: [
    { key: 'severity', label: 'Severity', options: ['INFO', 'WARNING', 'HIGH', 'CRITICAL'] },
    { key: 'status', label: 'Status', options: ['OPEN', 'ACKNOWLEDGED', 'RESOLVED'] },
    { key: 'category', label: 'Category', options: ['DEVICE_ANOMALY', 'DEVICE_HEALTH',
        'DEVICE_AUTH', 'DATA_THEFT', 'BIOSECURITY', 'DURC', 'FRAUD', 'COMPLIANCE',
        'CERTIFICATION', 'AGRONOMY'] },
    ],
  columns: [
    { label: 'Raised', render: (row) => fmtDate(row.created_at) },
    { label: 'Severity', render: (row) => badge(row.severity) },
    { label: 'Category', render: (row) => titleCase(row.category) },
    { label: 'Title', render: (row) => el('div', {}, [
        el('strong', { text: row.title }),
        row.detail ? el('div', { class: 'hint', text: row.detail }) : null,
      ]) },
    { label: 'Reasons', render: (row) => el('span', { class: 'hint',
        text: (row.reasons || []).slice(0, 2)
          .map((r) => (typeof r === 'string' ? r : r.rule || '')).join('; ') }) },
    { label: 'Status', render: (row, ctx) => actionButtons(row, ctx.reload) },
  ],
  emptyTitle: 'No alerts',
  emptyMessage: 'Nothing has triggered an alert. Try: python3 iot/simulator.py --mode spoof',
});
