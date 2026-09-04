import { el, api, badge, fmtDate, toast, can } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Incidents',
  subtitle: 'Opened automatically from HIGH/CRITICAL alerts. Containment actions '
    + '(quarantine, revocation, suspension) are themselves audited API calls.',
  endpoint: '/security/incidents',
  filters: [{ key: 'status', label: 'Status',
    options: ['OPEN', 'TRIAGED', 'CONTAINED', 'RESOLVED', 'CLOSED'] }],
  columns: [
    { label: 'Opened', render: (row) => fmtDate(row.created_at) },
    { label: 'Title', render: (row) => el('a', { href: `#/incident/${row.id}`, text: row.title }) },
    { label: 'Severity', render: (row) => badge(row.severity) },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'Summary', render: (row) => el('span', { class: 'hint', text: row.summary }) },
  ],
  emptyTitle: 'No incidents',
  emptyMessage: 'A HIGH or CRITICAL alert opens an incident automatically.',
});
