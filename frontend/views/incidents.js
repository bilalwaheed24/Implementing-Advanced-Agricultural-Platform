import { el, badge, fmtDate, humanizeText } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { entityLink, incidentTitle } from '/static/views/entity-links.js';

export const render = listView({
  title: 'Incidents',
  subtitle: 'Opened automatically from HIGH/CRITICAL alerts. A later alert about the same '
    + 'record joins the incident already open for it. Containment actions (quarantine, '
    + 'revocation, suspension) are themselves audited API calls.',
  endpoint: '/security/incidents',
  filters: [
    { key: 'status', label: 'Status',
      options: ['OPEN', 'TRIAGED', 'CONTAINED', 'RESOLVED', 'CLOSED'] },
    { key: 'severity', label: 'Severity', options: ['WARNING', 'HIGH', 'CRITICAL'] },
  ],
  columns: [
    { label: 'Opened', render: (row) => fmtDate(row.created_at) },
    { label: 'Title', render: (row) => el('a', { href: `#/incident/${row.id}`,
      text: incidentTitle(row.title) }) },
    { label: 'Severity', render: (row) => badge(row.severity) },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'About', render: (row) => entityLink(row.entity_type, row.entity_id)
      || el('span', { class: 'hint', text: '—' }) },
    { label: 'Summary', render: (row) => el('span', { class: 'hint',
      text: humanizeText(row.summary) }) },
  ],
  emptyTitle: 'No incidents',
  emptyMessage: 'A HIGH or CRITICAL alert opens an incident automatically.',
});
