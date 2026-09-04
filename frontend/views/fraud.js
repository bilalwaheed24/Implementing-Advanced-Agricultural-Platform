import { el, badge, fmtDate, reasonList } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Fraud assessments',
  subtitle: 'One record per integrity verification run. Rules dominate the score; an '
    + 'anomaly model contributes a novelty component (ADR-012).',
  endpoint: '/supply-chain/fraud-assessments',
  columns: [
    { label: 'Assessed', render: (row) => fmtDate(row.created_at) },
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.batch_id}`,
      class: 'mono', text: row.batch_id.slice(0, 8) }) },
    { label: 'Score', numeric: true, key: 'score' },
    { label: 'Level', render: (row) => badge(row.level) },
    { label: 'Ledger', render: (row) => badge(row.ledger_status) },
    { label: 'Reasons', render: (row) => (row.reasons || []).length
      ? el('details', {}, [
        el('summary', { class: 'hint', text: `${row.reasons.length} finding(s)` }),
        reasonList(row.reasons),
      ]) : el('span', { class: 'hint', text: 'none' }) },
  ],
  emptyTitle: 'No fraud assessments yet',
  emptyMessage: 'Run an integrity verification from a batch detail page to produce one.',
});
