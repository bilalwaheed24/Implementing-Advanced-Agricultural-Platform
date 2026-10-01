import { el, badge, fmtDate, reasonList } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Fraud assessments',
  subtitle: 'One record per integrity verification run. Rules dominate the score; an '
    + 'anomaly model contributes a novelty component (ADR-012).',
  endpoint: '/supply-chain/fraud-assessments',
  columns: [
    { label: 'Assessed', render: (row) => fmtDate(row.created_at) },
    // The business batch code is what a supply-chain operator recognises; the internal id
    // stays beneath it so a record is still traceable. The link target is unchanged.
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.batch_id}` }, [
      el('div', { class: 'mono', text: row.batch_code || 'Unknown batch' }),
      el('div', { class: 'hint mono', text: `ID: ${String(row.batch_id || '').slice(0, 8)}` }),
    ]) },
    { label: 'Score', numeric: true, key: 'score' },
    // `level` holds VERIFIED / SUSPECT / FAILED — the integrity verdict, not a fraud-risk
    // band. The heading said Level while the cell said Verified, which read as two
    // different things. No risk level is invented; the column is named what it holds.
    { label: 'Integrity', render: (row) => badge(row.level) },
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
