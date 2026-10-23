import { el, badge, fmtDate, fmtNum, reasonList } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

const RISK_LEVELS = { VERIFIED: 'Low risk', SUSPECT: 'Elevated risk', FAILED: 'High risk' };
const RISK_CLASS = { VERIFIED: 'info', SUSPECT: 'warning', FAILED: 'critical' };

export const render = listView({
  title: 'Fraud assessments',
  subtitle: 'One record per integrity verification run. Rules dominate the score; an '
    + 'anomaly model contributes a novelty component. Visible to the batch owner and to the '
    + 'organisation holding it when the check ran.',
  endpoint: '/supply-chain/fraud-assessments',
  columns: [
    { label: 'Assessed', render: (row) => fmtDate(row.created_at) },
    // The business batch code is what a supply-chain operator recognises; the internal id
    // stays beneath it so a record is still traceable. The link target is unchanged.
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.batch_id}` }, [
      el('div', { class: 'mono', text: row.batch_code || 'Unknown batch' }),
      el('div', { class: 'hint mono', text: `ID: ${String(row.batch_id || '').slice(0, 8)}` }),
    ]) },
    { label: 'Score', numeric: true, render: (row) => fmtNum(row.score, 2) },
    // The fraud-risk band the score falls in, derived from the verdict the engine reached
    // with the configured suspect / fail thresholds (it is not a separate model output).
    { label: 'Risk level', render: (row) => badge(RISK_LEVELS[row.level] || 'UNKNOWN',
      RISK_CLASS[row.level] || 'neutral') },
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
