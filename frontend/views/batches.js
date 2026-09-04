import { el, badge, fmtDate, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Traceable batches',
  subtitle: 'Each batch carries a chain of custody anchored to the ledger and a public '
    + 'verification code a consumer can scan.',
  endpoint: '/supply-chain/batches',
  filters: [
    { key: 'state', label: 'State', options: ['CREATED', 'HARVESTED', 'PROCESSED', 'PACKAGED',
      'IN_TRANSIT', 'RECEIVED', 'STORED', 'RETAILED', 'RECALLED'] },
    { key: 'integrity', label: 'Integrity', options: ['VERIFIED', 'SUSPECT', 'FAILED',
      'UNVERIFIED'] },
  ],
  columns: [
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.id}`, class: 'mono',
      text: row.batch_code }) },
    { label: 'State', render: (row) => badge(row.state) },
    { label: 'Quantity', numeric: true, render: (row) => `${fmtNum(row.quantity, 0)} ${row.unit}` },
    { label: 'Origin', render: (row) => row.origin_region
      ? `${row.origin_region}, ${row.origin_country}` : '—' },
    { label: 'GMO lineage', render: (row) => row.gmo_event_id ? badge('WARNING') : '—' },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Integrity', render: (row) => badge(row.integrity_status) },
    { label: 'Verify code', render: (row) => el('a', { href: `/verify.html?code=${row.verification_code}`,
      target: '_blank', rel: 'noopener', class: 'mono', text: row.verification_code }) },
  ],
  emptyTitle: 'No batches',
  emptyMessage: 'Create a batch against a product to begin its chain of custody.',
});
