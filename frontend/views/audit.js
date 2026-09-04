import { el, api, badge, fmtDate, table, toast, can } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

async function verifyCard() {
  try {
    const result = await api('/audit/verify');
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Hash-chain verification' }),
      el('div', { class: 'row' }, [
        result.valid ? badge('VERIFIED') : badge('FAILED'),
        el('span', { class: 'hint', text: `${result.entries} entries, head sequence ${result.head_seq}` }),
        result.anchor_matches ? badge('ANCHORED') : badge('WARNING'),
      ]),
      !result.valid ? el('p', { class: 'error-text',
        text: `First divergence: ${JSON.stringify(result.first_divergence)}` }) : null,
      can('audit:read') ? el('div', { class: 'row u-mt-8' }, [
        el('button', { text: 'Anchor current head to the ledger', onClick: async () => {
          try {
            const receipt = await api('/audit/anchor', { method: 'POST' });
            toast(receipt.ok ? `Anchored in block ${receipt.block_number}` : 'Anchoring pending',
              receipt.ok ? 'ok' : 'error');
          } catch (error) { toast(error.message, 'error'); }
        } }),
        el('a', { href: '/api/v1/audit/export', target: '_blank', rel: 'noopener',
          text: 'Export audit trail (JSON) →' }),
      ]) : null,
    ]);
  } catch (error) {
    return el('div', { class: 'card' }, [el('p', { class: 'error-text', text: error.message })]);
  }
}

export const render = listView({
  title: 'Audit trail',
  subtitle: 'Append-only, hash-chained. Every entry links to the previous one; altering '
    + 'any record breaks the chain from that point forward.',
  endpoint: '/audit/logs',
  extra: verifyCard,
  filters: [{ key: 'outcome', label: 'Outcome', options: ['SUCCESS', 'FAILURE'] }],
  columns: [
    { label: 'Seq', numeric: true, key: 'seq' },
    { label: 'When', render: (row) => fmtDate(row.created_at) },
    { label: 'Action', render: (row) => el('span', { class: 'mono', text: row.action }) },
    { label: 'Actor', render: (row) => row.actor_id
      ? el('span', { class: 'mono', text: row.actor_id.slice(0, 8) }) : 'system' },
    { label: 'Entity', render: (row) => row.entity_type
      ? `${row.entity_type} ${row.entity_id ? row.entity_id.slice(0, 8) : ''}` : '—' },
    { label: 'Outcome', render: (row) => badge(row.outcome) },
    { label: 'Hash', render: (row) => el('span', { class: 'mono',
      text: row.entry_hash.slice(0, 16) + '…' }) },
  ],
  emptyTitle: 'No audit records',
  emptyMessage: 'Audit records are created automatically by every security-relevant action.',
});
