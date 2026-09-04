import { el, api, badge, fmtDate, toast, can, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function revokeButton(row, reload) {
  if (row.status !== 'ACTIVE' || !can('cert:revoke')) return badge(row.status);
  return el('div', { class: 'row' }, [
    badge(row.status),
    el('button', { class: 'danger', text: 'Revoke', onClick: async () => {
      const reason = window.prompt('Reason for revocation (written to the ledger and the audit trail):');
      if (!reason) return;
      try {
        await api(`/supply-chain/certifications/${row.id}/revoke`, {
          method: 'POST', body: { reason } });
        toast('Certification revoked', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }),
  ]);
}

export const render = listView({
  title: 'Certifications',
  subtitle: 'Organic, non-GMO and specialty claims. Issuance and revocation are anchored, '
    + 'so a revoked certificate cannot later be presented as valid.',
  endpoint: '/supply-chain/certifications',
  filters: [{ key: 'cert_type', label: 'Type', options: ['ORGANIC', 'NON_GMO', 'SPECIALTY'] }],
  columns: [
    { label: 'Code', render: (row) => el('span', { class: 'mono', text: row.cert_code }) },
    { label: 'Type', render: (row) => titleCase(row.cert_type) },
    { label: 'Standard', key: 'standard' },
    { label: 'Scope', key: 'scope' },
    { label: 'Valid to', render: (row) => fmtDate(row.valid_to) },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Status', render: (row, { reload }) => revokeButton(row, reload) },
  ],
  emptyTitle: 'No certifications issued',
  emptyMessage: 'A certifier can issue an organic, non-GMO or specialty certification.',
});
