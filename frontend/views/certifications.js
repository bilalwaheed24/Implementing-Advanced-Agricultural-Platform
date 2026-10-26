import { el, api, badge, fmtDay, toast, can, humanize, orgTypeLabel } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, choiceSelect, dateInput, todayIso, atNoon }
  from '/static/views/formkit.js';

// Labelled with humanize, as the Type column and filter are.
const CERT_TYPES = ['ORGANIC', 'NON_GMO', 'SPECIALTY'].map((code) => [code, humanize(code)]);

/* A suggested scope for the certificate type and the kind of organisation certified: a
 * non-GMO certificate for a processor is not "whole-farm crop production". The certifier
 * can overwrite it; a scope they typed is never replaced. */
const SUGGESTED_SCOPES = {
  FARM: { ORGANIC: 'Whole-farm organic crop production',
    NON_GMO: 'Non-GMO crop production and on-farm segregation',
    SPECIALTY: 'Specialty crop production' },
  SUPPLY: { ORGANIC: 'Organic handling, processing and distribution',
    NON_GMO: 'Non-GMO handling, segregation and identity preservation',
    SPECIALTY: 'Specialty product handling and distribution' },
  BIOTECH: { ORGANIC: 'Organic seed production',
    NON_GMO: 'Non-GMO seed and breeding lines',
    SPECIALTY: 'Specialty seed and breeding lines' },
};
function suggestedScope(certType, orgType) {
  const byType = SUGGESTED_SCOPES[orgType] || {};
  return byType[certType] || `${humanize(certType)} production and handling`;
}

function issueForm(reload) {
  const certCode = el('input', { required: 'required', minlength: '3', maxlength: '60',
    placeholder: 'your own certificate code, e.g. ORG-2026-0012' });
  const certType = choiceSelect(CERT_TYPES);
  // A suggested standard per certificate type, US first; the certifier can overwrite it.
  const SUGGESTED = { ORGANIC: 'USDA-NOP 7 CFR 205', NON_GMO: 'Non-GMO Project Standard',
    SPECIALTY: '' };
  const standard = el('input', { required: 'required', minlength: '2', maxlength: '80',
    placeholder: 'e.g. USDA-NOP 7 CFR 205, EU 2018/848', value: SUGGESTED[certType.value] || '' });
  certType.addEventListener('change', () => {
    if (!standard.value || Object.values(SUGGESTED).includes(standard.value)) {
      standard.value = SUGGESTED[certType.value] || '';
    }
  });
  // Fed by the eligible-subjects endpoint, which excludes the certifier's own organisation,
  // so self-certification is not offerable in the UI and is refused by the API (audit P0-3).
  const subject = remoteSelect({
    endpoint: '/supply-chain/certifications/eligible-subjects',
    label: (row) => `${row.name} — ${orgTypeLabel(row.org_type)}, ${row.country}`,
    placeholder: 'Select the organisation being certified',
    emptyLabel: 'No other organisation is available to certify',
  });
  const scope = el('input', { required: 'required', minlength: '3', maxlength: '255',
    value: suggestedScope(certType.value, 'FARM') });
  // Re-suggested whenever the type or subject changes, unless the certifier has edited it.
  let subjects = [];
  subject.whenReady.then((rows) => { subjects = rows || []; });
  const allSuggestions = () => new Set(Object.values(SUGGESTED_SCOPES)
    .flatMap((byType) => Object.values(byType))
    .concat(CERT_TYPES.map(([code]) => suggestedScope(code, null))));
  const resuggest = () => {
    if (scope.value && !allSuggestions().has(scope.value)) return;
    const chosen = subjects.find((row) => row.id === subject.value);
    scope.value = suggestedScope(certType.value, chosen ? chosen.org_type : 'FARM');
  };
  certType.addEventListener('change', resuggest);
  subject.addEventListener('change', resuggest);
  const today = todayIso();
  const nextYear = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const validFrom = dateInput(today, { required: 'required' });
  const validTo = dateInput(nextYear, { required: 'required' });

  return createPanel({
    toggleLabel: 'Issue a certification',
    submitLabel: 'Issue certification',
    hint: 'A certifier may only certify another organisation. Your own organisation is not '
      + 'listed, and the API refuses a self-issued certificate.',
    controls: [
      ['Certificate code', certCode],
      ['Type', certType],
      ['Standard', standard],
      ['Subject organisation', subject],
      ['Scope', scope],
      ['Valid from', validFrom],
      ['Valid to', validTo],
    ],
    submit: async () => {
      const created = await api('/supply-chain/certifications', { method: 'POST', body: {
        cert_code: certCode.value, cert_type: certType.value, standard: standard.value,
        subject_org_id: subject.value, scope: scope.value,
        valid_from: atNoon(validFrom.value), valid_to: atNoon(validTo.value),
      } });
      return `Certification ${created.cert_code} issued`;
    },
    onDone: reload,
  });
}

function revokeButton(row, reload) {
  // Status is its own column; this one carries only the action, so a reader is not parsing a
  // state and a control out of the same cell.
  if (row.status !== 'ACTIVE' || !can('cert:revoke')) return '—';
  return el('div', { class: 'row' }, [
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

/* The batches a certificate is claimed on. A batch the reader cannot open (the issuer is not
 * a party to it) comes back without an id and is listed by code only. */
function claimedCell(row) {
  const batches = row.claimed_batches || [];
  if (!batches.length) return el('span', { class: 'hint', text: 'Not claimed' });
  return el('div', {}, batches.map((b) => el('div', {}, [b.id
    ? el('a', { class: 'mono', href: `#/batch/${b.id}`, text: b.batch_code })
    : el('span', { class: 'mono', text: b.batch_code })])));
}

// EXPIRED is reported by the API once valid_to has passed, even before the expiry sweep runs.
const statusBadge = (status) => badge(status, status === 'EXPIRED' ? 'warning' : 'neutral');

// A function, not a constant, so the columns follow the permissions of the session that is
// rendering rather than those held when the module was first imported.
export function render(context) {
  return listView({
    title: 'Certifications',
    subtitle: 'Organic, non-GMO and specialty claims. Issuance and revocation are anchored, '
      + 'so a revoked certificate cannot later be presented as valid.',
    endpoint: '/supply-chain/certifications',
    actions: ({ reload }) => (can('cert:issue') ? issueForm(reload) : null),
    // The dashboard's certifier tiles open this list with these filters set, so each list
    // shows what its tile counts (the server applies the tile's rules).
    filters: [
      { key: 'cert_type', label: 'Type', options: ['ORGANIC', 'NON_GMO', 'SPECIALTY'] },
      { key: 'status', label: 'Status', options: ['ACTIVE', 'EXPIRED', 'REVOKED'] },
      { key: 'expiring_within_days', label: 'Expiring', allLabel: 'Any time',
        options: [['30', 'Within 30 days'], ['90', 'Within 90 days']] },
      { key: 'claimed', label: 'Claimed', allLabel: 'Any',
        options: [['true', 'Claimed on a batch'], ['false', 'Not claimed']] },
      can('cert:issue') ? { key: 'issued_by_me', label: 'Issuer', allLabel: 'Any issuer',
        options: [['true', 'Issued by my organisation']] } : null,
    ].filter(Boolean),
    emptyFor: (active) => {
      if (active.expiring_within_days) {
        return { title: 'Nothing expiring soon', message: 'No valid certificate ends within '
          + `${active.expiring_within_days} days.` };
      }
      if (active.claimed === 'true') {
        return { title: 'Not claimed on any batch',
          message: 'No batch cites one of these certificates yet.' };
      }
      return null;
    },
    columns: [
      { label: 'Code', render: (row) => el('span', { class: 'mono', text: row.cert_code }) },
      { label: 'Type', render: (row) => humanize(row.cert_type) },
      { label: 'Standard', key: 'standard' },
      { label: 'Subject', render: (row) => row.subject_org_name || '—' },
      { label: 'Scope', key: 'scope' },
      { label: 'Claimed on', render: (row) => claimedCell(row) },
      // A validity end is a day, not an instant.
      { label: 'Valid to', render: (row) => fmtDay(row.valid_to) },
      { label: 'Anchor', render: (row) => badge(row.anchor_status) },
      { label: 'Status', render: (row) => statusBadge(row.status) },
      // Only roles that can revoke get the column; for others it would be a column of dashes.
      can('cert:revoke')
        ? { label: 'Action', render: (row, { reload }) => revokeButton(row, reload) } : null,
    ].filter(Boolean),
    emptyTitle: 'No certifications issued',
    emptyMessage: 'A certifier can issue an organic, non-GMO or specialty certification.',
  })(context);
}
