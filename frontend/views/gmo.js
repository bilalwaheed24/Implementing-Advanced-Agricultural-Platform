import { el, api, badge, field, fmtDate, can, toast } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, choiceSelect } from '/static/views/formkit.js';

const JURISDICTIONS = [
  ['EU', 'European Union'],
  ['US', 'United States'],
  ['BR', 'Brazil'],
  ['CA', 'Canada'],
  ['JP', 'Japan'],
];

const DECISIONS = [
  ['APPROVED', 'Approve — cleared for this jurisdiction'],
  ['REJECTED', 'Reject — not cleared'],
  ['PENDING', 'Pending — under assessment'],
];

/* The regulator's one regulated write. Both the event and the decision are chosen from
 * controlled inputs, so no raw identifier is typed (audit §C, P3 §6). */
function approvalForm(reload) {
  const event = remoteSelect({
    endpoint: '/gmo/events',
    label: (row) => `${row.event_code} — ${row.crop_type}, ${row.trait} (${row.developer})`,
    placeholder: 'Select a registered GMO event',
    emptyLabel: 'No GMO event has been registered yet',
  });
  const jurisdiction = choiceSelect(JURISDICTIONS);
  const decision = choiceSelect(DECISIONS);
  const reference = el('input', { maxlength: '120',
    placeholder: 'your decision reference, e.g. EFSA-GMO-2026-004' });
  const decided = el('div', { class: 'hint' });

  // Show what is already on record for the chosen event, so a decision is never taken blind.
  event.addEventListener('change', async () => {
    decided.textContent = '';
    if (!event.value) return;
    try {
      const approvals = await api(`/gmo/events/${event.value}/approvals`);
      decided.textContent = approvals.length
        ? `On record: ${approvals.map((a) => `${a.jurisdiction} ${a.status}`).join(', ')}`
        : 'No jurisdictional decision recorded yet.';
    } catch { decided.textContent = ''; }
  });

  return createPanel({
    toggleLabel: 'Record a jurisdictional decision',
    submitLabel: 'Record decision',
    hint: 'A granted approval may later be withdrawn by rejecting it; a rejected one must be '
      + 'resubmitted as pending rather than flipped straight back to approved.',
    controls: [
      ['GMO event', event, decided],
      ['Jurisdiction', jurisdiction],
      ['Decision', decision],
      ['Reference', reference],
    ],
    submit: async () => {
      await api(`/gmo/events/${event.value}/approvals`, { method: 'POST', body: {
        jurisdiction: jurisdiction.value, status: decision.value,
        reference: reference.value || null,
      } });
      return `Decision recorded: ${jurisdiction.value} ${decision.value}`;
    },
    onDone: reload,
  });
}

// Readable labels; the field name is not a label ("screening id").
const FIELD_LABELS = {
  event_code: 'Event code (OECD identifier)',
  crop_type: 'Crop type',
  trait: 'Trait',
  donor_organism: 'Donor organism',
  developer: 'Developer',
  screening_id: 'Biosecurity screening',
};

function registerForm(reload) {
  const fields = {
    event_code: el('input', { required: 'required',
      placeholder: 'ABS-01234-5 (OECD unique identifier format)' }),
    crop_type: el('input', { required: 'required', value: 'Maize' }),
    trait: el('input', { required: 'required', value: 'Drought tolerance' }),
    donor_organism: el('input', { required: 'required', value: 'Bacillus subtilis' }),
    developer: el('input', { required: 'required' }),
    // Only screenings that actually passed are offered, with a readable label, so the
    // operator never pastes an identifier (audit P3 §6).
    screening_id: remoteSelect({
      endpoint: '/biosecurity/screenings', requires: 'biosecurity:read',
      filter: (row) => ['APPROVED_AUTO', 'APPROVED_BY_REVIEW'].includes(row.status),
      label: (row) => `${row.name} — ${row.verdict.toLowerCase()}`
        + `${row.organism ? `, ${row.organism}` : ''}`,
      placeholder: 'Select a passing screening',
      emptyLabel: 'No passing screening — submit and clear one first',
    }),
  };
  const message = el('div', { class: 'error-text', role: 'alert' });
  const submit = el('button', { class: 'primary', type: 'submit', text: 'Register event' });
  const form = el('form', { class: 'u-hidden' }, [
    el('p', { class: 'hint', text: 'Registration is gated on a passing biosecurity screening. '
      + 'Only screenings that cleared review are listed.' }),
    el('div', { class: 'grid cols-2' }, Object.entries(fields).map(([key, input]) =>
      field(FIELD_LABELS[key] || key.replace(/_/g, ' '), input))),
    message, submit,
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    try {
      const event_ = await api('/gmo/events', { method: 'POST', body: Object.fromEntries(
        Object.entries(fields).map(([key, input]) => [key, input.value])) });
      toast(`Event ${event_.event_code} anchored in block ${event_.block_number}`, 'ok');
      form.classList.add('u-hidden');
      reload();
    } catch (error) { message.textContent = error.message; }
  });
  const toggle = el('button', { class: 'primary', text: 'Register GMO event', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

export const render = listView({
  title: 'GMO transformation event registry',
  subtitle: 'Every event is anchored to the permissioned ledger with a SHA-256 content hash, '
    + 'endorsed by the biotech developer and the regulator.',
  endpoint: '/gmo/events',
  actions: ({ reload }) => {
    const panels = [
      can('gmo:write') ? registerForm(reload) : null,
      can('gmo:approve') ? approvalForm(reload) : null,
    ].filter(Boolean);
    return panels.length ? el('div', { class: 'row u-toolbar' }, panels) : null;
  },
  columns: [
    { label: 'Registered', render: (row) => fmtDate(row.created_at) },
    { label: 'Event code', render: (row) => el('span', { class: 'mono', text: row.event_code }) },
    { label: 'Crop', key: 'crop_type' },
    { label: 'Trait', key: 'trait' },
    { label: 'Developer', key: 'developer' },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Ledger', render: (row) => row.tx_id
      ? el('a', { href: `#/blockchain?tx=${row.tx_id}`, class: 'mono',
        text: row.tx_id.slice(0, 12) }) : '—' },
  ],
  emptyTitle: 'No GMO events registered',
  emptyMessage: 'Screen a sequence first, then register the event against that screening.',
});
