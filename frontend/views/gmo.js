import { el, api, badge, field, fmtDate, can, toast } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function registerForm(reload) {
  const fields = {
    event_code: el('input', { required: 'required',
      placeholder: 'ABS-01234-5 (OECD unique identifier format)' }),
    crop_type: el('input', { required: 'required', value: 'Maize' }),
    trait: el('input', { required: 'required', value: 'Drought tolerance' }),
    donor_organism: el('input', { required: 'required', value: 'Bacillus subtilis' }),
    developer: el('input', { required: 'required' }),
    screening_id: el('input', { required: 'required',
      placeholder: 'id of an APPROVED_AUTO or APPROVED_BY_REVIEW screening' }),
  };
  const message = el('div', { class: 'error-text', role: 'alert' });
  const submit = el('button', { class: 'primary', type: 'submit', text: 'Register event' });
  const form = el('form', { class: 'u-hidden' }, [
    el('p', { class: 'hint', text: 'Registration is gated on a passing biosecurity screening — '
      + 'find a screening id under Biosecurity → Sequence Screening.' }),
    el('div', { class: 'grid cols-2' }, Object.entries(fields).map(([key, input]) =>
      field(key.replace(/_/g, ' '), input))),
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
  actions: can('gmo:write') ? ({ reload }) => registerForm(reload) : null,
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
