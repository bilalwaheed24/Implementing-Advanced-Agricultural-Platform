import { el, api, badge, field, fmtDate, fmtPct, titleCase, toast, can } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function submitForm(reload) {
  const name = el('input', { required: 'required', maxlength: '200',
    value: 'Candidate insert' });
  const intent = el('input', { required: 'required', maxlength: '80',
    value: 'drought tolerance improvement' });
  const organism = el('input', { maxlength: '160', value: 'Zea mays' });
  const sequence = el('textarea', { required: 'required', minlength: '11',
    placeholder: 'Paste a nucleotide sequence or FASTA record (A/C/G/T/U, up to 100 kb)' });
  const message = el('div', { class: 'error-text', role: 'alert' });
  const submit = el('button', { class: 'primary', type: 'submit', text: 'Screen sequence' });

  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-3' }, [
      field('Name', name),
      field('Stated intent', intent,
        el('div', { class: 'hint', text: 'Intent feeds the dual-use concern matrix.' })),
      field('Organism', organism),
    ]),
    field('Sequence', sequence),
    message,
    el('div', { class: 'row' }, [submit,
      el('button', { type: 'button', text: 'Insert a random benign sequence', onClick: () => {
        const bases = 'ACGT';
        let out = '';
        for (let i = 0; i < 1200; i += 1) {
          out += bases[Math.floor(Math.random() * 4)];
        }
        sequence.value = out;
      } })]),
  ]);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    submit.disabled = true;
    submit.textContent = 'Screening…';
    try {
      const result = await api('/biosecurity/screenings', { method: 'POST', body: {
        name: name.value, sequence: sequence.value, intent: intent.value,
        organism: organism.value || null,
      } });
      toast(`Verdict ${result.verdict} — status ${result.status}`,
        result.verdict === 'CLEAR' ? 'ok' : 'error');
      window.location.hash = `#/screening/${result.id}`;
    } catch (error) {
      message.textContent = error.message;
    } finally {
      submit.disabled = false;
      submit.textContent = 'Screen sequence';
    }
  });

  const toggle = el('button', { class: 'primary', text: 'New screening', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', { class: 'u-flex-1' }, [toggle, form]);
}

export const render = listView({
  title: 'Biosecurity sequence screening',
  subtitle: 'k-mer seeding with Smith–Waterman local alignment against a curated hazard '
    + 'database. Detects diverged homology, not just exact matches. Hazard sequences '
    + 'shipped here are synthetic motifs.',
  endpoint: '/biosecurity/screenings',
  filters: [
    { key: 'verdict', label: 'Verdict', options: ['CLEAR', 'FLAG', 'BLOCK'] },
    { key: 'status', label: 'Status', options: ['APPROVED_AUTO', 'PENDING_REVIEW', 'BLOCKED',
      'APPROVED_BY_REVIEW', 'REJECTED'] },
  ],
  actions: can('biosecurity:submit') ? ({ reload }) => submitForm(reload) : null,
  columns: [
    { label: 'Submitted', render: (row) => fmtDate(row.created_at) },
    { label: 'Name', render: (row) => el('a', { href: `#/screening/${row.id}`, text: row.name }) },
    { label: 'Intent', key: 'intent' },
    { label: 'Verdict', render: (row) => badge(row.verdict) },
    { label: 'Max identity', numeric: true, render: (row) => fmtPct(row.max_identity, 1) },
    { label: 'Hazard classes', render: (row) => (row.hazard_classes || []).length
      ? el('span', { class: 'hint',
        text: row.hazard_classes.map(titleCase).join(', ') }) : '—' },
    { label: 'DURC', render: (row) => row.durc_flag ? badge('CRITICAL') : '—' },
    { label: 'Status', render: (row) => badge(row.status) },
  ],
  emptyTitle: 'No screenings submitted',
  emptyMessage: 'Submit a sequence to have it screened against the hazard database.',
});
