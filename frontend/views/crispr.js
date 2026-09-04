import { el, api, badge, field, fmtDate, toast, can, reasonList, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function assessForm() {
  const fields = {
    target_gene: el('input', { required: 'required', value: 'DREB2A' }),
    organism: el('input', { required: 'required', value: 'Zea mays' }),
    organism_class: el('select', {}, ['CROP', 'MODEL_PLANT', 'PLANT_PATHOGEN', 'INSECT_VECTOR',
      'SOIL_MICROBE'].map((v) => el('option', { value: v, text: titleCase(v) }))),
    guide_rna: el('input', { required: 'required', minlength: '17', maxlength: '25',
      value: 'ACGTACGTACGTACGTACGT' }),
    pam: el('input', { required: 'required', value: 'NGG' }),
    edit_type: el('select', {}, ['KNOCKOUT', 'KNOCK_IN', 'BASE_EDIT', 'PRIME_EDIT',
      'MULTIPLEX'].map((v) => el('option', { value: v, text: titleCase(v) }))),
    intent: el('input', { required: 'required', value: 'drought tolerance improvement' }),
  };
  const reference = el('textarea', { placeholder:
    'Optional reference sequence for the off-target scan (A/C/G/T)' });
  const result = el('div');
  const message = el('div', { class: 'error-text', role: 'alert' });
  const submit = el('button', { class: 'primary', type: 'submit', text: 'Assess risk' });

  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-3' }, Object.entries(fields).map(([key, input]) =>
      field(key.replace(/_/g, ' '), input))),
    field('Reference sequence (optional)', reference),
    message, el('div', { class: 'row' }, [submit]), result,
  ]);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    result.replaceChildren();
    submit.disabled = true;
    try {
      const body = Object.fromEntries(
        Object.entries(fields).map(([key, input]) => [key, input.value]));
      if (reference.value.trim()) body.reference_sequence = reference.value.trim();
      const assessment = await api('/biosecurity/crispr', { method: 'POST', body });
      toast(`Risk ${assessment.risk_level} (${assessment.risk_score})`,
        assessment.risk_level === 'LOW' ? 'ok' : 'error');
      result.replaceChildren(el('div', { class: 'card u-mt-12' }, [
        el('h3', {}, [badge(assessment.risk_level), ` score ${assessment.risk_score}`,
          assessment.durc_flag ? el('span', { class: 'u-ml-8' },
            [badge('CRITICAL')]) : null]),
        el('p', { class: 'hint',
          text: `${assessment.off_target_count} potential off-target site(s) found.` }),
        reasonList(assessment.reasons),
      ]));
    } catch (error) {
      message.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });

  const toggle = el('button', { class: 'primary', text: 'Assess a gene edit', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', { class: 'u-flex-1' }, [toggle, form]);
}

export const render = listView({
  title: 'CRISPR risk and dual-use monitoring',
  subtitle: 'Every score component is returned as a citable reason, because the output can '
    + 'block a research proposal and must withstand challenge.',
  endpoint: '/biosecurity/crispr',
  filters: [{ key: 'risk_level', label: 'Risk level',
    options: ['LOW', 'MODERATE', 'HIGH', 'PROHIBITED'] }],
  actions: can('biosecurity:submit') ? () => assessForm() : null,
  columns: [
    { label: 'Assessed', render: (row) => fmtDate(row.created_at) },
    { label: 'Target gene', key: 'target_gene' },
    { label: 'Organism', key: 'organism' },
    { label: 'Edit type', render: (row) => titleCase(row.edit_type) },
    { label: 'Off-targets', numeric: true, render: (row) => row.off_target_count },
    { label: 'Risk', render: (row) => badge(row.risk_level) },
    { label: 'Score', numeric: true, render: (row) => row.risk_score },
    { label: 'DURC', render: (row) => row.durc_flag ? badge('CRITICAL') : '—' },
    { label: 'Status', render: (row) => badge(row.status) },
  ],
  emptyTitle: 'No assessments yet',
  emptyMessage: 'Assess a gene-edit proposal to see its risk breakdown.',
});
