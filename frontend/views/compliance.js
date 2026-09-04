import { el, api, badge, field, fmtDate, table, empty, toast, can, reasonList, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function evaluateForm(reload) {
  const batchId = el('input', { required: 'required', placeholder: 'Batch id' });
  const jurisdiction = el('select', {}, ['US-USDA', 'US-FDA', 'EU', 'CODEX', 'GS1']
    .map((v) => el('option', { value: v, text: v })));
  const message = el('div', { class: 'error-text', role: 'alert' });
  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-2' }, [
      field('Batch id', batchId),
      field('Jurisdiction', jurisdiction),
    ]),
    message,
    el('button', { class: 'primary', type: 'submit', text: 'Evaluate' }),
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    try {
      const report = await api('/compliance/evaluate', { method: 'POST', body: {
        subject_type: 'BATCH', subject_id: batchId.value.trim(),
        jurisdiction: jurisdiction.value } });
      toast(`Report ${report.status}`, report.status === 'COMPLIANT' ? 'ok' : 'error');
      form.classList.add('u-hidden');
      reload();
    } catch (error) { message.textContent = error.message; }
  });
  const toggle = el('button', { class: 'primary', text: 'Evaluate a batch', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

export function render(context) {
  return listView({
    title: 'Regulatory compliance',
    subtitle: 'Rules modelled on published USDA, FDA, EU, Codex Alimentarius and GS1 '
      + 'requirements — an engineering control, not legal advice.',
    endpoint: '/compliance/reports',
    filters: [
      { key: 'jurisdiction', label: 'Jurisdiction',
        options: ['US-USDA', 'US-FDA', 'EU', 'CODEX', 'GS1'] },
      { key: 'report_type', label: 'Type', options: ['COMPLIANCE', 'ENVIRONMENTAL_IMPACT'] },
    ],
    actions: can('compliance:run') ? ({ reload }) => evaluateForm(reload) : null,
    columns: [
      { label: 'Generated', render: (row) => fmtDate(row.created_at) },
      { label: 'Type', render: (row) => titleCase(row.report_type) },
      { label: 'Jurisdiction', key: 'jurisdiction' },
      { label: 'Status', render: (row) => badge(row.status) },
      { label: 'Pass rate', numeric: true, render: (row) =>
        `${row.summary?.passed ?? '—'}/${row.summary?.rules_evaluated ?? '—'}` },
      { label: 'Anchor', render: (row) => badge(row.anchor_status) },
      { label: 'Detail', render: (row) => el('details', {}, [
        el('summary', { class: 'hint', text: 'Rule results' }),
        row.results?.length ? reasonList(row.results.map((result) => ({
          rule: result.rule_id, detail: `${result.title}: ${result.detail}` })))
          : el('p', { class: 'hint', text: 'No rules recorded.' }),
      ]) },
    ],
    emptyTitle: 'No compliance reports',
    emptyMessage: 'Evaluate a batch to produce a report with citable rule results.',
  })(context);
}
