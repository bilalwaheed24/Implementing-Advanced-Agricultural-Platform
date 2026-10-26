import { el, api, badge, field, fmtDate, fmtPct, jurisdictionLabel, toast, can,
         reasonList, humanize } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { remoteSelect } from '/static/views/formkit.js';

function evaluateForm(reload) {
  // Chosen from the batches this role can see, so no raw identifier is typed.
  const batchId = remoteSelect({
    endpoint: '/supply-chain/batches',
    label: (row) => {
      const origin = [row.origin_region, row.origin_country].filter(Boolean).join(', ');
      return `${row.batch_code}${origin ? ` — ${origin}` : ''}`
        + ` (${humanize(row.state).toLowerCase()})`;
    },
    placeholder: 'Select a batch',
    emptyLabel: 'No batch is visible to your role',
    requires: 'supply:read',
  });
  const jurisdiction = el('select', {}, ['US-USDA', 'US-FDA', 'EU', 'CODEX', 'GS1']
    .map((v) => el('option', { value: v, text: jurisdictionLabel(v) })));
  const message = el('div', { class: 'error-text', role: 'alert' });
  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-2' }, [
      field('Batch', batchId),
      field('Rule set', jurisdiction),
    ]),
    message,
    el('button', { class: 'primary', type: 'submit', text: 'Evaluate' }),
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    try {
      const report = await api('/compliance/evaluate', { method: 'POST', body: {
        subject_type: 'BATCH', subject_id: batchId.value,
        jurisdiction: jurisdiction.value } });
      toast(`Report: ${humanize(report.status).toLowerCase()}`,
        report.status === 'COMPLIANT' ? 'ok' : 'error');
      form.classList.add('u-hidden');
      reload();
    } catch (error) { message.textContent = error.message; }
  });
  const toggle = el('button', { class: 'primary', text: 'Evaluate a batch', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

/* Release check (labelling + live GMO approval) for a batch the caller holds. Releasing is
 * the holder's act, so the API requires supply:write and current custody. */
function releaseForm() {
  const batchId = remoteSelect({
    endpoint: '/supply-chain/batches',
    label: (row) => `${row.batch_code} — ${humanize(row.state).toLowerCase()}`,
    placeholder: 'Select a batch you hold',
    emptyLabel: 'No batch is visible to your role',
    requires: 'supply:read',
  });
  const jurisdiction = el('select', {}, ['US-USDA', 'US-FDA', 'EU', 'CODEX']
    .map((v) => el('option', { value: v, text: jurisdictionLabel(v) })));
  const message = el('div', { class: 'error-text', role: 'alert' });
  const result = el('div');
  const form = el('form', { class: 'u-hidden' }, [
    el('p', { class: 'hint', text: 'Checks GMO labelling and that the lineage event holds a '
      + 'live approval in the destination. A failed check is recorded and alerts the batch '
      + 'owner and holder.' }),
    el('div', { class: 'grid cols-2' }, [
      field('Batch', batchId),
      field('Destination', jurisdiction),
    ]),
    message, result,
    el('button', { class: 'primary', type: 'submit', text: 'Check release' }),
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    result.replaceChildren();
    try {
      const check = await api(`/gmo/labelling/${batchId.value}/check-release`
        + `?jurisdiction=${encodeURIComponent(jurisdiction.value)}`, { method: 'POST' });
      toast(check.compliant ? 'Release permitted' : 'Release blocked',
        check.compliant ? 'ok' : 'error');
      result.replaceChildren(el('div', { class: 'u-mt-12' }, [
        badge(check.compliant ? 'COMPLIANT' : 'NON_COMPLIANT'),
        check.required_label_text
          ? el('p', { class: 'hint', text: `Label required: "${check.required_label_text}"` })
          : null,
        reasonList((check.findings || []).map((f) => ({ rule: f.rule, detail: f.detail }))),
      ]));
    } catch (error) { message.textContent = error.message; }
  });
  const toggle = el('button', { text: 'Check a release', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

/* Pass rate as a percentage everywhere, with the counts behind it. An environmental-impact
 * assessment records findings rather than pass/fail rules, so it has no rate. */
function passRate(row) {
  const total = row.summary?.rules_evaluated;
  if (total === undefined || total === null) return '—';
  const passed = row.summary?.passed;
  if (passed === undefined || passed === null) {
    return el('span', { class: 'hint', text: `${total} finding${total === 1 ? '' : 's'}` });
  }
  const rate = total ? passed / total : 0;
  return el('span', { title: `${passed} of ${total} rules passed` },
    [`${fmtPct(rate, 0)} `, el('span', { class: 'hint', text: `(${passed}/${total})` })]);
}

function subjectCell(row) {
  if (row.subject_type === 'BATCH') {
    const code = row.summary?.batch_code || String(row.subject_id).slice(0, 8);
    // A batch the reader can no longer open (e.g. handed on since) is shown as its code only.
    if (row.subject_readable === false) return el('span', { class: 'mono', text: code });
    return el('a', { class: 'mono', href: `#/batch/${row.subject_id}`, text: code });
  }
  return el('span', { class: 'mono', text: row.summary?.event_code || '—' });
}

export function render(context) {
  return listView({
    title: 'Regulatory compliance',
    subtitle: 'Rules modelled on published USDA, FDA, EU, Codex Alimentarius and GS1 '
      + 'requirements — an engineering control, not legal advice.',
    endpoint: '/compliance/reports',
    // Client-side: the report list endpoint has no text search parameter.
    // The jurisdiction (code and label) and status are searched too, so "EU" or "compliant"
    // finds the reports the table shows under those words.
    search: { placeholder: 'Batch, GMO event, jurisdiction or status',
      fields: (row) => [row.summary?.batch_code, row.summary?.event_code, row.jurisdiction,
        row.jurisdiction ? jurisdictionLabel(row.jurisdiction) : '', row.status,
        row.status ? humanize(row.status) : ''].filter(Boolean).join(' ') },
    filters: [
      { key: 'jurisdiction', label: 'Jurisdiction', optionLabel: jurisdictionLabel,
        options: ['US-USDA', 'US-FDA', 'EU', 'CODEX', 'GS1'] },
      { key: 'report_type', label: 'Type', options: ['COMPLIANCE', 'ENVIRONMENTAL_IMPACT'] },
    ],
    actions: ({ reload }) => {
      const panels = [
        can('compliance:run') ? evaluateForm(reload) : null,
        can('supply:write') ? releaseForm() : null,
      ].filter(Boolean);
      return panels.length ? el('div', { class: 'row u-toolbar' }, panels) : null;
    },
    columns: [
      { label: 'Generated', render: (row) => fmtDate(row.created_at) },
      { label: 'Type', render: (row) => humanize(row.report_type) },
      { label: 'Batch / event', render: (row) => subjectCell(row) },
      { label: 'Jurisdiction', render: (row) => jurisdictionLabel(row.jurisdiction) },
      { label: 'Status', render: (row) => badge(row.status) },
      { label: 'Pass rate', numeric: true, render: (row) => passRate(row) },
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
