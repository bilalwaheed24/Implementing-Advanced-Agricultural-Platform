import { el, api, badge, can, fmtDate, fmtNum, fmtPct, barChart, table, empty,
         humanize, termLabel, loadFieldPlaces, fieldPlaceName } from '/static/assets/core.js';

/* Requirement and design-record references ("(FR-A5)", "ADR-012") belong to the project's
 * documents, not to the screen. */
function withoutDocRefs(text) {
  return String(text || '')
    .replace(/\s*\((?:N?FR|ADR)-[A-Z0-9]+(?:\s*,\s*(?:N?FR|ADR)-[A-Z0-9]+)*\)/g, '')
    .replace(/\b(?:N?FR|ADR)-[A-Z0-9]+\b/g, '').trim();
}

/* Every telemetry reading is scored, so most rows are a routine "Info, score 0". Those are
 * hidden by default; the rest are what someone should look at. */
function noteworthy(row) {
  return Number(row.score) > 0 || !['INFO', 'OK', 'LOW', 'HEALTHY'].includes(row.level);
}

/* A subject is linked where the platform has a screen for it. */
function subjectHref(row) {
  switch (row.subject_type) {
    case 'Telemetry': return can('telemetry:read') ? '#/telemetry' : null;
    case 'Field': {
      if (!can('farm:read')) return null;
      const fieldRow = places.fields.get(row.subject_id);
      return fieldRow ? `#/farm/${fieldRow.farm_id}` : '#/farms';
    }
    case 'Device': return can('device:read') ? `#/device/${row.subject_id}` : null;
    case 'Batch': return can('supply:read') ? `#/batch/${row.subject_id}` : null;
    default: return null;
  }
}

function subjectCell(row) {
  // The analysis carries the field name or device class in its evidence; the id is only a
  // secondary handle. No label is invented when the evidence has none.
  const evidence = row.evidence || {};
  // A field is named with its farm: two farms can both have a "Block C".
  const fieldName = row.subject_type === 'Field'
    ? fieldPlaceName(places, row.subject_id, evidence.field) : evidence.field;
  const name = fieldName
    || (evidence.device_type ? `${termLabel(evidence.device_type)} reading` : null)
    || (row.subject_id === 'unassigned' ? 'No field given' : null);
  const text = name || `${humanize(row.subject_type)} ${String(row.subject_id || '').slice(0, 8)}`;
  const href = subjectHref(row);
  return href ? el('a', { href, text }) : el('span', { text });
}

/* Farm and field names, loaded once per render. */
let places = { farms: new Map(), fields: new Map() };

/* The class a crop-vision analysis predicted. Seeded rows keep it in evidence.label with a
 * severity in `level`; rows from the API store the class itself in `level`. Otherwise it is
 * the most probable class. */
const SEVERITY_LEVELS = new Set(['INFO', 'OK', 'LOW', 'WARNING', 'MEDIUM', 'MODERATE', 'HIGH',
  'CRITICAL']);
function predictedClass(row) {
  const evidence = row.evidence || {};
  if (evidence.label) return evidence.label;
  if (row.level && !SEVERITY_LEVELS.has(String(row.level).toUpperCase())) return row.level;
  const probabilities = Object.entries(evidence.probabilities || {});
  if (!probabilities.length) return null;
  return probabilities.sort((a, b) => b[1] - a[1])[0][0];
}

/* What the score means depends on the analysis. For crop vision it is the model's
 * confidence in the class it predicted, not a measure of how bad things are, so it is shown
 * as "99.9% confident: healthy" rather than a bare 0.999 next to an Info badge. */
function scoreCell(row) {
  if (row.analysis_type === 'CROP_VISION') {
    const predicted = predictedClass(row);
    return el('span', { title: 'Model confidence in the predicted class' },
      [`${fmtPct(row.score, 1)} confident`, predicted
        ? el('div', { class: 'hint', text: termLabel(predicted).toLowerCase() }) : null]);
  }
  return fmtNum(row.score, 3);
}

function modelCard([name, card]) {
  const trained = !card.status || card.status !== 'not_trained';
  return el('div', { class: 'tile' }, [
    el('div', { class: 'label', text: humanize(String(name).toUpperCase()) }),
    el('div', { class: 'hint', text: trained ? (card.model || 'Deployed') : 'Not trained yet' }),
    card.purpose ? el('div', { class: 'hint', text: withoutDocRefs(card.purpose) }) : null,
  ]);
}

export async function render() {
  const [summary, analyses, cards, loadedPlaces] = await Promise.all([
    api('/ai/summary'), api('/ai/analyses?page_size=100'), api('/ai/model-cards'),
    loadFieldPlaces(),
  ]);
  places = loadedPlaces;

  const totals = {};
  for (const [type, byLevel] of Object.entries(summary.by_type_and_level || {})) {
    totals[type] = Object.values(byLevel).reduce((a, b) => a + b, 0);
  }

  const cardEntries = Object.entries(cards).filter(([key]) => key !== 'marking');
  const rows = analyses.items || [];
  const columns = [
    { label: 'When', render: (row) => fmtDate(row.created_at) },
    { label: 'Type', render: (row) => humanize(row.analysis_type) },
    { label: 'Subject', render: subjectCell },
    { label: 'Score', numeric: true, render: scoreCell },
    { label: 'Level', render: (row) => badge(row.level) },
    { label: 'Degraded', render: (row) => (row.degraded
      ? el('span', { class: 'badge warning', text: 'Fallback model' }) : '—') },
  ];

  const tableHost = el('div', {});
  const showAll = el('input', { type: 'checkbox', id: 'ai-show-all' });
  const draw = () => {
    const shown = showAll.checked ? rows : rows.filter(noteworthy);
    tableHost.replaceChildren(table(columns, shown, {
      emptyTitle: 'Nothing noteworthy',
      emptyMessage: `None of the ${rows.length} most recent analyses scored above zero. `
        + 'Tick "Show routine results" to see them all.',
    }));
  };
  showAll.addEventListener('change', draw);
  draw();

  return el('div', {}, [
    el('h1', { text: 'AI insights' }),
    el('p', { class: 'subtitle', text: cards.marking }),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Analyses by type' }),
      Object.keys(totals).length
        ? barChart(Object.entries(totals).map(([label, value]) => ({ label: humanize(label), value })),
          { label: 'Analyses by type' })
        : empty('No analyses yet', 'Analyses appear as devices report and screenings run.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Recent analyses' }),
      el('p', { class: 'hint', text: 'Score: for crop vision, the model\'s confidence in the '
        + 'class it predicted (shown beneath it); for telemetry, the anomaly score, from 0 '
        + '(normal) to 1 (most unusual). Level: Info means nothing needs doing '
        + '(a healthy crop, a normal reading); Warning means the predicted class or reading '
        + 'needs a look, however confident the model is.' }),
      el('label', { class: 'row u-fw-400', for: 'ai-show-all' }, [showAll,
        ` Show routine results (score 0) — ${rows.filter((r) => !noteworthy(r)).length} hidden`]),
      tableHost,
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Model cards' }),
      el('div', { class: 'grid cols-3' }, cardEntries.map(modelCard)),
    ]),
  ]);
}
