import { el, api, badge, fmtDate, barChart, severityColour, table, empty,
         titleCase } from '/static/assets/core.js';

export async function render() {
  const [summary, analyses, cards] = await Promise.all([
    api('/ai/summary'), api('/ai/analyses?page_size=20'), api('/ai/model-cards'),
  ]);

  const totals = {};
  for (const [type, byLevel] of Object.entries(summary.by_type_and_level || {})) {
    totals[type] = Object.values(byLevel).reduce((a, b) => a + b, 0);
  }

  const cardEntries = Object.entries(cards).filter(([key]) => key !== 'marking');

  return el('div', {}, [
    el('h1', { text: 'AI insights' }),
    el('p', { class: 'subtitle', text: cards.marking }),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Analyses by type' }),
      Object.keys(totals).length
        ? barChart(Object.entries(totals).map(([label, value]) => ({ label: titleCase(label), value })),
          { label: 'Analyses by type' })
        : empty('No analyses yet', 'Run telemetry, screening or vision requests to populate this.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Recent analyses' }),
      table([
        { label: 'When', render: (row) => fmtDate(row.created_at) },
        { label: 'Type', render: (row) => titleCase(row.analysis_type) },
        { label: 'Subject', render: (row) => `${row.subject_type} ${row.subject_id.slice(0, 8)}` },
        { label: 'Score', numeric: true, key: 'score' },
        { label: 'Level', render: (row) => badge(row.level) },
        { label: 'Degraded', render: (row) => row.degraded ? badge('WARNING') : '—' },
      ], analyses.items),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Model cards' }),
      el('div', { class: 'grid cols-3' }, cardEntries.map(([name, card]) => el('div', { class: 'tile' }, [
        el('div', { class: 'label', text: titleCase(name) }),
        el('div', { class: 'hint', text: card.model || card.status || 'unavailable' }),
        card.purpose ? el('div', { class: 'hint', text: card.purpose }) : null,
      ]))),
    ]),
  ]);
}
