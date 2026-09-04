import { el, api, badge, fmtDate, fmtPct, table, empty, titleCase } from '/static/assets/core.js';

export async function render() {
  const queue = await api('/biosecurity/screenings/queue');
  const crispr = await api('/biosecurity/crispr?durc_only=true&page_size=25')
    .catch(() => ({ items: [] }));

  return el('div', {}, [
    el('h1', { text: 'Biosafety review queue' }),
    el('p', { class: 'subtitle', text: 'Submissions that the screening engine would not '
      + 'release without human judgement. Nothing here has been approved.' }),
    el('div', { class: 'card' }, [
      el('h2', { text: `Sequence screenings awaiting review (${queue.length})` }),
      queue.length ? table([
        { label: 'Submitted', render: (row) => fmtDate(row.created_at) },
        { label: 'Name', render: (row) => el('a', { href: `#/screening/${row.id}`,
          text: row.name }) },
        { label: 'Intent', key: 'intent' },
        { label: 'Verdict', render: (row) => badge(row.verdict) },
        { label: 'Identity', numeric: true, render: (row) => fmtPct(row.max_identity, 1) },
        { label: 'DURC', render: (row) => row.durc_flag ? badge('CRITICAL') : '—' },
        { label: 'Status', render: (row) => badge(row.status) },
      ], queue) : empty('Queue is empty', 'No screening currently requires review.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: `Gene-edit proposals flagged as dual-use (${crispr.items.length})` }),
      crispr.items.length ? table([
        { label: 'Target gene', key: 'target_gene' },
        { label: 'Organism', key: 'organism' },
        { label: 'Edit type', render: (row) => titleCase(row.edit_type) },
        { label: 'Risk', render: (row) => badge(row.risk_level) },
        { label: 'Score', numeric: true, render: (row) => row.risk_score },
        { label: 'Status', render: (row) => badge(row.status) },
      ], crispr.items) : empty('No dual-use proposals', 'Nothing has been flagged.'),
    ]),
  ]);
}
