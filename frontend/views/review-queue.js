import { el, api, badge, fmtDate, fmtPct, table, empty, humanize } from '/static/assets/core.js';

export async function render() {
  const queue = await api('/biosecurity/screenings/queue');
  // Every gene-edit proposal still awaiting a decision (high or prohibited risk, or dual-use),
  // not every dual-use proposal ever flagged: reviewed ones have left the queue.
  const crispr = await api('/biosecurity/crispr?status=PENDING_REVIEW&page_size=100')
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
        { label: 'Action', render: (row) => el('a', { href: `#/screening/${row.id}`,
          text: 'Review' }) },
      ], queue) : empty('Queue is empty', 'No screening currently requires review.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: `Gene-edit proposals awaiting review (${crispr.items.length})` }),
      crispr.items.length ? table([
        { label: 'Submitted', render: (row) => fmtDate(row.created_at) },
        { label: 'Target gene', key: 'target_gene' },
        { label: 'Organism', key: 'organism' },
        { label: 'Edit type', render: (row) => humanize(row.edit_type) },
        { label: 'Risk', render: (row) => badge(row.risk_level) },
        { label: 'Score', numeric: true, render: (row) => row.risk_score },
        { label: 'DURC', render: (row) => row.durc_flag ? badge('CRITICAL') : '—' },
        { label: 'Status', render: (row) => badge(row.status) },
        // The CRISPR register carries the review control (four-eyes aware); `focus` makes
        // it pick out this proposal and open its review dialog.
        { label: 'Action', render: (row) => el('a', {
          href: `#/crispr?status=PENDING_REVIEW&focus=${encodeURIComponent(row.id)}`,
          text: 'Review' }) },
      ], crispr.items) : empty('No proposals awaiting review',
        'No gene-edit proposal currently requires a decision.'),
    ]),
  ]);
}
