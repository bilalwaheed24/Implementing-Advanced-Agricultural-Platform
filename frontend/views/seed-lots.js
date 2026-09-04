import { el, badge, fmtDate, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Seed lots',
  subtitle: 'Seed production tied to a registered GMO event, anchored to the ledger.',
  endpoint: '/gmo/seed-lots',
  columns: [
    { label: 'Lot code', render: (row) => el('span', { class: 'mono', text: row.lot_code }) },
    { label: 'Crop', key: 'crop_type' },
    { label: 'Variety', key: 'variety' },
    { label: 'Quantity (kg)', numeric: true, render: (row) => fmtNum(row.quantity_kg, 0) },
    { label: 'Germination', numeric: true, render: (row) =>
      row.germination_pct === null ? '—' : `${fmtNum(row.germination_pct, 1)}%` },
    { label: 'Produced', render: (row) => fmtDate(row.produced_at) },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
  ],
  emptyTitle: 'No seed lots',
  emptyMessage: 'Create a seed lot from the GMO event detail once an event is registered.',
});
