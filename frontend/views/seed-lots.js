import { el, api, badge, can, fmtDate, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon } from '/static/views/formkit.js';

function createForm(reload) {
  const lotCode = el('input', { required: 'required', minlength: '3', maxlength: '60',
    placeholder: 'your own lot code, e.g. SL-2026-004' });
  // `approved_only` applies the same rule the write endpoint enforces, so the selector can
  // only ever offer lineage a regulator has actually approved (audit P1 §15).
  const event = remoteSelect({
    endpoint: '/gmo/events?approved_only=true', requires: 'gmo:read',
    label: (row) => `${row.event_code} — ${row.crop_type}, ${row.trait}`,
    placeholder: 'Select an approved GMO event',
    emptyLabel: 'No approved GMO event — a regulator must approve one first',
  });
  const cropType = el('input', { required: 'required', minlength: '2', maxlength: '80',
    value: 'Maize' });
  const variety = el('input', { required: 'required', maxlength: '120', value: 'V1' });
  const quantity = el('input', { type: 'number', step: 'any', min: '0.01', required: 'required',
    value: '500' });
  const germination = el('input', { type: 'number', step: 'any', min: '0', max: '100',
    placeholder: 'optional' });
  const produced = dateInput(todayIso(), { required: 'required' });

  return createPanel({
    toggleLabel: 'Create a seed lot',
    submitLabel: 'Create seed lot',
    hint: 'Propagating a GMO event into planting material is a regulated step: only events '
      + 'holding a live jurisdictional approval are listed.',
    controls: [
      ['Lot code', lotCode],
      ['Approved GMO event', event],
      ['Crop type', cropType],
      ['Variety', variety],
      ['Quantity (kg)', quantity],
      ['Germination (%)', germination],
      ['Produced on', produced],
    ],
    submit: async () => {
      const created = await api('/gmo/seed-lots', { method: 'POST', body: {
        lot_code: lotCode.value, gmo_event_id: event.value || null,
        crop_type: cropType.value, variety: variety.value,
        quantity_kg: Number(quantity.value),
        germination_pct: germination.value === '' ? null : Number(germination.value),
        produced_at: atNoon(produced.value),
      } });
      return `Seed lot ${created.lot_code} created`;
    },
    onDone: reload,
  });
}

export const render = listView({
  title: 'Seed lots',
  subtitle: 'Seed production tied to a registered GMO event, anchored to the ledger.',
  endpoint: '/gmo/seed-lots',
  actions: ({ reload }) => (can('gmo:write') ? createForm(reload) : null),
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
