import { el, api, badge, can, fmtDate, fmtNum, toast, session, orgDirectory, orgName }
  from '/static/assets/core.js';
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

/* Row action: the holder of a lot supplies it to a farm, which can then plant from it. */
function supplyControl(row, reload) {
  const holder = row.custodian_org_id || row.org_id;
  if (!can('gmo:write') || holder !== session.read()?.org_id) return orgName(holder);
  const farms = el('select', { 'aria-label': `Farm to supply ${row.lot_code} to` },
    [el('option', { value: '', text: 'Supply to farm…' })]);
  orgDirectory().then((rows) => {
    for (const org of rows.filter((o) => o.org_type === 'FARM')) {
      farms.appendChild(el('option', { value: org.id, text: org.name }));
    }
  });
  const send = el('button', { text: 'Supply', onClick: async () => {
    if (!farms.value) { toast('Choose the farm to supply first', 'error'); return; }
    send.disabled = true;
    try {
      await api(`/gmo/seed-lots/${row.id}/transfer`, { method: 'POST',
        body: { to_org_id: farms.value } });
      toast(`Seed lot ${row.lot_code} supplied — the farm has been notified`, 'ok');
      reload();
    } catch (error) {
      toast(error.message, 'error');
      send.disabled = false;
    }
  } });
  return el('div', { class: 'row' }, [orgName(holder), farms, send]);
}

export const render = listView({
  title: 'Seed lots',
  subtitle: 'Seed produced from an approved GMO event and anchored to the ledger. The '
    + 'developer supplies a lot to a farm, which can then plant from it.',
  endpoint: '/gmo/seed-lots',
  actions: ({ reload }) => (can('gmo:write') ? createForm(reload) : null),
  columns: [
    { label: 'Lot code', render: (row) => el('span', { class: 'mono', text: row.lot_code }) },
    { label: 'GMO event', render: (row) => (row.gmo_event_code
      ? el('span', { class: 'mono', text: row.gmo_event_code }) : 'Conventional') },
    { label: 'Crop', key: 'crop_type' },
    { label: 'Variety', key: 'variety' },
    { label: 'Quantity (kg)', numeric: true, render: (row) => fmtNum(row.quantity_kg, 0) },
    { label: 'Germination', numeric: true, render: (row) =>
      row.germination_pct === null ? '—' : `${fmtNum(row.germination_pct, 1)}%` },
    { label: 'Produced', render: (row) => fmtDate(row.produced_at) },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Held by', render: (row, { reload }) => supplyControl(row, reload) },
  ],
  emptyTitle: 'No seed lots',
  emptyMessage: can('gmo:write')
    ? 'Create a seed lot from an approved GMO event with the button above.'
    : 'No seed has been supplied to your organisation yet. Seed lots appear here once a '
      + 'biotech developer supplies one to you.',
});
