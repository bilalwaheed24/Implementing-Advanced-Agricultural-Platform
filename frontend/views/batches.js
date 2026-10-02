import { el, api, badge, can, fmtDate, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon } from '/static/views/formkit.js';

function createForm(reload) {
  const code = el('input', { required: 'required', minlength: '3', maxlength: '60',
    placeholder: 'your own batch code, e.g. MAIZE-2026-014' });
  // Every selector is fed from a tenant-scoped list endpoint, so a foreign batch, farm, seed
  // lot or GMO event is not offered and cannot be named by typing an id (audit P1).
  const product = remoteSelect({
    endpoint: '/supply-chain/products',
    label: (row) => `${row.name} (${row.gtin})`,
    placeholder: 'Select a product', emptyLabel: 'Create a product first',
  });
  const parent = remoteSelect({
    endpoint: '/supply-chain/batches', required: false,
    label: (row) => `${row.batch_code} — ${row.state.toLowerCase()}`,
    placeholder: 'None (this is an origin batch)',
    emptyLabel: 'No existing batch to derive from',
  });
  const farm = remoteSelect({
    endpoint: '/farms', required: false, requires: 'farm:read',
    label: (row) => `${row.name} — ${row.region}, ${row.country}`,
    placeholder: 'Not from a farm you hold', emptyLabel: 'No farms registered',
  });
  const seedLot = remoteSelect({
    endpoint: '/gmo/seed-lots', required: false, requires: 'gmo:read',
    label: (row) => `${row.lot_code} — ${row.crop_type} ${row.variety}`,
    placeholder: 'No seed lot', emptyLabel: 'No seed lots available',
  });
  const gmoEvent = remoteSelect({
    endpoint: '/gmo/events', required: false, requires: 'gmo:read',
    label: (row) => `${row.event_code} — ${row.crop_type}, ${row.trait}`,
    placeholder: 'Not a GMO batch', emptyLabel: 'No GMO events registered',
  });
  const quantity = el('input', { type: 'number', step: 'any', min: '0.01', required: 'required',
    value: '1000' });
  const unit = el('input', { required: 'required', maxlength: '12', value: 'kg' });
  const region = el('input', { maxlength: '120', value: 'Iowa' });
  const country = el('input', { maxlength: '2', minlength: '2', value: 'US' });
  const harvested = dateInput(todayIso());

  return createPanel({
    toggleLabel: 'Create a batch',
    submitLabel: 'Create batch',
    hint: 'A batch opens a chain of custody. Lineage selectors only offer records your '
      + 'organisation holds.',
    controls: [
      ['Batch code', code],
      ['Product', product],
      ['Quantity', quantity],
      ['Unit', unit],
      ['Parent batch', parent],
      ['Farm of origin', farm],
      ['Seed lot', seedLot],
      ['GMO event', gmoEvent],
      ['Origin region', region],
      ['Origin country', country],
      ['Harvested on', harvested],
    ],
    submit: async () => {
      const created = await api('/supply-chain/batches', { method: 'POST', body: {
        batch_code: code.value, product_id: product.value,
        quantity: Number(quantity.value), unit: unit.value,
        parent_batch_id: parent.value || null,
        seed_lot_id: seedLot.value || null,
        farm_id: farm.value || null,
        gmo_event_id: gmoEvent.value || null,
        origin_region: region.value || null,
        origin_country: country.value ? country.value.toUpperCase() : null,
        harvested_at: atNoon(harvested.value),
      } });
      return `Batch ${created.batch_code} created — verification code ${created.verification_code}`;
    },
    onDone: reload,
  });
}

export const render = listView({
  title: 'Traceable batches',
  subtitle: 'Each batch carries a chain of custody anchored to the ledger and a public '
    + 'verification code a consumer can scan.',
  endpoint: '/supply-chain/batches',
  actions: ({ reload }) => (can('supply:write') ? createForm(reload) : null),
  filters: [
    { key: 'state', label: 'State', options: ['CREATED', 'HARVESTED', 'PROCESSED', 'PACKAGED',
      'IN_TRANSIT', 'RECEIVED', 'STORED', 'RETAILED', 'RECALLED'] },
    { key: 'integrity', label: 'Integrity', options: ['VERIFIED', 'SUSPECT', 'FAILED',
      'UNVERIFIED'] },
  ],
  columns: [
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.id}`, class: 'mono',
      text: row.batch_code }) },
    { label: 'State', render: (row) => badge(row.state) },
    { label: 'Quantity', numeric: true, render: (row) => `${fmtNum(row.quantity, 0)} ${row.unit}` },
    { label: 'Origin', render: (row) => row.origin_region
      ? `${row.origin_region}, ${row.origin_country}` : '—' },
    { label: 'GMO lineage', render: (row) => row.gmo_event_id ? badge('GMO') : '—' },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Integrity', render: (row) => badge(row.integrity_status) },
    { label: 'Verify code', render: (row) => el('a', { href: `/verify.html?code=${row.verification_code}`,
      target: '_blank', rel: 'noopener', class: 'mono', text: row.verification_code }) },
  ],
  emptyTitle: 'No batches',
  emptyMessage: 'Create a batch against a product to begin its chain of custody.',
});
