import { el, api, badge, can, fmtDay, fmtNum, orgName, humanize, session }
  from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon } from '/static/views/formkit.js';

function wantedCrop() {
  return new URLSearchParams(window.location.hash.split('?')[1] || '').get('crop');
}

/* Field and farm names, so the crops in the harvest selector can be told apart: four
 * plantings of the same hybrid on the same day otherwise read identically. */
async function cropPlaces() {
  const places = { farms: new Map(), fields: new Map() };
  if (!can('farm:read')) return places;
  const [farms, fields] = await Promise.all([
    api('/farms?page=1&page_size=200').catch(() => ({ items: [] })),
    api('/fields?page=1&page_size=200').catch(() => ({ items: [] })),
  ]);
  for (const row of farms.items || []) places.farms.set(row.id, row.name);
  for (const row of fields.items || []) places.fields.set(row.id, row);
  return places;
}

function cropLabel(row, places = null) {
  const base = `${row.crop_type}${row.variety ? ` ${row.variety}` : ''}`;
  const fieldRow = places?.fields.get(row.field_id);
  const farmName = fieldRow ? places.farms.get(fieldRow.farm_id) : null;
  const where = fieldRow ? ` — ${fieldRow.name}${farmName ? `, ${farmName}` : ''}` : '';
  return `${base}${where} — planted ${fmtDay(row.planted_at)}${row.gmo_event_id ? ' (GMO)' : ''}`;
}

function createForm(reload) {
  const placesReady = cropPlaces();
  const code = el('input', { required: 'required', minlength: '3', maxlength: '60',
    placeholder: 'your own batch code, e.g. MAIZE-2026-014' });
  // Every selector is fed from a tenant-scoped list endpoint, so a foreign batch, farm, seed
  // lot or GMO event is not offered and cannot be named by typing an id (audit P1).
  const product = remoteSelect({
    endpoint: '/supply-chain/products',
    label: (row) => `${row.name} (${row.gtin})`,
    placeholder: 'Select a product', emptyLabel: 'Create a product first',
  });
  // Only batches this organisation holds now (and that are with it, not on the road): the
  // API refuses a parent the caller does not hold, so a batch already handed on, or still
  // in transit to it, would only fail on submit (round 6).
  const me = session.read()?.org_id;
  const parent = remoteSelect({
    endpoint: '/supply-chain/batches', required: false,
    filter: (row) => row.custodian_org_id === me
      && !['RECALLED', 'CONSUMED', 'IN_TRANSIT'].includes(row.state),
    label: (row) => `${row.batch_code} — ${humanize(row.state).toLowerCase()}`,
    placeholder: 'None (this is an origin batch)',
    emptyLabel: 'No batch you hold to derive from',
  });
  // A grower harvesting its own crop: farm, seed lot and GMO event are taken from the
  // planting on the server, so they need not be chosen again below.
  const crop = remoteSelect({
    endpoint: '/crops', required: false, requires: 'farm:read',
    label: (row) => cropLabel(row),
    // A crop already marked harvested (or failed) cannot be harvested into a batch again.
    filter: (row) => !['HARVESTED', 'FAILED'].includes(row.status),
    placeholder: 'Not harvested from one of your crops',
    emptyLabel: 'No crop planted yet',
  });
  const farm = remoteSelect({
    endpoint: '/farms', required: false, requires: 'farm:read',
    label: (row) => `${row.name} — ${row.region}, ${row.country}`,
    placeholder: 'Not from a farm you hold', emptyLabel: 'No farms registered',
  });
  const seedLot = remoteSelect({
    endpoint: '/gmo/seed-lots', required: false, requires: 'gmo:read',
    label: (row) => `${row.lot_code} — ${row.crop_type}${row.variety ? ` ${row.variety}` : ''}`,
    placeholder: 'No seed lot', emptyLabel: 'No seed lots available',
  });
  const gmoEvent = remoteSelect({
    endpoint: '/gmo/events', required: false, requires: 'gmo:read',
    label: (row) => `${row.event_code} — ${row.crop_type}, ${row.trait}`,
    // An empty list here usually means the events belong to the developer, not that none
    // exist: a grower's GMO lineage comes from the planting, not from this selector.
    placeholder: 'Not a GMO batch',
    emptyLabel: 'GMO lineage is taken from the harvested crop',
  });
  Promise.all([crop.whenReady, placesReady]).then(([rows, places]) => {
    const byId = new Map(rows.map((row) => [row.id, row]));
    for (const option of crop.options) {
      const row = byId.get(option.value);
      if (row) option.textContent = cropLabel(row, places);
    }
  });
  // The server takes farm, seed lot and GMO event from the chosen crop and rejects a request
  // naming different ones, so they are cleared and locked while a crop is chosen.
  const lineage = [farm, seedLot, gmoEvent];
  const lockLineage = async () => {
    await Promise.all(lineage.map((select) => select.whenReady));
    for (const select of lineage) {
      if (crop.value) select.value = '';
      // Leave a selector disabled by remoteSelect itself (no options, or not readable).
      const usable = !select.unavailable && select.options.length > 1;
      select.disabled = Boolean(crop.value) || !usable;
    }
  };
  crop.addEventListener('change', lockLineage);
  // Provenance is declared, never defaulted: a prefilled origin or harvest date would be
  // anchored to the ledger as if the operator had stated it.
  const quantity = el('input', { type: 'number', step: 'any', min: '0.01', required: 'required',
    placeholder: 'e.g. 12000' });
  const unit = el('input', { required: 'required', maxlength: '12', value: 'kg' });
  const region = el('input', { maxlength: '120', required: 'required',
    placeholder: 'e.g. Iowa' });
  const country = el('input', { maxlength: '2', minlength: '2', required: 'required',
    placeholder: 'ISO code, e.g. US' });
  const harvested = dateInput(null, { required: 'required', max: todayIso() });

  const panel = createPanel({
    toggleLabel: 'Create a batch',
    submitLabel: 'Create batch',
    hint: 'A batch opens a chain of custody. A grower picks the harvested crop and its farm, '
      + 'seed lot and GMO event are recorded automatically. Lineage selectors only offer '
      + 'records your organisation holds.',
    controls: [
      ['Batch code', code],
      ['Product', product],
      ['Quantity', quantity],
      ['Unit', unit],
      ['Harvested crop', crop],
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
        crop_id: crop.value || null,
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
  // form.reset() after a create clears the crop without a change event; lockLineage awaits
  // before reading, so it sees the reset values.
  panel.querySelector('form')?.addEventListener('reset', lockLineage);
  // Arriving from a farm's "Create harvest batch" link: open the form with that crop chosen.
  const wanted = wantedCrop();
  if (wanted) {
    crop.whenReady.then(() => {
      crop.value = wanted;
      crop.dispatchEvent(new Event('change'));
      panel.querySelector('form')?.classList.remove('u-hidden');
    });
  }
  return panel;
}

export const render = listView({
  title: 'Traceable batches',
  subtitle: 'Each batch carries a chain of custody anchored to the ledger and a public '
    + 'verification code a consumer can scan.',
  endpoint: '/supply-chain/batches',
  actions: ({ reload }) => (can('supply:write') ? createForm(reload) : null),
  // Client-side: the batch list endpoint has no text search parameter.
  search: { placeholder: 'Batch code, product or verification code',
    fields: (row) => `${row.batch_code} ${row.product_name || ''} ${row.verification_code}` },
  filters: [
    { key: 'state', label: 'State', options: ['CREATED', 'HARVESTED', 'PROCESSED', 'PACKAGED',
      'IN_TRANSIT', 'RECEIVED', 'STORED', 'RETAILED', 'RECALLED'] },
    { key: 'integrity', label: 'Integrity', options: ['VERIFIED', 'SUSPECT', 'FAILED',
      'UNVERIFIED'] },
    { key: 'gmo', label: 'GMO lineage', options: [['true', 'GMO lineage'],
      ['false', 'No GMO recorded']] },
    // Batches handed to this organisation that have reached it (not in transit) but have no
    // receiving, storing or processing event from it yet (the dashboard's "Hand-overs to
    // book in" tile). Shipments still on the road are under Shipments, "Coming to us".
    { key: 'awaiting_receipt', label: 'Hand-over', allLabel: 'Any',
      options: [['true', 'With us, not booked in']] },
    // In this organisation's custody now, not still on the road to it (the dashboard's
    // "Batches held" tile links here; the server applies the same rule).
    { key: 'held', label: 'Custody', allLabel: 'Any',
      options: [['true', 'Held by us now']] },
  ],
  emptyFor: (active) => {
    if (active.held) {
      return { title: 'No batch in your custody',
        message: 'Batches your organisation holds now appear here. A batch on its way to you '
          + 'is listed once it has arrived.' };
    }
    if (active.awaiting_receipt) {
      return { title: 'Nothing to book in',
        message: 'Every batch handed to your organisation has been received or stored.' };
    }
    if (active.gmo === 'true') {
      return { title: 'No GMO batches', message: 'No batch you hold has a GMO lineage.' };
    }
    return null;
  },
  columns: [
    { label: 'Batch', render: (row) => el('a', { href: `#/batch/${row.id}`, class: 'mono',
      text: row.batch_code }) },
    { label: 'Product', render: (row) => row.product_name || '—' },
    { label: 'State', render: (row) => badge(row.state) },
    { label: 'Quantity', numeric: true, render: (row) => `${fmtNum(row.quantity, 0)} ${row.unit}` },
    { label: 'Origin', render: (row) => row.origin_region
      ? `${row.origin_region}, ${row.origin_country}` : '—' },
    // A GMO lineage is a fact to disclose, not a fault: a neutral label, not a warning.
    // Lineage, not just a GMO event named on the batch itself: the seed lot or a parent batch
    // can carry it (`gmo_lineage` from the API; gmo_event_id for an older server).
    { label: 'GMO lineage', render: (row) => ((row.gmo_lineage ?? Boolean(row.gmo_event_id))
      ? el('span', { class: 'badge neutral', text: 'GMO' }) : 'None recorded') },
    // A batch handed to this organisation but still on the road is not in its custody yet.
    { label: 'Held by', render: (row) => (row.state === 'IN_TRANSIT'
      && row.custodian_org_id === session.read()?.org_id
      ? el('span', { text: 'In transit to you' }) : orgName(row.custodian_org_id)) },
    { label: 'Anchor', render: (row) => badge(row.anchor_status) },
    { label: 'Integrity', render: (row) => badge(row.integrity_status) },
    { label: 'Verify code', render: (row) => el('a', { href: `/verify.html?code=${row.verification_code}`,
      target: '_blank', rel: 'noopener', class: 'mono', text: row.verification_code }) },
  ],
  emptyTitle: 'No batches',
  emptyMessage: 'Batches you create, or that another organisation hands over to you, appear '
    + 'here.',
});
