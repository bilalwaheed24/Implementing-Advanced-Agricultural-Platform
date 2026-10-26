import { el, api, badge, can, fmtDate, fmtNum, toast, session, titleCase, humanize,
         orgName , orgTypeLabel}
  from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon } from '/static/views/formkit.js';

/* The organisation types that can take custody of a batch and record its next steps
 * (`supplychain.RECEIVER_ORG_TYPES`, from the ledger's rights). A batch handed to a biotech
 * developer or a regulator could never be marked arrived, so they are not offered. */
export const RECEIVER_ORG_TYPES = ['FARM', 'SUPPLY'];

/* GS1 mod-10 check digit for the digits before it (as backend/app/gs1.py). */
export function gs1CheckDigit(digits) {
  let total = 0;
  [...digits].reverse().forEach((char, position) => {
    total += Number(char) * (position % 2 === 0 ? 3 : 1);
  });
  return (10 - (total % 10)) % 10;
}

/* Ship a batch. Creating the shipment records the batch's shipping event and, when a
 * receiving organisation is chosen, hands custody to it there and then; the receiver marks it
 * arrived. Used here and, with the batch fixed, on the batch page. */
export function shipmentForm({ batch: fixedBatch = null, reload,
                               toggleLabel = 'Create a shipment' }) {
  const me = session.read()?.org_id;
  const sscc = el('input', { required: 'required', minlength: '18', maxlength: '18',
    inputmode: 'numeric', pattern: '\\d{18}', placeholder: 'SSCC, 18 digits',
    title: '18 digits, the last one a GS1 check digit' });
  // Checked as the operator types, as the server checks it: 18 digits and a valid GS1 check
  // digit. A typo in one digit is caught here rather than after submitting.
  sscc.addEventListener('input', () => {
    const value = sscc.value.trim();
    let problem = '';
    if (value && !/^\d{18}$/.test(value)) problem = 'An SSCC is 18 digits.';
    else if (value && gs1CheckDigit(value.slice(0, 17)) !== Number(value[17])) {
      problem = `Check digit is wrong (expected ${gs1CheckDigit(value.slice(0, 17))}).`;
    }
    sscc.setCustomValidity(problem);
  });
  // Only batches this organisation holds, in a state that can still move, are offered; the
  // API refuses anything else regardless (a foreign batch is a plain 404, audit P1).
  const batch = fixedBatch ? null : remoteSelect({
    endpoint: '/supply-chain/batches',
    filter: (row) => row.custodian_org_id === me
      && !['RECALLED', 'CONSUMED', 'IN_TRANSIT', 'RETAILED'].includes(row.state),
    label: (row) => `${row.batch_code} — ${humanize(row.state).toLowerCase()}, `
      + `${row.quantity} ${row.unit}`,
    placeholder: 'Select a batch to ship', emptyLabel: 'No batch you hold can be shipped',
  });
  const receiver = remoteSelect({
    endpoint: '/admin/organizations/directory', required: false,
    filter: (org) => org.id !== me && RECEIVER_ORG_TYPES.includes(org.org_type),
    label: (org) => `${org.name} (${orgTypeLabel(org.org_type)})`,
    placeholder: 'Nobody — an internal move (keep custody)',
    emptyLabel: 'No trading partner registered',
  });
  const carrier = el('input', { required: 'required', minlength: '2', maxlength: '160',
    placeholder: 'e.g. Midwest Cold Freight' });
  const originName = el('input', { required: 'required', minlength: '2', maxlength: '200',
    value: 'Origin depot' });
  const originLat = el('input', { type: 'number', step: 'any', min: '-90', max: '90',
    required: 'required', value: '42.0' });
  const originLon = el('input', { type: 'number', step: 'any', min: '-180', max: '180',
    required: 'required', value: '-93.6' });
  const destName = el('input', { required: 'required', minlength: '2', maxlength: '200',
    value: 'Destination depot' });
  const destLat = el('input', { type: 'number', step: 'any', min: '-90', max: '90',
    required: 'required', value: '41.6' });
  const destLon = el('input', { type: 'number', step: 'any', min: '-180', max: '180',
    required: 'required', value: '-93.7' });
  // No future dates: the server refuses them (a shipment dated ahead froze the batch).
  const departed = dateInput(todayIso(), { required: 'required', max: todayIso() });
  const arrived = dateInput(null, { max: todayIso() });
  // Only a move inside the organisation can be entered as already arrived: a hand-over is
  // signed for by the receiver.
  const syncArrived = () => {
    arrived.disabled = Boolean(receiver.value);
    if (arrived.disabled) arrived.value = '';
  };
  receiver.addEventListener('change', syncArrived);
  // The sensor travelling with the shipment. Its readings are bound to the shipment while it
  // is in transit and checked against the product's storage range.
  const coldChain = remoteSelect({
    endpoint: '/devices?device_type=COLD_CHAIN_SENSOR', required: false,
    requires: 'device:read',
    filter: (row) => row.org_id === me && row.status !== 'RETIRED',
    label: (row) => `${row.model} — ${row.id.slice(0, 8)} (${humanize(row.status).toLowerCase()})`,
    placeholder: 'No sensor — ship without temperature evidence',
    emptyLabel: 'Your organisation has no cold-chain sensor — register one under Devices '
      + 'to record temperatures in transit',
  });

  const controls = [
    ['SSCC', sscc],
    fixedBatch ? null : ['Batch', batch],
    ['Hand over to', receiver],
    ['Carrier', carrier],
    ['Origin name', originName],
    ['Origin latitude', originLat],
    ['Origin longitude', originLon],
    ['Destination name', destName],
    ['Destination latitude', destLat],
    ['Destination longitude', destLon],
    ['Departed on', departed],
    ['Arrived on (internal moves only)', arrived],
    ['Cold-chain sensor', coldChain],
  ].filter(Boolean);

  return createPanel({
    toggleLabel,
    submitLabel: 'Create shipment',
    hint: 'Creating the shipment records the batch as shipped. Choosing an organisation to hand '
      + 'over to moves custody to it now; it marks the shipment arrived when the goods reach '
      + 'it. Leave the arrival date empty while the shipment is in transit.',
    controls,
    submit: async () => {
      const created = await api('/supply-chain/shipments', { method: 'POST', body: {
        sscc: sscc.value, batch_id: fixedBatch ? fixedBatch.id : batch.value,
        to_org_id: receiver.value || null,
        carrier: carrier.value,
        origin_name: originName.value,
        origin_lat: Number(originLat.value), origin_lon: Number(originLon.value),
        destination_name: destName.value,
        destination_lat: Number(destLat.value), destination_lon: Number(destLon.value),
        departed_at: atNoon(departed.value),
        arrived_at: receiver.value ? null : atNoon(arrived.value),
        cold_chain_device_id: coldChain.value || null,
      } });
      return created.to_org_id
        ? `Shipment ${created.sscc} created — custody passed to the receiver, who has been `
          + 'notified'
        : `Shipment ${created.sscc} created`;
    },
    onDone: reload,
  });
}

/* The receiver signs for an in-transit shipment; this records the batch's receipt. */
export function arriveControl(row, reload) {
  const me = session.read()?.org_id;
  const receiver = row.to_org_id || row.org_id;
  if (row.status !== 'IN_TRANSIT' || receiver !== me || !can('supply:write')) return null;
  const day = dateInput(todayIso(), { 'aria-label': `Arrival date of ${row.sscc}`,
    max: todayIso() });
  const button = el('button', { text: 'Arrived', onClick: async () => {
    button.disabled = true;
    try {
      await api(`/supply-chain/shipments/${row.id}/arrive`, { method: 'POST',
        body: { arrived_at: atNoon(day.value || todayIso()) } });
      toast(`Shipment ${row.sscc} received — the batch is now recorded as received`, 'ok');
      reload();
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  } });
  return el('div', { class: 'row' }, [day, button]);
}

function rangeText(row) {
  if (row.storage_temp_min_c === null && row.storage_temp_max_c === null) return null;
  const low = row.storage_temp_min_c === null ? '' : fmtNum(row.storage_temp_min_c, 1);
  const high = row.storage_temp_max_c === null ? '' : fmtNum(row.storage_temp_max_c, 1);
  return `limit ${low} – ${high} °C`;
}

/* Recorded range against the product's storage range. */
export function coldChainCell(row) {
  const limit = rangeText(row);
  if (row.temp_min_c === null || row.temp_min_c === undefined) {
    return el('div', {}, [
      el('div', { text: row.cold_chain_device_id ? 'No readings yet' : 'No sensor' }),
      limit ? el('div', { class: 'hint', text: limit }) : null,
    ]);
  }
  const verdict = row.excursion === true ? badge('EXCURSION', 'critical')
    : row.excursion === false ? badge('WITHIN_LIMITS', 'verified') : null;
  return el('div', {}, [
    el('div', { text: `${fmtNum(row.temp_min_c, 1)} – ${fmtNum(row.temp_max_c, 1)} °C` }),
    limit ? el('div', { class: 'hint', text: limit }) : null,
    verdict,
  ]);
}

function refreshButton(row, reload) {
  if (!row.cold_chain_device_id) return null;
  return el('button', { text: 'Refresh telemetry', onClick: async () => {
    try {
      const summary = await api(`/supply-chain/shipments/${row.id}/cold-chain`);
      toast(summary.excursions
        ? `${summary.excursions} reading(s) outside the storage range`
        : `Cold chain: ${summary.readings} reading(s), none outside the range`,
      summary.excursions ? 'error' : 'ok');
      reload();
    } catch (error) { toast(error.message, 'error'); }
  } });
}

export const render = listView({
  title: 'Shipments and cold chain',
  subtitle: 'A shipment hands a batch to its receiver. The cold-chain sensor travelling with it '
    + 'binds its temperature readings to the shipment; an excursion outside the product\'s '
    + 'storage range raises a compliance alert and feeds the batch integrity verdict.',
  endpoint: '/supply-chain/shipments',
  // `incoming=true` (the dashboard's "Awaiting your arrival") lists only shipments coming to
  // this organisation, which it is the one to mark arrived.
  filters: [
    { key: 'status', label: 'Status', options: ['IN_TRANSIT', 'DELIVERED'] },
    { key: 'incoming', label: 'Direction', allLabel: 'Sent and received',
      options: [['true', 'Coming to us'], ['false', 'Sent by us']] },
  ],
  emptyFor: (active) => (active.incoming === 'true' && active.status === 'IN_TRANSIT'
    ? { title: 'Nothing on its way to you',
      message: 'No shipment to your organisation is waiting to be marked arrived.' }
    : null),
  actions: ({ reload }) => (can('supply:write') ? shipmentForm({ reload }) : null),
  columns: [
    { label: 'SSCC', render: (row) => el('span', { class: 'mono', text: row.sscc }) },
    { label: 'Batch', render: (row) => el('div', {}, [
      el('a', { href: `#/batch/${row.batch_id}`, class: 'mono',
        text: row.batch_code || row.batch_id.slice(0, 8) }),
      row.product_name ? el('div', { class: 'hint', text: row.product_name }) : null,
    ]) },
    { label: 'From → to', render: (row) => el('div', {}, [
      orgName(row.org_id), ' → ',
      row.to_org_id ? orgName(row.to_org_id)
        : el('span', { class: 'hint', text: 'Internal move (no hand-over)' }),
    ]) },
    { label: 'Carrier', key: 'carrier' },
    { label: 'Route', render: (row) => `${row.origin_name} → ${row.destination_name}` },
    { label: 'Departed', render: (row) => fmtDate(row.departed_at) },
    { label: 'Arrived', render: (row, { reload }) => (row.arrived_at
      ? fmtDate(row.arrived_at) : arriveControl(row, reload) || '—') },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'Cold chain', render: (row, { reload }) => el('div', {}, [
      coldChainCell(row), refreshButton(row, reload)]) },
  ],
  emptyTitle: 'No shipments',
  emptyMessage: 'Shipments your organisation sends or receives appear here. Create one against '
    + 'a batch you hold to hand it over and track its cold chain.',
});
