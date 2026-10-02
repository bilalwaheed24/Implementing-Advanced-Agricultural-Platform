import { el, api, badge, can, fmtDate, fmtNum, toast, empty } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon } from '/static/views/formkit.js';

function createForm(reload) {
  const sscc = el('input', { required: 'required', minlength: '8', maxlength: '18',
    placeholder: 'SSCC, 8–18 digits' });
  // Only batches this organisation holds are offered; the API refuses a foreign batch with a
  // plain 404 regardless, so the selector and the server agree (audit P1).
  const batch = remoteSelect({
    endpoint: '/supply-chain/batches',
    label: (row) => `${row.batch_code} — ${row.state.toLowerCase()}, `
      + `${row.quantity} ${row.unit}`,
    placeholder: 'Select a batch to ship', emptyLabel: 'No batch available to ship',
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
  const departed = dateInput(todayIso(), { required: 'required' });
  const arrived = dateInput();
  // A cold-chain sensor binds temperature telemetry to this shipment.
  const coldChain = remoteSelect({
    endpoint: '/devices', required: false, requires: 'device:read',
    filter: (row) => row.device_type === 'COLD_CHAIN_SENSOR',
    label: (row) => `${row.model} — ${row.id.slice(0, 8)} (${row.status.toLowerCase()})`,
    placeholder: 'No cold-chain sensor',
    emptyLabel: 'No cold-chain sensor registered',
  });

  return createPanel({
    toggleLabel: 'Create a shipment',
    submitLabel: 'Create shipment',
    hint: 'Leave the arrival date empty while the shipment is still in transit.',
    controls: [
      ['SSCC', sscc],
      ['Batch', batch],
      ['Carrier', carrier],
      ['Origin name', originName],
      ['Origin latitude', originLat],
      ['Origin longitude', originLon],
      ['Destination name', destName],
      ['Destination latitude', destLat],
      ['Destination longitude', destLon],
      ['Departed on', departed],
      ['Arrived on', arrived],
      ['Cold-chain sensor', coldChain],
    ],
    submit: async () => {
      const created = await api('/supply-chain/shipments', { method: 'POST', body: {
        sscc: sscc.value, batch_id: batch.value, carrier: carrier.value,
        origin_name: originName.value,
        origin_lat: Number(originLat.value), origin_lon: Number(originLon.value),
        destination_name: destName.value,
        destination_lat: Number(destLat.value), destination_lon: Number(destLon.value),
        departed_at: atNoon(departed.value),
        arrived_at: atNoon(arrived.value),
        cold_chain_device_id: coldChain.value || null,
      } });
      return `Shipment ${created.sscc} created`;
    },
    onDone: reload,
  });
}

export const render = listView({
  title: 'Shipments and cold chain',
  subtitle: 'Cold-chain telemetry is bound to a shipment; a temperature excursion feeds '
    + 'directly into the batch integrity verdict.',
  endpoint: '/supply-chain/shipments',
  actions: ({ reload }) => (can('supply:write') ? createForm(reload) : null),
  columns: [
    { label: 'SSCC', render: (row) => el('span', { class: 'mono', text: row.sscc }) },
    { label: 'Carrier', key: 'carrier' },
    { label: 'Route', render: (row) => `${row.origin_name} → ${row.destination_name}` },
    { label: 'Departed', render: (row) => fmtDate(row.departed_at) },
    { label: 'Arrived', render: (row) => fmtDate(row.arrived_at) },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'Temp range', render: (row) => row.temp_min_c === null ? 'no telemetry'
      : `${fmtNum(row.temp_min_c, 1)} – ${fmtNum(row.temp_max_c, 1)} °C` },
    { label: 'Cold chain', render: (row, { reload }) => row.cold_chain_device_id
      ? el('button', { text: 'Refresh telemetry', onClick: async () => {
        try {
          await api(`/supply-chain/shipments/${row.id}/cold-chain`);
          toast('Cold-chain summary refreshed', 'ok');
          reload();
        } catch (error) { toast(error.message, 'error'); }
      } })
      : '—' },
  ],
  emptyTitle: 'No shipments',
  emptyMessage: 'Create a shipment against a batch to track its cold chain.',
});
