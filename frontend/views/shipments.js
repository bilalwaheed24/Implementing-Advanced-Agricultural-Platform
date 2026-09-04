import { el, api, badge, fmtDate, fmtNum, toast, empty } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

export const render = listView({
  title: 'Shipments and cold chain',
  subtitle: 'Cold-chain telemetry is bound to a shipment; a temperature excursion feeds '
    + 'directly into the batch integrity verdict.',
  endpoint: '/supply-chain/shipments',
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
