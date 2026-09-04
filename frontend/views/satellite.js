import { el, api, fmtNum, fmtDate, badge, table, empty, errorBox } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

async function stressCard() {
  try {
    const result = await api('/telemetry/insights/field-stress');
    if (!result.ranking?.length) {
      return el('div', { class: 'card' }, [
        el('h2', { text: 'Field stress ranking' }),
        empty('No scenes ingested', result.method),
      ]);
    }
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Precision-farming field stress ranking' }),
      el('p', { class: 'hint', text: result.method }),
      table([
        { label: 'Field', key: 'field_name' },
        { label: 'NDVI mean', numeric: true, render: (r) => fmtNum(r.ndvi_mean, 3) },
        { label: 'Soil moisture', numeric: true, render: (r) =>
          r.soil_moisture_pct === null ? '—' : `${fmtNum(r.soil_moisture_pct, 1)}%` },
        { label: 'Stress index', numeric: true, render: (r) => fmtNum(r.stress_index, 3) },
        { label: 'Level', render: (r) => badge(r.level) },
        { label: 'Captured', render: (r) => fmtDate(r.captured_at) },
      ], result.ranking),
    ]);
  } catch (error) {
    return errorBox(error);
  }
}

export const render = listView({
  title: 'Satellite imagery and NDVI',
  subtitle: 'Scene metadata is checksum-verified and range-validated on ingestion. '
    + 'Raster imagery itself is out of scope for this demonstration.',
  endpoint: '/telemetry/satellite/scenes',
  extra: stressCard,
  columns: [
    { label: 'Scene', render: (row) => el('span', { class: 'mono', text: row.scene_id }) },
    { label: 'Provider', key: 'provider' },
    { label: 'Captured', render: (row) => fmtDate(row.captured_at) },
    { label: 'NDVI mean', numeric: true, render: (row) => fmtNum(row.ndvi_mean, 3) },
    { label: 'NDVI range', render: (row) =>
      `${fmtNum(row.ndvi_min, 2)} – ${fmtNum(row.ndvi_max, 2)}` },
    { label: 'Cloud cover', numeric: true, render: (row) => `${fmtNum(row.cloud_cover_pct, 0)}%` },
    { label: 'Source', render: (row) => row.is_simulated
      ? el('span', { class: 'demo-flag', text: 'Simulated' }) : 'Provider' },
  ],
  emptyTitle: 'No satellite scenes',
  emptyMessage: 'Scenes are ingested through POST /api/v1/telemetry/satellite/scenes.',
});
