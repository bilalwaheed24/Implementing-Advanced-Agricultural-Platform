import { el, api, fmtNum, fmtDate, badge, table, empty, errorBox, toast, shortId }
  from '/static/assets/core.js';
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

// GeoJSON for QGIS: fetched through the API client (an <a href> cannot send the token) and
// handed to the browser as a file. In QGIS: Layer > Add Layer > Add Vector Layer.
function qgisExport() {
  return el('button', { class: 'secondary', text: 'Download fields for QGIS (GeoJSON)',
    onClick: async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const data = await api('/telemetry/satellite/geojson');
        const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)],
          { type: 'application/geo+json' }));
        const link = el('a', { href: url,
          download: `absp-fields-${new Date().toISOString().slice(0, 10)}.geojson` });
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        toast(`${data.features.length} features exported for QGIS`, 'ok');
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    } });
}

export const render = listView({
  title: 'Satellite and drone imagery',
  subtitle: 'Satellite scenes and OpenDroneMap orthophotos. Every scene is checksum-verified; '
    + 'for a drone orthophoto the SHA-256 of the image file itself is anchored on the ledger. '
    + 'NDVI needs a near-infrared band; an RGB drone camera gives VARI instead.',
  endpoint: '/telemetry/satellite/scenes',
  extra: stressCard,
  actions: () => qgisExport(),
  columns: [
    { label: 'Scene', render: (row) => el('span', { class: 'mono', text: row.scene_id }) },
    { label: 'Provider', key: 'provider' },
    { label: 'Type', render: (row) => badge(row.source || 'SATELLITE', 'neutral') },
    { label: 'Index', render: (row) => row.index_name || 'NDVI' },
    { label: 'Captured', render: (row) => fmtDate(row.captured_at) },
    { label: 'Index mean', numeric: true, render: (row) => fmtNum(row.ndvi_mean, 3) },
    { label: 'Index range', render: (row) =>
      `${fmtNum(row.ndvi_min, 2)} – ${fmtNum(row.ndvi_max, 2)}` },
    { label: 'Cloud cover', numeric: true, render: (row) => `${fmtNum(row.cloud_cover_pct, 0)}%` },
    { label: 'Image file', render: (row) => (row.file_sha256
      ? el('span', { class: 'mono', title: row.file_sha256, text: `sha256 ${shortId(row.file_sha256)}…` })
      : el('span', { class: 'demo-flag', text: 'Simulated' })) },
    { label: 'Ledger', render: (row) => (row.anchor_tx_id
      ? badge('ANCHORED') : '—') },
  ],
  emptyTitle: 'No imagery scenes',
  emptyMessage: 'Ingest a drone flight with scripts/odm_ingest.py, or satellite scenes through the API.',
});
