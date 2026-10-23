import { el, api, badge, can, fmtDate, fmtNum, termLabel, titleCase } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

/* Sensor channels as a reader would name them, with the unit. */
const CHANNELS = {
  air_temp_c: ['Air temperature', '°C'], soil_temp_c: ['Soil temperature', '°C'],
  temp_c: ['Temperature', '°C'], humidity_pct: ['Humidity', '%'],
  soil_moisture_pct: ['Soil moisture', '%'], ph: ['Soil pH', ''],
  ec_ds_m: ['Conductivity', 'dS/m'], nitrogen_ppm: ['Nitrogen', 'ppm'],
  phosphorus_ppm: ['Phosphorus', 'ppm'], potassium_ppm: ['Potassium', 'ppm'],
  rainfall_mm: ['Rainfall', 'mm'], solar_w_m2: ['Solar radiation', 'W/m²'],
  wind_speed_ms: ['Wind speed', 'm/s'], battery_pct: ['Battery', '%'], shock_g: ['Shock', 'g'],
};
const UNIT_SUFFIXES = { pct: '%', c: '°C', mm: 'mm', ppm: 'ppm', ms: 'm/s', kg: 'kg', m: 'm',
  g: 'g', ha: 'ha' };

function channel(key, value) {
  let [name, unit] = CHANNELS[key] || [];
  if (!name) {
    const parts = key.split('_');
    unit = UNIT_SUFFIXES[parts[parts.length - 1]];
    name = termLabel((unit ? parts.slice(0, -1) : parts).join('_'));
    unit = unit || '';
  }
  return `${name} ${fmtNum(value, 1)}${unit && unit !== '%' && unit !== '°C' ? ' ' : ''}${unit}`;
}

/* The device filter offers this organisation's devices by name. */
async function deviceOptions() {
  if (!can('device:read')) return [];
  try {
    const page = await api('/devices?page=1&page_size=200');
    return (page.items || []).map((device) => [device.id,
      `${titleCase(device.device_type)} — ${device.model} (${device.id.slice(0, 8)})`]);
  } catch { return []; }
}

export const render = listView({
  title: 'Telemetry',
  subtitle: 'Payloads are encrypted at rest; only a non-sensitive numeric summary is shown '
    + 'here. Quality reflects range validation and anomaly scoring.',
  endpoint: '/telemetry',
  filters: [
    { key: 'device_id', label: 'Device', allLabel: 'All devices', options: deviceOptions },
    { key: 'quality', label: 'Quality', options: ['OK', 'SUSPECT', 'QUARANTINED'] },
  ],
  columns: [
    { label: 'Recorded', render: (row) => fmtDate(row.recorded_at) },
    { label: 'Device', render: (row) => el('a', { href: `#/device/${row.device_id}` }, [
      el('span', { text: row.device_type ? titleCase(row.device_type) : 'Device' }),
      el('span', { class: 'hint mono u-ml-6', text: row.device_id.slice(0, 8) }),
    ]) },
    { label: 'Quality', render: (row) => badge(row.quality) },
    { label: 'Anomaly', numeric: true, render: (row) =>
      row.anomaly_score === null ? 'pending' : fmtNum(row.anomaly_score, 3) },
    { label: 'Readings', render: (row) => el('span', { class: 'hint',
      text: Object.entries(row.summary || {})
        .filter(([, value]) => typeof value === 'number').slice(0, 4)
        .map(([key, value]) => channel(key, value)).join(' · ') }) },
    { label: 'Backfilled', render: (row) => (row.backfilled
      ? el('span', { class: 'badge neutral', text: 'Sent late' }) : '—') },
  ],
  emptyTitle: 'No telemetry yet',
  emptyMessage: 'Readings appear here once a registered device starts reporting.',
});
