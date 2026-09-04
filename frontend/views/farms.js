import { el, api, badge, field, fmtNum, fmtDay, toast } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function createFarmForm(reload) {
  const fields = {
    name: el('input', { required: 'required', maxlength: '200' }),
    region: el('input', { required: 'required', maxlength: '120', value: 'Iowa' }),
    country: el('input', { required: 'required', maxlength: '2', minlength: '2', value: 'US' }),
    latitude: el('input', { type: 'number', step: 'any', min: '-90', max: '90', value: '42.0' }),
    longitude: el('input', { type: 'number', step: 'any', min: '-180', max: '180', value: '-93.6' }),
    area_ha: el('input', { type: 'number', step: 'any', min: '0.1', value: '120' }),
  };
  const message = el('div', { class: 'error-text', role: 'alert' });
  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-3' }, Object.entries(fields).map(([key, input]) =>
      field(key.replace(/_/g, ' '), input))),
    message,
    el('button', { class: 'primary', type: 'submit', text: 'Create farm' }),
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    try {
      await api('/farms', { method: 'POST', body: {
        name: fields.name.value, region: fields.region.value,
        country: fields.country.value.toUpperCase(),
        latitude: Number(fields.latitude.value), longitude: Number(fields.longitude.value),
        area_ha: Number(fields.area_ha.value),
      } });
      toast('Farm registered', 'ok');
      form.classList.add('u-hidden');
      reload();
    } catch (error) {
      message.textContent = error.message
        + (error.fields || []).map((f) => ` (${f.field}: ${f.message})`).join('');
    }
  });
  const toggle = el('button', { text: 'Register a farm', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

export const render = listView({
  title: 'Farms and fields',
  subtitle: 'Farms are scoped to your organisation. A competitor cannot see these records.',
  endpoint: '/farms',
  columns: [
    { label: 'Name', key: 'name' },
    { label: 'Region', render: (row) => `${row.region}, ${row.country}` },
    { label: 'Area (ha)', numeric: true, render: (row) => fmtNum(row.area_ha, 1) },
    { label: 'Coordinates', render: (row) =>
      el('span', { class: 'mono', text: `${fmtNum(row.latitude, 3)}, ${fmtNum(row.longitude, 3)}` }) },
    { label: 'GLN', render: (row) => row.gln || '—' },
    { label: 'Registered', render: (row) => fmtDay(row.created_at) },
    { label: 'Fields', render: (row) => el('a', {
      href: `#/farms?farm_id=${row.id}`, text: 'View fields' }) },
  ],
  actions: ({ reload }) => createFarmForm(reload),
  emptyTitle: 'No farms registered',
  emptyMessage: 'Register a farm to start attaching fields, crops and devices to it.',
});
