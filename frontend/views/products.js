import { el, api, field, toast, can, fmtNum } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

function createForm(reload) {
  const fields = {
    gtin: el('input', { required: 'required', minlength: '8', maxlength: '14',
      placeholder: '8-14 digit GTIN' }),
    name: el('input', { required: 'required' }),
    category: el('input', { required: 'required' }),
    storage_temp_min_c: el('input', { type: 'number', step: 'any' }),
    storage_temp_max_c: el('input', { type: 'number', step: 'any' }),
  };
  const organic = el('input', { type: 'checkbox' });
  const nonGmo = el('input', { type: 'checkbox' });
  const message = el('div', { class: 'error-text', role: 'alert' });
  const form = el('form', { class: 'u-hidden' }, [
    el('div', { class: 'grid cols-3' }, Object.entries(fields).map(([key, input]) =>
      field(key.replace(/_/g, ' '), input))),
    el('div', { class: 'row' }, [
      el('label', { class: 'row u-fw-400' }, [organic, ' Organic claim']),
      el('label', { class: 'row u-fw-400' }, [nonGmo, ' Non-GMO claim']),
    ]),
    message,
    el('button', { class: 'primary', type: 'submit', text: 'Create product' }),
  ]);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    try {
      await api('/supply-chain/products', { method: 'POST', body: {
        gtin: fields.gtin.value, name: fields.name.value, category: fields.category.value,
        organic_claim: organic.checked, non_gmo_claim: nonGmo.checked,
        storage_temp_min_c: fields.storage_temp_min_c.value
          ? Number(fields.storage_temp_min_c.value) : null,
        storage_temp_max_c: fields.storage_temp_max_c.value
          ? Number(fields.storage_temp_max_c.value) : null,
      } });
      toast('Product created', 'ok');
      form.classList.add('u-hidden');
      reload();
    } catch (error) { message.textContent = error.message; }
  });
  const toggle = el('button', { class: 'primary', text: 'New product', onClick: () => {
    form.classList.toggle('u-hidden');
  } });
  return el('div', {}, [toggle, form]);
}

export const render = listView({
  title: 'Products',
  subtitle: 'Trade items identified by GS1 GTIN.',
  endpoint: '/supply-chain/products',
  actions: can('supply:write') ? ({ reload }) => createForm(reload) : null,
  columns: [
    { label: 'GTIN', render: (row) => el('span', { class: 'mono', text: row.gtin }) },
    { label: 'Name', key: 'name' },
    { label: 'Category', key: 'category' },
    { label: 'Organic', render: (row) => row.organic_claim ? '✓' : '—' },
    { label: 'Non-GMO', render: (row) => row.non_gmo_claim ? '✓' : '—' },
    { label: 'Storage range', render: (row) => row.storage_temp_min_c === null ? '—'
      : `${fmtNum(row.storage_temp_min_c, 0)}–${fmtNum(row.storage_temp_max_c, 0)} °C` },
  ],
  emptyTitle: 'No products',
  emptyMessage: 'Create a product before creating batches against it.',
});
