/* One farm: its fields, and what is planted on them. A planting from a supplied seed lot
 * carries that lot's GMO event, and a harvest batch created from the crop inherits it. */
import { el, api, can, empty, fmtDay, fmtNum, table, humanize, toast, confirmDialog,
         refreshView } from '/static/assets/core.js';
import { createPanel, remoteSelect, dateInput, todayIso, atNoon }
  from '/static/views/formkit.js';

function addFieldPanel(farm, reload) {
  const name = el('input', { required: 'required', maxlength: '120', placeholder: 'e.g. North 40' });
  const area = el('input', { type: 'number', step: 'any', min: '0.01', required: 'required',
    placeholder: 'hectares' });
  const soil = el('input', { maxlength: '60', placeholder: 'optional, e.g. Silty loam' });
  return createPanel({
    toggleLabel: 'Add a field',
    submitLabel: 'Add field',
    controls: [['Field name', name], ['Area (ha)', area], ['Soil type', soil]],
    submit: async () => {
      await api('/fields', { method: 'POST', body: {
        farm_id: farm.id, name: name.value, area_ha: Number(area.value),
        soil_type: soil.value || null } });
      return `Field ${name.value} added`;
    },
    onDone: reload,
  });
}

function plantPanel(fields, reload) {
  const fieldSelect = el('select', { required: 'required' }, [
    el('option', { value: '', text: fields.length ? 'Select a field' : 'Add a field first' }),
    ...fields.map((f) => el('option', { value: f.id, text: `${f.name} (${fmtNum(f.area_ha, 1)} ha)` })),
  ]);
  const seedLot = remoteSelect({
    endpoint: '/gmo/seed-lots', required: false, requires: 'gmo:read',
    label: (lot) => `${lot.lot_code} — ${lot.crop_type}${lot.variety ? ` ${lot.variety}` : ''}`
      + (lot.gmo_event_code ? ` (GMO ${lot.gmo_event_code})` : ''),
    placeholder: 'Own or conventional seed (no lot)',
    emptyLabel: 'No seed lot has been supplied to you',
  });
  const cropType = el('input', { required: 'required', maxlength: '80', placeholder: 'e.g. Maize' });
  const variety = el('input', { maxlength: '120', placeholder: 'optional' });
  const planted = dateInput(todayIso(), { required: 'required', max: todayIso() });
  const harvest = dateInput(null);
  // Fill from the lot's own fields: parsing the option label split "Sweet corn" in two.
  seedLot.addEventListener('change', async () => {
    const lots = await seedLot.whenReady;
    const lot = lots.find((row) => String(row.id) === seedLot.value);
    if (!lot) return;
    if (!cropType.value) cropType.value = lot.crop_type || '';
    if (!variety.value) variety.value = lot.variety || '';
  });
  return createPanel({
    toggleLabel: 'Plant a crop',
    submitLabel: 'Record planting',
    hint: 'Planting from a GMO seed lot records the lot\'s GMO event on the crop. The event '
      + 'must hold a live regulatory approval, or the planting is refused.',
    controls: [['Field', fieldSelect], ['Seed lot', seedLot], ['Crop', cropType],
      ['Variety', variety], ['Planted on', planted], ['Expected harvest', harvest]],
    submit: async () => {
      await api('/crops', { method: 'POST', body: {
        field_id: fieldSelect.value, crop_type: cropType.value, variety: variety.value || null,
        seed_lot_id: seedLot.value || null, planted_at: atNoon(planted.value),
        expected_harvest: atNoon(harvest.value) } });
      return 'Planting recorded';
    },
    onDone: reload,
  });
}

export async function render({ id }) {
  if (!id) return empty('No farm selected', 'Choose a farm from the list.');
  const [farm, fieldPage, cropPage, lotPage, batchPage] = await Promise.all([
    api(`/farms/${id}`),
    api(`/fields?farm_id=${id}&page_size=200`),
    api('/crops?page_size=200'),
    can('gmo:read') ? api('/gmo/seed-lots?page_size=200').catch(() => ({ items: [] }))
      : Promise.resolve({ items: [] }),
    can('supply:read') ? api('/supply-chain/batches?page_size=200').catch(() => ({ items: [] }))
      : Promise.resolve({ items: [] }),
  ]);
  const fields = fieldPage.items;
  const fieldNames = Object.fromEntries(fields.map((f) => [f.id, f.name]));
  const crops = cropPage.items.filter((c) => fieldNames[c.field_id]);
  const lots = Object.fromEntries(lotPage.items.map((l) => [l.id, l]));
  const batchesByCrop = {};
  for (const batch of batchPage.items || []) {
    if (batch.crop_id) (batchesByCrop[batch.crop_id] ||= []).push(batch);
  }
  const reload = () => refreshView();

  /* What can still happen to a crop: a growing crop can be marked harvested and turned into
   * a harvest batch; one already harvested into a batch links to that batch instead. */
  function harvestCell(crop) {
    const batches = batchesByCrop[crop.id] || [];
    if (batches.length) {
      return el('div', {}, batches.map((batch) => el('div', {}, [
        el('a', { href: `#/batch/${batch.id}`, class: 'mono', text: batch.batch_code }),
      ])));
    }
    const open = !['HARVESTED', 'FAILED'].includes(crop.status);
    if (!open) return humanize(crop.status);
    const actions = [];
    if (can('supply:write')) {
      actions.push(el('a', { href: `#/batches?crop=${crop.id}`, text: 'Create harvest batch' }));
    }
    if (can('farm:write')) {
      // For a harvest that does not become a traceable batch here (sold off-platform, say).
      const button = el('button', { text: 'Mark harvested', onClick: async () => {
        if (!confirmDialog(`Mark ${crop.crop_type} as harvested? A harvest batch can no `
          + 'longer be created from it afterwards.')) return;
        button.disabled = true;
        try {
          await api(`/crops/${crop.id}`, { method: 'PATCH', body: { status: 'HARVESTED' } });
          toast(`${crop.crop_type} marked as harvested`, 'ok');
          reload();
        } catch (error) {
          toast(error.message, 'error');
          button.disabled = false;
        }
      } });
      actions.push(button);
    }
    return actions.length ? el('div', { class: 'row' }, actions) : '—';
  }

  return el('div', {}, [
    el('h1', { text: farm.name }),
    el('p', { class: 'subtitle', text: `${farm.region}, ${farm.country} · `
      + `${fmtNum(farm.area_ha, 1)} ha · registered ${fmtDay(farm.created_at)}` }),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Fields' }),
      table([
        { label: 'Field', key: 'name' },
        { label: 'Area (ha)', numeric: true, render: (f) => fmtNum(f.area_ha, 1) },
        { label: 'Soil', render: (f) => f.soil_type || '—' },
        { label: 'Crops', numeric: true,
          render: (f) => String(crops.filter((c) => c.field_id === f.id).length) },
      ], fields, { emptyTitle: 'No fields yet',
        emptyMessage: 'Add the farm\'s fields so crops and devices can be placed on them.' }),
      can('farm:write') ? addFieldPanel(farm, reload) : null,
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Crops' }),
      table([
        { label: 'Field', render: (c) => fieldNames[c.field_id] },
        { label: 'Crop', render: (c) => `${c.crop_type}${c.variety ? ` ${c.variety}` : ''}` },
        { label: 'Seed lot', render: (c) => (c.seed_lot_id && lots[c.seed_lot_id]
          ? el('span', { class: 'mono', text: lots[c.seed_lot_id].lot_code }) : '—') },
        { label: 'GMO', render: (c) => (c.gmo_event_id
          ? (lots[c.seed_lot_id]?.gmo_event_code || 'Yes') : 'No') },
        // Planting and harvest dates are calendar days; the noon time stored with them was
        // never entered by anyone.
        { label: 'Planted', render: (c) => fmtDay(c.planted_at) },
        { label: 'Expected harvest', render: (c) => fmtDay(c.expected_harvest) },
        { label: 'Status', render: (c) => (batchesByCrop[c.id]
          ? 'Harvested' : humanize(c.status)) },
        { label: 'Harvest', render: (c) => harvestCell(c) },
      ], crops, { emptyTitle: 'Nothing planted yet',
        emptyMessage: 'Record a planting to start this farm\'s traceability chain.' }),
      can('farm:write') ? plantPanel(fields, reload) : null,
    ]),
    el('a', { href: '#/farms', text: '← All farms' }),
  ]);
}
