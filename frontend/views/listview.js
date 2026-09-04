/* Shared list-view factory: fetch, paginate, filter, render. Used by the simple
 * catalogue screens so each one stays a declaration rather than a copy. */
import { el, api, table, loading, errorBox, pager, empty, titleCase } from '/static/assets/core.js';

export function listView({ title, subtitle, endpoint, columns, filters = [], actions = null,
                           emptyTitle, emptyMessage, extra = null, pageSize = 25 }) {
  /* Column renderers receive (row, { reload }) so a row action can refresh the list
   * without the caller wiring a callback through module scope. */
  return async function render(context = {}) {
    const state = { page: 1, filters: {} };
    for (const filter of filters) {
      const fromUrl = context.params?.get(filter.key);
      if (fromUrl) state.filters[filter.key] = fromUrl;
    }

    const body = el('div', {}, [loading()]);

    const filterControls = filters.map((filter) => el('div', { class: 'field',
      class: 'u-filter-field' }, [
      el('label', { for: `f-${filter.key}`, text: filter.label }),
      el('select', {
        id: `f-${filter.key}`,
        onChange: (event) => {
          state.filters[filter.key] = event.target.value;
          state.page = 1;
          load();
        },
      }, [
        el('option', { value: '', text: filter.allLabel || 'All' }),
        ...filter.options.map((option) => el('option', {
          value: option, text: titleCase(option),
          selected: state.filters[filter.key] === option ? 'selected' : null,
        })),
      ]),
    ]));

    async function load() {
      body.replaceChildren(loading());
      const query = new URLSearchParams({ page: String(state.page),
        page_size: String(pageSize) });
      for (const [key, value] of Object.entries(state.filters)) {
        if (value) query.set(key, value);
      }
      try {
        const result = await api(`${endpoint}?${query.toString()}`);
        const rows = result.items ?? result;
        const total = result.total ?? rows.length;
        const bound = columns.map((column) => (column.render
          ? { ...column, render: (row) => column.render(row, { reload: load }) }
          : column));
        const children = [table(bound, rows, { emptyTitle, emptyMessage })];
        if (result.total !== undefined && total > pageSize) {
          children.push(pager(state.page, pageSize, total, (page) => {
            state.page = page;
            load();
          }));
        }
        body.replaceChildren(...children);
      } catch (error) {
        body.replaceChildren(errorBox(error));
      }
    }

    await load();

    const head = [el('h1', { text: title })];
    if (subtitle) head.push(el('p', { class: 'subtitle', text: subtitle }));
    const toolbar = [];
    if (filterControls.length) toolbar.push(...filterControls);
    if (actions) toolbar.push(actions({ reload: load }));

    return el('div', {}, [
      ...head,
      extra ? await extra() : null,
      el('div', { class: 'card' }, [
        toolbar.length ? el('div', { class: 'row u-toolbar' },
          toolbar) : null,
        body,
      ]),
    ]);
  };
}

export { empty };
