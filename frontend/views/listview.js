/* Shared list-view factory: fetch, paginate, filter, render. Used by the simple
 * catalogue screens so each one stays a declaration rather than a copy. */
import { el, api, table, loading, errorBox, pager, empty, humanize } from '/static/assets/core.js';

/* Rows of the loaded set fetched when a client-side search is active: the most the API
 * returns in one page. */
const SEARCH_WINDOW = 200;

/* `search` (optional) adds a text box above the table:
 *   { key: 'q', placeholder, label }            the term is sent to the endpoint as ?key=
 *   { fields: ['batch_code'] | (row) => text }  the endpoint has no search parameter, so the
 *                                               most recent SEARCH_WINDOW rows are fetched
 *                                               and filtered in the browser.
 *
 * `emptyFor` (optional) is called with the active filter values ({key: value}) when the
 * list comes back empty and no search term is set; it may return {title, message} to
 * replace the generic empty state ("No events are awaiting a decision" rather than "No
 * events registered" while a filter is on). Returning nothing keeps emptyTitle/Message.
 *
 * Filter values are read from the hash query (#/devices?offline=true), so a link from a
 * dashboard tile opens the list already filtered. A filter may carry `fromParams(params)`
 * to translate a legacy or alternative parameter into its own value. `columns` may be a
 * function returning the column list, evaluated on every load (to drop a column the role
 * cannot use). */
export function listView({ title, subtitle, endpoint, columns, filters = [], actions = null,
                           emptyTitle, emptyMessage, extra = null, pageSize = 25,
                           search = null, emptyFor = null }) {
  /* Column renderers receive (row, { reload }) so a row action can refresh the list
   * without the caller wiring a callback through module scope. */
  return async function render(context = {}) {
    const state = { page: 1, filters: {}, term: '' };
    for (const filter of filters) {
      const fromUrl = context.params?.get(filter.key)
        || (filter.fromParams && context.params ? filter.fromParams(context.params) : null);
      if (fromUrl) state.filters[filter.key] = fromUrl;
    }
    const clientSearch = Boolean(search && search.fields);
    if (search) state.term = context.params?.get(search.key || 'q') || '';

    const body = el('div', {}, [loading()]);

    let searchControl = null;
    if (search) {
      const input = el('input', {
        type: 'search', id: 'f-search', value: state.term || null,
        placeholder: search.placeholder || 'Search…', autocomplete: 'off',
      });
      let pending = null;
      input.addEventListener('input', () => {
        clearTimeout(pending);
        pending = setTimeout(() => {
          state.term = input.value.trim();
          state.page = 1;
          load();
        }, 300);
      });
      searchControl = el('div', { class: 'u-search-field' }, [
        el('label', { for: 'f-search', text: search.label || 'Search' }), input,
      ]);
    }

    let loadSequence = 0;

    function rowText(row) {
      if (typeof search.fields === 'function') return String(search.fields(row) || '');
      return search.fields.map((key) => row[key] ?? '').join(' ');
    }

    /* `filter.options` is a list of codes, or (for options that depend on the caller's
     * records, such as their devices) an async function returning codes or
     * [value, label] pairs. */
    const optionNodes = (filter, options) => options.map((option) => {
      const [value, text] = Array.isArray(option)
        // humanize, as the badges use: "In transit" and "Non-GMO" read the same in a filter
        // and in the rows it filters.
        ? option : [option, (filter.optionLabel || humanize)(option)];
      return el('option', { value, text,
        selected: state.filters[filter.key] === value ? 'selected' : null });
    });
    const filterControls = await Promise.all(filters.map(async (filter) => {
      const options = typeof filter.options === 'function'
        ? await filter.options() : filter.options;
      if (typeof filter.options === 'function' && !options.length) return null;
      return el('div', { class: 'u-filter-field' }, [
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
          ...optionNodes(filter, options),
        ]),
      ]);
    }));

    async function load() {
      body.replaceChildren(loading());
      const filtering = clientSearch && state.term;
      const query = new URLSearchParams({ page: filtering ? '1' : String(state.page),
        page_size: String(filtering ? SEARCH_WINDOW : pageSize) });
      for (const [key, value] of Object.entries(state.filters)) {
        if (value) query.set(key, value);
      }
      if (search && !clientSearch && state.term) query.set(search.key || 'q', state.term);
      // Only the newest load may draw: a slow response to an earlier search term must not
      // overwrite the result for the term now in the box.
      const sequence = ++loadSequence;
      try {
        const result = await api(`${endpoint}?${query.toString()}`);
        if (sequence !== loadSequence) return;
        let rows = result.items ?? result;
        const total = result.total ?? rows.length;
        const notes = [];
        if (filtering) {
          const needle = state.term.toLowerCase();
          rows = rows.filter((row) => rowText(row).toLowerCase().includes(needle));
          if (total > SEARCH_WINDOW) {
            notes.push(el('p', { class: 'hint',
              text: `Searched the ${SEARCH_WINDOW} most recent of ${total} records.` }));
          }
        }
        const activeColumns = typeof columns === 'function' ? columns() : columns;
        const bound = activeColumns.map((column) => (column.render
          ? { ...column, render: (row) => column.render(row, { reload: load }) }
          : column));
        const active = Object.fromEntries(
          Object.entries(state.filters).filter(([, value]) => value));
        const fitted = !state.term && emptyFor && Object.keys(active).length
          ? emptyFor(active) : null;
        const children = [...notes, table(bound, rows, state.term
          ? { emptyTitle: 'No matches', emptyMessage: `Nothing matches “${state.term}”.` }
          : (fitted ? { emptyTitle: fitted.title, emptyMessage: fitted.message }
            : { emptyTitle, emptyMessage }))];
        if (!filtering && result.total !== undefined && total > pageSize) {
          children.push(pager(state.page, pageSize, total, (page) => {
            state.page = page;
            load();
          }));
        }
        body.replaceChildren(...children);
      } catch (error) {
        if (sequence === loadSequence) body.replaceChildren(errorBox(error));
      }
    }

    await load();

    const head = [el('h1', { text: title })];
    // A function is evaluated per render, so the copy can follow the signed-in role.
    const subtitleText = typeof subtitle === 'function' ? subtitle() : subtitle;
    if (subtitleText) head.push(el('p', { class: 'subtitle', text: subtitleText }));
    const toolbar = [];
    if (searchControl) toolbar.push(searchControl);
    toolbar.push(...filterControls.filter(Boolean));
    // Somewhere above the table for a form to put a one-time notice the operator must read
    // (a freshly issued device secret, say) rather than a toast that disappears.
    const notices = el('div', {});
    // `actions` is invoked here, on every render, so a control is gated on the permissions
    // the session holds now rather than those it held when the module was first imported.
    if (actions) toolbar.push(actions({ reload: load, host: notices }));
    const controls = toolbar.filter(Boolean);

    return el('div', {}, [
      ...head,
      extra ? await extra() : null,
      notices,
      el('div', { class: 'card' }, [
        controls.length ? el('div', { class: 'row u-toolbar' },
          controls) : null,
        body,
      ]),
    ]);
  };
}

export { empty };
