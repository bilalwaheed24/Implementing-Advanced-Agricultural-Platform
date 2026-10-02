/* Shared building blocks for the create/approve forms.
 *
 * Two things every one of these screens needs and used to re-implement:
 *  - a <select> whose options are fetched from a tenant-scoped list endpoint, so an operator
 *    picks a human-readable label instead of pasting a UUID (audit P3 §6), and cannot name a
 *    resource their organisation does not hold;
 *  - a disclosure panel with consistent submit/error/busy handling.
 */
import { el, api, can, field, toast } from '/static/assets/core.js';

/* A select backed by a list endpoint. The caller supplies `label(row)`, which is what the
 * operator reads; the option value is always the id the API expects. */
export function remoteSelect({ endpoint, label, required = true, placeholder = 'Select…',
                              filter = () => true, pageSize = 100, emptyLabel,
                              requires = null }) {
  const select = el('select', required ? { required: 'required' } : {});
  select.appendChild(el('option', { value: '', text: 'Loading…' }));
  select.disabled = true;

  const ready = (async () => {
    // When the session plainly lacks the permission the source endpoint requires, do not
    // call it at all: the 403 is predictable, and firing it only produces a console error
    // and a wasted round trip.
    if (requires && !can(requires)) {
      select.unavailable = true;
      select.replaceChildren(el('option', { value: '',
        text: 'Not available to your role' }));
      select.disabled = true;
      return [];
    }
    try {
      const separator = endpoint.includes('?') ? '&' : '?';
      const query = new URLSearchParams({ page: '1', page_size: String(pageSize) });
      const page = await api(`${endpoint}${separator}${query}`);
      // Paginated list endpoints answer {items: [...]}; the small helper endpoints
      // (eligible-subjects, say) answer a bare array.
      const rows = (Array.isArray(page) ? page : page.items || []).filter(filter);
      select.replaceChildren();
      if (!rows.length) {
        select.appendChild(el('option', { value: '',
          text: emptyLabel || 'Nothing eligible yet' }));
        select.disabled = true;
        return [];
      }
      select.appendChild(el('option', { value: '', text: placeholder }));
      for (const row of rows) {
        select.appendChild(el('option', { value: row.id, text: label(row) }));
      }
      select.disabled = false;
      return rows;
    } catch (error) {
      // A role that cannot read the source list is not a fault: an optional selector is
      // simply not applicable to it, and createPanel hides the field rather than leaving a
      // dead control on screen. A required one stays visible and says why it is blocked.
      const forbidden = error.status === 403;
      select.unavailable = forbidden;
      select.replaceChildren(el('option', { value: '',
        text: forbidden ? 'Not available to your role' : 'Could not load options' }));
      select.disabled = true;
      return [];
    }
  })();

  select.whenReady = ready;
  return select;
}

/* Static options from a fixed vocabulary, rendered with a human label. */
export function choiceSelect(options, { required = true, value = null } = {}) {
  return el('select', required ? { required: 'required' } : {},
    options.map(([optionValue, text]) => el('option', {
      value: optionValue, text, selected: optionValue === value ? 'selected' : null })));
}

export function dateInput(value = null, attrs = {}) {
  const input = el('input', { type: 'date', ...attrs });
  if (value) input.value = value;
  return input;
}

export function todayIso() { return new Date().toISOString().slice(0, 10); }

/* Turn a yyyy-mm-dd value into the ISO instant the API expects. */
export function atNoon(dayValue) {
  return dayValue ? new Date(`${dayValue}T12:00:00Z`).toISOString() : null;
}

/* A toggle button plus a hidden form, with one place for errors and the busy state.
 *
 * `submit` returns a success message, or throws; the panel never reports success for a call
 * that failed (audit: no false UI success). */
export function createPanel({ toggleLabel, submitLabel, controls, submit, onDone,
                             hint = null, primary = true }) {
  const message = el('div', { class: 'error-text', role: 'alert' });
  const button = el('button', { class: 'primary', type: 'submit', text: submitLabel });
  const wrappers = controls.map(([labelText, control, extras]) => {
    const wrapper = field(labelText, control, extras || []);
    // An optional selector whose source this role may not read is withdrawn once its load
    // settles, so no unauthorised-looking control is left on the form.
    if (control && control.whenReady) {
      control.whenReady.then(() => {
        if (control.unavailable && !control.hasAttribute('required')) wrapper.hidden = true;
      });
    }
    return wrapper;
  });
  const form = el('form', { class: 'u-hidden' }, [
    hint ? el('p', { class: 'hint', text: hint }) : null,
    el('div', { class: 'grid cols-2' }, wrappers),
    message,
    button,
  ]);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Working…';
    try {
      const result = await submit();
      toast(result || 'Saved', 'ok');
      form.reset();
      form.classList.add('u-hidden');
      if (onDone) onDone();
    } catch (error) {
      message.textContent = error.message
        + (error.fields || []).map((f) => ` (${f.field}: ${f.message})`).join('');
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  });

  const toggle = el('button', {
    class: primary ? 'primary' : '', text: toggleLabel,
    onClick: () => form.classList.toggle('u-hidden'),
  });
  return el('div', {}, [toggle, form]);
}
