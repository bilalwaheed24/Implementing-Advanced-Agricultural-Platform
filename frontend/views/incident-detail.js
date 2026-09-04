import { el, api, badge, field, fmtDate, toast, can, empty, titleCase } from '/static/assets/core.js';

export async function render({ id }) {
  if (!id) return empty('No incident selected', 'Choose an incident from the list.');
  const detail = await api(`/security/incidents/${id}`);
  const incident = detail.incident;

  const timeline = el('ul', { class: 'timeline' }, detail.timeline.map((event) =>
    el('li', {}, [
      el('strong', { text: titleCase(event.action) }),
      el('div', { class: 'when', text: fmtDate(event.created_at) }),
      event.detail ? el('div', { class: 'hint', text: event.detail }) : null,
    ])));

  const controls = [];
  if (can('incident:write')) {
    const rootCause = el('textarea', { placeholder: 'Root cause, once determined' });
    const message = el('div', { class: 'error-text', role: 'alert' });
    async function update(status) {
      try {
        await api(`/security/incidents/${id}`, { method: 'PATCH', body: {
          status, root_cause: rootCause.value.trim() || null,
          note: `Status set to ${status}` } });
        toast(`Incident marked ${status.toLowerCase()}`, 'ok');
        window.location.reload();
      } catch (error) { message.textContent = error.message; }
    }
    controls.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Update incident' }),
      field('Root cause', rootCause),
      message,
      el('div', { class: 'row' }, [
        el('button', { text: 'Triage', onClick: () => update('TRIAGED') }),
        el('button', { text: 'Mark contained', onClick: () => update('CONTAINED') }),
        el('button', { class: 'primary', text: 'Resolve', onClick: () => update('RESOLVED') }),
        el('button', { text: 'Close', onClick: () => update('CLOSED') }),
      ]),
    ]));
  }

  return el('div', {}, [
    el('h1', { text: incident.title }),
    el('p', { class: 'subtitle' }, [badge(incident.severity), ' ', badge(incident.status),
      ' · opened ', fmtDate(incident.created_at)]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Summary' }),
      el('p', { text: incident.summary || 'No summary recorded.' }),
      incident.root_cause ? el('p', {}, [el('strong', { text: 'Root cause: ' }),
        incident.root_cause]) : null,
    ]),
    el('div', { class: 'card' }, [el('h2', { text: 'Timeline' }), timeline]),
    ...controls,
    el('a', { href: '#/incidents', text: '← All incidents' }),
  ]);
}
