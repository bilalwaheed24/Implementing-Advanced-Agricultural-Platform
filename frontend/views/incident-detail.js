import { el, api, badge, field, fmtDate, toast, can, empty, titleCase, humanizeText,
         refreshView, session, table, confirmDialog, rowHeader } from '/static/assets/core.js';
import { entityLink, incidentTitle } from '/static/views/entity-links.js';

/* The moves the server permits from each status (security_ops.INCIDENT_TRANSITIONS), with
 * the label each is offered under. Only these are shown, so a button never leads to a 409. */
const NEXT_STATUS = {
  OPEN: [['TRIAGED', 'Triage'], ['CONTAINED', 'Mark contained'], ['RESOLVED', 'Resolve']],
  TRIAGED: [['CONTAINED', 'Mark contained'], ['RESOLVED', 'Resolve']],
  CONTAINED: [['RESOLVED', 'Resolve']],
  RESOLVED: [['CLOSED', 'Close'], ['OPEN', 'Reopen']],
  CLOSED: [],
};

const BIOSAFETY_CATEGORIES = ['BIOSECURITY', 'DURC'];

function timelineList(events) {
  return el('ul', { class: 'timeline' }, events.map((event) =>
    el('li', {}, [
      el('strong', { text: titleCase(event.action) }),
      el('div', { class: 'when', text: [fmtDate(event.created_at),
        event.actor_name ? `by ${event.actor_name}` : 'automatic'].join(' · ') }),
      event.detail ? el('div', { class: 'hint', text: humanizeText(event.detail) }) : null,
    ])));
}

function alertsCard(alerts) {
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Linked alerts' }),
    el('p', { class: 'hint', text: 'Resolving the incident resolves these; resolving the last '
      + 'of them resolves the incident.' }),
    table([
      { label: 'Raised', render: (row) => fmtDate(row.created_at) },
      { label: 'Alert', render: (row) => el('div', {}, [
        el('strong', { text: row.title }),
        row.occurrences > 1 ? el('div', { class: 'hint',
          text: `Seen ${row.occurrences} times, last ${fmtDate(row.last_seen_at)}` }) : null,
      ]) },
      { label: 'Severity', render: (row) => badge(row.severity) },
      { label: 'Status', render: (row) => badge(row.status) },
    ], alerts, { emptyTitle: 'No linked alerts',
      emptyMessage: 'This incident was opened by hand rather than from an alert.' }),
    can('alert:read') ? el('a', { href: '#/alerts', text: 'All alerts →' }) : null,
  ]);
}

function deviceContainment(incident) {
  // Offered, never forced: moving an incident to CONTAINED is a statement about the response,
  // and only the operator knows whether revoking the device credential is the right step.
  if (incident.entity_type !== 'Device' || !incident.entity_id || !can('device:contain')
      || ['RESOLVED', 'CLOSED'].includes(incident.status)) return null;
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Contain the device' }),
    el('p', { class: 'hint', text: 'Quarantining revokes the device credential so further '
      + 'telemetry is rejected, and marks this incident contained.' }),
    el('div', { class: 'row' }, [
      el('button', { class: 'danger', text: 'Quarantine device', onClick: async () => {
        if (!confirmDialog('Quarantine this device? Its credential is revoked immediately.')) {
          return;
        }
        const reason = window.prompt('Reason for quarantine (written to the audit trail):',
          `Containment for incident ${incident.id.slice(0, 8)}`);
        if (!reason) return;
        try {
          await api(`/devices/${incident.entity_id}/quarantine`, { method: 'POST',
            body: { reason } });
          toast('Device quarantined', 'ok');
          refreshView();
        } catch (error) { toast(error.message, 'error'); }
      } }),
      el('a', { href: `#/device/${incident.entity_id}`, text: 'Open device' }),
    ]),
  ]);
}

function updateCard(id, incident, assignee) {
  const me = session.read()?.id;
  const rootCause = el('textarea', { placeholder: 'Root cause, once determined' });
  rootCause.value = incident.root_cause || '';
  const notes = el('textarea', { placeholder: 'What was done or found. Saved to the timeline '
    + 'with your name.' });
  const message = el('div', { class: 'error-text', role: 'alert' });

  async function patch(body, done) {
    message.textContent = '';
    try {
      await api(`/security/incidents/${id}`, { method: 'PATCH', body });
      toast(done, 'ok');
      // The note is now an incident event, shown in the timeline once the view refreshes.
      refreshView();
    } catch (error) {
      // Leave whatever was typed in place so a failed save loses nothing.
      message.textContent = error.message;
    }
  }

  function payload(extra = {}) {
    const body = { ...extra };
    const note = notes.value.trim();
    const cause = rootCause.value.trim();
    if (note) body.note = note;
    if (cause && cause !== (incident.root_cause || '')) body.root_cause = cause;
    return body;
  }

  const statusButtons = (NEXT_STATUS[incident.status] || []).map(([status, label]) =>
    el('button', { class: status === 'RESOLVED' ? 'primary' : '', text: label,
      onClick: () => patch(payload({ status }), `Incident marked ${status.toLowerCase()}`) }));

  const assignButtons = [];
  if (me && assignee?.id !== me) {
    assignButtons.push(el('button', { text: 'Assign to me',
      onClick: () => patch(payload({ assignee_id: me }), 'Incident assigned to you') }));
  }
  if (assignee) {
    assignButtons.push(el('button', { text: 'Unassign',
      onClick: () => patch(payload({ assignee_id: '' }), 'Incident unassigned') }));
  }

  return el('div', { class: 'card' }, [
    el('h2', { text: 'Update incident' }),
    field('Notes', notes),
    field('Root cause', rootCause),
    message,
    el('div', { class: 'row' }, [
      el('button', { text: 'Add note', onClick: () => {
        if (!notes.value.trim() && rootCause.value.trim() === (incident.root_cause || '')) {
          message.textContent = 'Write a note or a root cause first.';
          return;
        }
        patch(payload(), 'Saved to the timeline');
      } }),
      ...statusButtons,
    ]),
    statusButtons.length ? null : el('p', { class: 'hint',
      text: 'This incident is closed; no further status change is possible.' }),
    assignButtons.length ? el('div', { class: 'row u-m-12-0' }, assignButtons) : null,
  ]);
}

function readOnlyCard(incident) {
  const bio = BIOSAFETY_CATEGORIES.includes(incident.category);
  if (bio && can('biosecurity:review')) return null;   // handled by updateCard
  const parts = [el('h2', { text: 'Read-only' })];
  if (bio && can('biosecurity:read')) {
    parts.push(el('p', { class: 'hint', text: 'The screening behind this incident is released '
      + 'or upheld by a biosafety officer in the Review Queue.' }));
    if (incident.entity_type === 'SequenceScreening' && incident.entity_id) {
      parts.push(el('a', { href: `#/screening/${incident.entity_id}`, text: 'Open screening' }));
    }
  } else {
    parts.push(el('p', { class: 'hint', text: 'Updating incidents requires the incident:write '
      + 'permission held by security analysts. You can still act on the source record.' }));
  }
  return el('div', { class: 'card' }, parts);
}

export async function render({ id }) {
  if (!id) return empty('No incident selected', 'Choose an incident from the list.');
  const detail = await api(`/security/incidents/${id}`);
  const incident = detail.incident;
  const alerts = detail.alerts || [];
  const assignee = detail.assignee;
  const bio = BIOSAFETY_CATEGORIES.includes(incident.category);

  const facts = el('table', {}, [
    el('tr', {}, [rowHeader('About'),
      el('td', {}, [entityLink(incident.entity_type, incident.entity_id) || '—'])]),
    el('tr', {}, [rowHeader('Category'),
      el('td', { text: incident.category ? titleCase(incident.category) : '—' })]),
    el('tr', {}, [rowHeader('Assignee'),
      el('td', { text: assignee ? (assignee.name || assignee.id.slice(0, 8)) : 'Unassigned' })]),
  ]);

  return el('div', {}, [
    el('h1', { text: incidentTitle(incident.title) }),
    el('p', { class: 'subtitle' }, [badge(incident.severity), ' ', badge(incident.status),
      ' · opened ', fmtDate(incident.created_at)]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Summary' }),
      el('p', { text: humanizeText(incident.summary) || 'No summary recorded.' }),
      facts,
      incident.root_cause ? el('p', {}, [el('strong', { text: 'Root cause: ' }),
        incident.root_cause]) : null,
    ]),
    detail.can_update ? updateCard(id, incident, assignee) : readOnlyCard(incident),
    detail.can_update && bio && can('biosecurity:review')
      ? el('p', { class: 'hint' }, ['Releasing or upholding the screening itself is done in the ',
        el('a', { href: '#/review-queue', text: 'Review Queue' }), '.'])
      : null,
    deviceContainment(incident),
    alertsCard(alerts),
    el('div', { class: 'card' }, [el('h2', { text: 'Timeline' }), timelineList(detail.timeline)]),
    el('a', { href: '#/incidents', text: '← All incidents' }),
  ]);
}
