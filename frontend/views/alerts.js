import { el, api, badge, fmtDate, humanizeText, titleCase, toast,
         can } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { entityLink, incidentLink } from '/static/views/entity-links.js';

async function alertAction(row, action, done, reload) {
  try {
    await api(`/security/alerts/${row.id}/${action}`, { method: 'POST' });
    toast(done, 'ok');
    reload();
  } catch (error) { toast(error.message, 'error'); }
}

function actionButtons(row, reload) {
  // Mirrors the server's alert lifecycle (notifications.ALERT_TRANSITIONS): an OPEN alert
  // may be acknowledged or resolved, an ACKNOWLEDGED one may still be resolved, and a
  // RESOLVED one is final. Only a principal holding alert:write is offered either.
  if (!can('alert:write') || row.status === 'RESOLVED') {
    return el('span', { class: 'hint', text: '—' });
  }
  const buttons = [];
  if (row.status === 'OPEN') {
    buttons.push(el('button', { text: 'Acknowledge',
      onClick: () => alertAction(row, 'acknowledge', 'Alert acknowledged', reload) }));
  }
  buttons.push(el('button', { text: 'Resolve', title: row.incident_id
    ? 'Resolving the last open alert on an incident also resolves the incident' : null,
    onClick: () => alertAction(row, 'resolve', 'Alert resolved', reload) }));
  return el('div', { class: 'row' }, buttons);
}

/* The reasons worth showing besides the detail line: those it does not already say. Most
 * alerts' detail is their first reasons joined, so a Reasons column of its own was "—" on
 * most rows; what is left is shown as one short line under the detail instead. */
function extraReasons(row) {
  const detail = String(row.detail || '').toLowerCase();
  const reasons = (row.reasons || [])
    .map((r) => (typeof r === 'string' ? r : r.rule || r.detail || ''))
    .filter((r) => r && !detail.includes(String(r).toLowerCase()));
  if (!reasons.length) return '';
  const first = humanizeText(String(reasons[0]));
  const short = first.length > 120 ? `${first.slice(0, 117)}…` : first;
  return reasons.length > 1 ? `${short} (+${reasons.length - 1} more)` : short;
}

function occurrenceHint(row) {
  if (!row.occurrences || row.occurrences < 2) return null;
  return el('div', { class: 'hint', text: `Seen ${row.occurrences} times, last `
    + `${fmtDate(row.last_seen_at)}` });
}

export const render = listView({
  title: 'Security and agronomy alerts',
  subtitle: 'Raised by AI scoring, deterministic rules and scheduled sweeps. '
    + 'Every alert carries the reasons that produced it. A condition that keeps recurring '
    + 'is counted on its open alert rather than raised again.',
  endpoint: '/security/alerts',
  filters: [
    { key: 'severity', label: 'Severity', options: ['INFO', 'WARNING', 'HIGH', 'CRITICAL'] },
    { key: 'status', label: 'Status', options: [['UNRESOLVED', 'Unresolved (open or acknowledged)'],
      'OPEN', 'ACKNOWLEDGED', 'RESOLVED'] },
    { key: 'category', label: 'Category', options: ['DEVICE_ANOMALY', 'DEVICE_HEALTH',
        'DEVICE_AUTH', 'DATA_THEFT', 'BIOSECURITY', 'DURC', 'FRAUD', 'COMPLIANCE',
        'CERTIFICATION', 'AGRONOMY'] },
    ],
  columns: [
    { label: 'Raised', render: (row) => el('div', {}, [fmtDate(row.created_at),
      occurrenceHint(row)]) },
    { label: 'Severity', render: (row) => badge(row.severity) },
    { label: 'Category', render: (row) => titleCase(row.category) },
    { label: 'Title', render: (row) => {
        const more = extraReasons(row);
        return el('div', {}, [
          el('strong', { text: row.title }),
          row.detail ? el('div', { class: 'hint', text: humanizeText(row.detail) }) : null,
          more ? el('div', { class: 'hint', text: `Also: ${more}` }) : null,
        ]);
      } },
    { label: 'Source', render: (row) => el('div', {}, [
        entityLink(row.entity_type, row.entity_id, row.source_label)
          || el('span', { class: 'hint', text: '—' }),
        row.incident_id ? el('div', {}, [incidentLink(row.incident_id,
          row.incident_label ? `Incident: ${row.incident_label}` : null)]) : null,
      ]) },
    { label: 'Status', render: (row) => badge(row.status) },
    { label: 'Actions', render: (row, ctx) => actionButtons(row, ctx.reload) },
  ],
  emptyTitle: 'No alerts',
  emptyMessage: 'Nothing has triggered an alert. Alerts appear here when a device, screening '
    + 'or supply-chain check needs attention.',
});
