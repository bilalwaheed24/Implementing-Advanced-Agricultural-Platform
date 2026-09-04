import { el, api, badge, fmtDate, fmtNum, table, toast, can, empty, lineChart,
         confirmDialog,
         titleCase } from '/static/assets/core.js';

async function containmentAction(id, action, promptText) {
  const reason = window.prompt(promptText);
  if (!reason) return false;
  await api(`/devices/${id}/${action}`, { method: 'POST', body: { reason } });
  return true;
}

export async function render({ id }) {
  if (!id) return empty('No device selected', 'Choose a device from the list.');
  const [device, series, vulns] = await Promise.all([
    api(`/devices/${id}`),
    api(`/telemetry/devices/${id}/series?hours=48`),
    api(`/devices/vulnerabilities?device_id=${id}`).catch(() => ({ items: [] })),
  ]);

  const actions = [];
  if (can('device:write') && device.status === 'PROVISIONED') {
    actions.push(el('button', { class: 'primary', text: 'Activate', onClick: async () => {
      await api(`/devices/${id}/activate`, { method: 'POST' });
      window.location.reload();
    } }));
  }
  if (can('device:write') && device.status === 'ACTIVE') {
    actions.push(el('button', { text: 'Rotate secret', onClick: async () => {
      const result = await api(`/devices/${id}/rotate-secret`, { method: 'POST' });
      window.prompt('New device secret (shown once — copy it now):', result.device_secret);
    } }));
  }
  if (can('device:contain') && ['ACTIVE', 'SUSPENDED'].includes(device.status)) {
    actions.push(el('button', { class: 'danger', text: 'Quarantine', onClick: async () => {
      if (!confirmDialog('Quarantine this device? Its credential will be revoked immediately '
        + 'and further telemetry will be rejected. This is a containment action.')) return;
      try {
        if (await containmentAction(id, 'quarantine',
          'Reason for quarantine (written to the audit trail):')) {
          toast('Device quarantined', 'ok');
          window.location.reload();
        }
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (can('device:contain') && device.status !== 'RETIRED') {
    actions.push(el('button', { text: 'Retire', onClick: async () => {
      if (!confirmDialog('Retire this device permanently?')) return;
      try {
        if (await containmentAction(id, 'retire', 'Reason for retirement:')) {
          toast('Device retired', 'ok');
          window.location.reload();
        }
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }

  const chartKey = Object.keys(series.points[0] || {}).find((key) =>
    !['recorded_at', 'anomaly_score', 'quality'].includes(key));

  return el('div', {}, [
    el('h1', { text: `Device ${titleCase(device.device_type)}` }),
    el('p', { class: 'subtitle mono', text: device.id }),
    device.quarantine_reason ? el('div', { class: 'card', role: 'alert' }, [
      el('strong', { text: 'Quarantined: ' }), device.quarantine_reason,
    ]) : null,
    el('div', { class: 'grid cols-4' }, [
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Status' }),
        el('div', { class: 'u-mt-6' }, [badge(device.status)])]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Firmware' }),
        el('div', { class: 'value mono u-fs-16', text: device.firmware_version })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Battery' }),
        el('div', { class: 'value', text: device.battery_pct === null ? '—'
          : `${fmtNum(device.battery_pct, 0)}%` })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Auth failures' }),
        el('div', { class: 'value', text: device.auth_failures })]),
    ]),
    el('div', { class: 'row u-m-12-0' }, actions),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Telemetry, last 48 hours' }),
      series.points.length && chartKey
        ? lineChart(series.points, { valueKey: chartKey, label: chartKey, threshold: null })
        : empty('No telemetry', 'This device has not reported yet.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Anomaly score' }),
      series.points.some((p) => p.anomaly_score !== null)
        ? lineChart(series.points, { valueKey: 'anomaly_score', label: 'anomaly score',
          threshold: 0.65 })
        : empty('No scored readings', 'Anomaly scoring may be deferred; see AI Insights.'),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Vulnerabilities' }),
      vulns.items.length ? table([
        { label: 'CVE', key: 'cve_id' }, { label: 'Title', key: 'title' },
        { label: 'Severity', render: (row) => badge(row.severity) },
        { label: 'Status', render: (row) => badge(row.status) },
      ], vulns.items) : empty('No known vulnerabilities', 'Nothing recorded against this device.'),
    ]),
    el('a', { href: '#/devices', text: '← All devices' }),
  ]);
}
