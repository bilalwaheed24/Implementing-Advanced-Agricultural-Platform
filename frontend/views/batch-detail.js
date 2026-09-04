import { el, api, badge, fmtDate, fmtNum, table, empty, toast, can, reasonList,
         rowHeader, titleCase } from '/static/assets/core.js';

export async function render({ id }) {
  if (!id) return empty('No batch selected', 'Choose a batch from the list.');
  const [batch, custody] = await Promise.all([
    api(`/supply-chain/batches/${id}`),
    api(`/supply-chain/batches/${id}/custody`),
  ]);

  const timeline = el('ul', { class: 'timeline' }, custody.events.map((event) =>
    el('li', { class: event.anchor_status === 'ANCHORED' ? '' : 'unverified' }, [
      el('div', {}, [
        el('strong', { text: titleCase(event.biz_step) }),
        ' — ', el('span', { class: 'hint', text: event.disposition }),
      ]),
      el('div', { class: 'when', text: fmtDate(event.occurred_at) }),
      event.location_name ? el('div', { class: 'hint', text: event.location_name }) : null,
      el('div', { class: 'row u-mt-4' }, [
        badge(event.anchor_status),
        event.quantity !== null
          ? el('span', { class: 'hint', text: `${fmtNum(event.quantity)} ${event.unit || ''}` })
          : null,
      ]),
    ])));

  const certifications = custody.certifications.length
    ? table([
      { label: 'Certification', key: 'cert_code' },
      { label: 'Type', render: (row) => titleCase(row.cert_type) },
      { label: 'Standard', key: 'standard' },
      { label: 'Issuer', key: 'issuer' },
      { label: 'Valid to', render: (row) => fmtDate(row.valid_to) },
      { label: 'Authentic', render: (row) => row.authentic
        ? badge('VERIFIED') : badge('FAILED') },
    ], custody.certifications)
    : empty('No certifications claimed', 'No certification is linked to this batch.');

  const verifyResult = el('div');
  const verifyButton = el('button', { class: 'primary', text: 'Run integrity verification',
    onClick: async () => {
      verifyButton.disabled = true;
      verifyButton.textContent = 'Verifying…';
      try {
        const result = await api(`/supply-chain/batches/${id}/verify`, { method: 'POST' });
        toast(`Integrity ${result.integrity_status}`,
          result.integrity_status === 'VERIFIED' ? 'ok' : 'error');
        verifyResult.replaceChildren(el('div', { class: 'card u-mt-12' }, [
          el('div', { class: 'row' }, [
            badge(result.integrity_status), badge(result.ledger_status),
            el('span', { class: 'hint',
              text: `fraud score ${result.fraud_score} (${result.fraud_level})` }),
          ]),
          reasonList(result.reasons),
        ]));
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        verifyButton.disabled = false;
        verifyButton.textContent = 'Run integrity verification';
      }
    } });

  return el('div', {}, [
    el('h1', { text: `Batch ${batch.batch_code}` }),
    el('p', { class: 'subtitle' }, [
      badge(batch.state), ' ', badge(batch.integrity_status), ' ', badge(batch.anchor_status),
      ' · ', el('a', { href: `/verify.html?code=${batch.verification_code}`, target: '_blank',
        rel: 'noopener', text: 'Public verification page ↗' }),
    ]),
    el('div', { class: 'grid cols-2' }, [
      el('div', { class: 'card' }, [
        el('h2', { text: 'Chain of custody' }),
        custody.events.length ? timeline
          : empty('No events recorded', 'No supply-chain events have been recorded yet.'),
      ]),
      el('div', {}, [
        el('div', { class: 'card' }, [
          el('h2', { text: 'Details' }),
          el('table', {}, [
            el('tr', {}, [rowHeader('Quantity'),
              el('td', { text: `${fmtNum(batch.quantity)} ${batch.unit}` })]),
            el('tr', {}, [rowHeader('Origin'),
              el('td', { text: batch.origin_region
                ? `${batch.origin_region}, ${batch.origin_country}` : '—' })]),
            el('tr', {}, [rowHeader('Harvested'),
              el('td', { text: fmtDate(batch.harvested_at) })]),
            el('tr', {}, [rowHeader('GMO lineage'),
              el('td', { text: batch.gmo_event_id ? 'Yes' : 'No' })]),
            el('tr', {}, [rowHeader('Ledger transaction'),
              el('td', { class: 'mono', text: batch.tx_id ? batch.tx_id.slice(0, 24) + '…' : '—' })]),
          ]),
        ]),
        el('div', { class: 'card' }, [
          el('h2', { text: 'Certifications' }),
          certifications,
        ]),
        can('supply:read') ? el('div', { class: 'card' }, [
          el('h2', { text: 'Supply-chain integrity and fraud scoring' }),
          el('p', { class: 'hint', text: 'Runs deterministic fraud rules plus an anomaly '
            + 'model, and cross-checks every anchored record against the ledger.' }),
          verifyButton, verifyResult,
        ]) : null,
      ]),
    ]),
    el('a', { href: '#/batches', text: '← All batches' }),
  ]);
}
