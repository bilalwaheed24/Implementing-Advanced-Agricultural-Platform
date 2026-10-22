import { session, el, api, badge, fmtDate, fmtNum, table, empty, toast, can, reasonList,
         rowHeader, titleCase, jurisdictionLabel, refreshView } from '/static/assets/core.js';
import { createPanel, choiceSelect, dateInput, todayIso, atNoon, remoteSelect }
  from '/static/views/formkit.js';

/* EPCIS business step -> the batch state it moves the batch into. Mirrors
 * `supplychain.BIZ_STEP_TO_STATE` on the server. */
const STEP_TO_STATE = {
  commissioning: 'CREATED', harvesting: 'HARVESTED', transforming: 'PROCESSED',
  packing: 'PACKAGED', shipping: 'IN_TRANSIT', receiving: 'RECEIVED',
  storing: 'STORED', retail_selling: 'RETAILED', recalling: 'RECALLED',
};

/* The legal transitions, mirroring `supplychain.BATCH_TRANSITIONS`. The server is the
 * authority and refuses an illegal move with 422 whether or not the ledger is reachable;
 * this only keeps the operator from being offered a step that cannot succeed. */
const BATCH_TRANSITIONS = {
  CREATED: ['HARVESTED', 'PROCESSED', 'IN_TRANSIT', 'RECALLED'],
  HARVESTED: ['PROCESSED', 'IN_TRANSIT', 'STORED', 'RECALLED'],
  PROCESSED: ['PACKAGED', 'IN_TRANSIT', 'STORED', 'RECALLED'],
  PACKAGED: ['IN_TRANSIT', 'STORED', 'RECALLED'],
  IN_TRANSIT: ['RECEIVED', 'STORED', 'RECALLED'],
  RECEIVED: ['PROCESSED', 'PACKAGED', 'IN_TRANSIT', 'STORED', 'RETAILED', 'RECALLED'],
  STORED: ['IN_TRANSIT', 'PROCESSED', 'PACKAGED', 'RETAILED', 'RECALLED'],
  RETAILED: ['CONSUMED', 'RECALLED'],
  CONSUMED: [],
  RECALLED: [],
};

const DISPOSITIONS = [
  ['in_progress', 'In progress'],
  ['in_transit', 'In transit'],
  ['in_storage', 'In storage'],
  ['sellable_accessible', 'Sellable'],
  ['recalled', 'Recalled'],
];

function recordEventPanel(batch, reload) {
  const reachable = BATCH_TRANSITIONS[batch.state] || [];
  const steps = Object.entries(STEP_TO_STATE)
    .filter(([, state]) => reachable.includes(state))
    .map(([step, state]) => [step, `${titleCase(step)} → ${titleCase(state)}`]);

  if (!steps.length) {
    return el('p', { class: 'hint',
      text: `This batch is ${titleCase(batch.state)}, which is a final state. No further `
        + 'custody event can be recorded.' });
  }

  const step = choiceSelect(steps);
  const disposition = choiceSelect(DISPOSITIONS);
  // The usual disposition for each step, so a shipment is not left marked "in progress".
  const USUAL = { shipping: 'in_transit', receiving: 'in_storage', storing: 'in_storage',
    retail_selling: 'sellable_accessible', recalling: 'recalled' };
  const syncDisposition = () => { disposition.value = USUAL[step.value] || 'in_progress'; };
  step.addEventListener('change', syncDisposition);
  syncDisposition();
  const locationName = el('input', { maxlength: '200', placeholder: 'e.g. Ames Processing' });
  const locationGln = el('input', { maxlength: '13', placeholder: 'optional GLN (13 digits)' });
  const quantity = el('input', { type: 'number', step: 'any', min: '0',
    value: String(batch.quantity) });
  const unit = el('input', { maxlength: '12', value: batch.unit });
  const occurred = dateInput(todayIso(), { required: 'required' });
  // Shipping the batch to another organisation transfers custody to it: the receiver then
  // sees the batch and records its receipt; this organisation keeps read access only.
  const handOver = remoteSelect({
    endpoint: '/admin/organizations/directory', required: false,
    filter: (org) => org.id !== session.read()?.org_id && org.org_type !== 'REGULATOR',
    label: (org) => `${org.name} (${titleCase(org.org_type)})`,
    placeholder: 'Keep custody (no hand-over)',
    emptyLabel: 'No trading partner registered',
  });

  return createPanel({
    toggleLabel: 'Record a custody event',
    submitLabel: 'Record event',
    hint: `This batch is ${titleCase(batch.state)}. Only the steps it can legally move to are `
      + 'listed. Quantity may fall but never rise — the server enforces conservation. To pass '
      + 'the batch on, choose Shipping and the organisation receiving it.',
    controls: [
      ['Business step', step],
      ['Disposition', disposition],
      ['Location name', locationName],
      ['Location GLN', locationGln],
      ['Quantity', quantity],
      ['Unit', unit],
      ['Occurred on', occurred],
      ['Hand over to', handOver],
    ],
    submit: async () => {
      await api('/supply-chain/events', { method: 'POST', body: {
        batch_id: batch.id, biz_step: step.value, disposition: disposition.value,
        location_name: locationName.value || null,
        location_gln: locationGln.value || null,
        quantity: quantity.value === '' ? null : Number(quantity.value),
        unit: unit.value || null,
        occurred_at: atNoon(occurred.value),
        to_org_id: handOver.value || null,
      } });
      const receiver = handOver.value ? handOver.selectedOptions[0]?.text : null;
      return receiver
        ? `Batch handed over to ${receiver} — they now hold it and have been notified`
        : `Event recorded — batch is now ${titleCase(STEP_TO_STATE[step.value])}`;
    },
    onDone: reload,
  });
}

/* The certifications issued to this organisation that it may claim on the batch. */
function claimPanel(batch, claimed, hasGmo, reload) {
  const me = session.read()?.org_id;
  const certification = remoteSelect({
    endpoint: '/supply-chain/certifications',
    // Organic and non-GMO claims are refused on GMO lineage, so they are not offered there.
    filter: (row) => row.subject_org_id === me && row.status === 'ACTIVE'
      && !claimed.has(row.cert_code)
      && !(hasGmo && ['ORGANIC', 'NON_GMO'].includes(row.cert_type)),
    label: (row) => `${row.cert_code} — ${titleCase(row.cert_type)}, ${row.standard}`,
    placeholder: 'Select one of your certifications',
    emptyLabel: 'No unclaimed active certification issued to your organisation',
  });
  return createPanel({
    toggleLabel: 'Claim a certification',
    submitLabel: 'Claim on this batch',
    hint: 'Only a certification issued to your organisation can be claimed. An organic or '
      + 'non-GMO claim is refused when the batch has GMO lineage.',
    controls: [['Certification', certification]],
    submit: async () => {
      await api(`/supply-chain/certifications/${certification.value}/link`,
        { method: 'POST', body: { batch_id: batch.id } });
      return 'Certification claimed — it now appears on the public verification page';
    },
    onDone: reload,
  });
}

/* A printable product label: the QR a consumer scans, with the code typed underneath. */
function labelCard(batch, context) {
  const label = el('div', { class: 'qr-label print-area' }, [
    el('img', { src: `/api/v1/verify/${batch.verification_code}/qr`, alt: 'Verification QR code',
      class: 'qr-image' }),
    el('div', {}, [
      el('strong', { text: context.product?.name || batch.batch_code }),
      el('div', { class: 'hint', text: `Batch ${batch.batch_code}` }),
      el('div', { class: 'mono', text: batch.verification_code }),
      el('div', { class: 'hint', text: 'Scan to verify origin, GMO status and certifications' }),
    ]),
  ]);
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Consumer label' }),
    label,
    el('div', { class: 'row u-mt-8' }, [
      el('button', { class: 'primary', text: 'Print label', onClick: () => window.print() }),
      el('a', { href: `/verify.html?code=${batch.verification_code}`, target: '_blank',
        rel: 'noopener', text: 'Open what the consumer sees ↗' }),
    ]),
  ]);
}

function gmoCell(gmo) {
  if (!gmo) return el('td', { text: 'No GMO lineage' });
  const approvals = gmo.approvals.length
    ? gmo.approvals.map((a) => `${jurisdictionLabel(a.jurisdiction)}: ${titleCase(a.status)}`
      + (a.expires_at ? ` until ${fmtDate(a.expires_at)}` : '')).join(' · ')
    : 'no approval on record';
  return el('td', {}, [
    el('div', {}, [el('span', { class: 'mono', text: gmo.event_code }),
      ` — ${gmo.crop_type}, ${gmo.trait}`]),
    el('div', { class: 'hint', text: `Developer ${gmo.developer}. ${approvals}` }),
  ]);
}

export async function render({ id }) {
  if (!id) return empty('No batch selected', 'Choose a batch from the list.');
  const [batch, custody] = await Promise.all([
    api(`/supply-chain/batches/${id}`),
    api(`/supply-chain/batches/${id}/custody`),
  ]);
  const context = custody.context || {};
  const orgName = (orgId) => (context.organisations || {})[orgId] || 'another organisation';
  const me = session.read()?.org_id;
  const holdsIt = batch.custodian_org_id === me;
  const isParty = holdsIt || context.owner?.id === me;

  const timeline = el('ul', { class: 'timeline' }, custody.events.map((event) =>
    el('li', { class: event.anchor_status === 'ANCHORED' ? '' : 'unverified' }, [
      el('div', {}, [
        el('strong', { text: titleCase(event.biz_step) }),
        ' — ', el('span', { class: 'hint', text: titleCase(event.disposition) }),
      ]),
      el('div', { class: 'when', text: fmtDate(event.occurred_at) }),
      event.location_name ? el('div', { class: 'hint', text: event.location_name }) : null,
      event.to_org_id && event.to_org_id !== event.from_org_id
        ? el('div', { class: 'hint',
          text: `Handed over: ${orgName(event.from_org_id)} → ${orgName(event.to_org_id)}` })
        : null,
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
            result.fabric_status ? el('span', { class: 'hint', text: 'Hyperledger Fabric:' }) : null,
            result.fabric_status ? badge(result.fabric_status) : null,
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
      // Labelled so "Unverified" next to "Anchored" reads as two separate checks.
      badge(batch.state), ' ', el('span', { class: 'hint', text: 'integrity' }), ' ',
      badge(batch.integrity_status), ' ', el('span', { class: 'hint', text: 'ledger' }), ' ',
      badge(batch.anchor_status),
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
            el('tr', {}, [rowHeader('Product'),
              el('td', { text: context.product
                ? `${context.product.name} (GTIN ${context.product.gtin})` : '—' })]),
            el('tr', {}, [rowHeader('Quantity'),
              el('td', { text: `${fmtNum(batch.quantity)} ${batch.unit}` })]),
            el('tr', {}, [rowHeader('Produced by'),
              el('td', { text: context.owner?.name || '—' })]),
            el('tr', {}, [rowHeader('Held by'),
              el('td', {}, [context.custodian?.name || '—',
                holdsIt ? el('span', { class: 'hint', text: ' (your organisation)' }) : null])]),
            el('tr', {}, [rowHeader('Grown at'),
              el('td', { text: context.farm
                ? `${context.farm.name}, ${context.farm.region} ${context.farm.country}` : '—' })]),
            el('tr', {}, [rowHeader('Origin'),
              el('td', { text: batch.origin_region
                ? `${batch.origin_region}, ${batch.origin_country}` : '—' })]),
            el('tr', {}, [rowHeader('Harvested'),
              el('td', { text: fmtDate(batch.harvested_at) })]),
            el('tr', {}, [rowHeader('GMO lineage'), gmoCell(context.gmo)]),
            el('tr', {}, [rowHeader('Ledger transaction'),
              el('td', { class: 'mono', text: batch.tx_id ? batch.tx_id.slice(0, 24) + '…' : '—' })]),
          ]),
        ]),
        labelCard(batch, context),
        el('div', { class: 'card' }, [
          el('h2', { text: 'Certifications' }),
          certifications,
          can('supply:write') && isParty
            ? claimPanel(batch, new Set(custody.certifications.map((c) => c.cert_code)),
              Boolean(context.gmo), () => refreshView())
            : null,
        ]),
        can('supply:write') ? el('div', { class: 'card' }, [
          el('h2', { text: 'Record the next step' }),
          holdsIt
            ? recordEventPanel(batch, () => refreshView())
            : el('p', { class: 'hint', text: `${context.custodian?.name || 'Another organisation'} `
              + 'holds this batch now, so only they can record its next step. You keep read '
              + 'access to its history.' }),
        ]) : null,
        can('supply:verify') ? el('div', { class: 'card' }, [
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
