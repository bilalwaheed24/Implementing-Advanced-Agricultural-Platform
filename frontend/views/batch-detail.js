import { session, el, api, badge, fmtDate, fmtDay, fmtNum, table, empty, toast, can, reasonList,
         rowHeader, titleCase, humanize, jurisdictionLabel, refreshView, confirmDialog }
  from '/static/assets/core.js';
import { createPanel, choiceSelect, dateInput, todayIso, atNoon, remoteSelect }
  from '/static/views/formkit.js';
import { shipmentForm, arriveControl, coldChainCell } from '/static/views/shipments.js';

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

function recordEventPanel(batch, reload, { only = null } = {}) {
  const reachable = BATCH_TRANSITIONS[batch.state] || [];
  const steps = Object.entries(STEP_TO_STATE)
    .filter(([step, state]) => reachable.includes(state) && (!only || only.includes(step)))
    .map(([step, state]) => [step, `${humanize(step)} → ${humanize(state)}`]);

  if (!steps.length) {
    return el('p', { class: 'hint',
      text: `This batch is ${humanize(batch.state)}, which is a final state. No further `
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
  // Not in the future, and not before the batch's last step: the server refuses both and says
  // which date to choose.
  const occurred = dateInput(todayIso(), { required: 'required', max: todayIso() });
  // Handing the batch to another organisation is done with a shipment (Shipments card): the
  // shipment records the shipping event and moves custody in one step, so the two cannot
  // fall out of order.

  return createPanel({
    toggleLabel: 'Record a custody event',
    submitLabel: 'Record event',
    hint: `This batch is ${humanize(batch.state)}. Only the steps it can legally move to are `
      + 'listed. Quantity may fall but never rise — the server enforces conservation. To pass '
      + 'the batch to another organisation, create a shipment in the Shipments card.',
    controls: [
      ['Business step', step],
      ['Disposition', disposition],
      ['Location name', locationName],
      ['Location GLN', locationGln],
      ['Quantity', quantity],
      ['Unit', unit],
      ['Occurred on', occurred],
    ],
    submit: async () => {
      await api('/supply-chain/events', { method: 'POST', body: {
        batch_id: batch.id, biz_step: step.value, disposition: disposition.value,
        location_name: locationName.value || null,
        location_gln: locationGln.value || null,
        quantity: quantity.value === '' ? null : Number(quantity.value),
        unit: unit.value || null,
        occurred_at: atNoon(occurred.value),
      } });
      return `Event recorded — batch is now ${humanize(STEP_TO_STATE[step.value])}`;
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
    label: (row) => `${row.cert_code} — ${humanize(row.cert_type)}, ${row.standard}`,
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

/* The owner answers for a batch after handing it over, so both the owner and the current
 * holder may recall it. The server notifies the whole lineage and flags derived batches. */
function recallControl(batch) {
  if (!(BATCH_TRANSITIONS[batch.state] || []).includes('RECALLED')) return null;
  const button = el('button', { class: 'danger', text: 'Recall this batch', onClick: async () => {
    if (!confirmDialog(`Recall batch ${batch.batch_code}? This is final. Every organisation in `
      + 'its lineage is notified and batches made from it are flagged.')) return;
    button.disabled = true;
    try {
      await api('/supply-chain/events', { method: 'POST', body: {
        batch_id: batch.id, biz_step: 'recalling', disposition: 'recalled',
        occurred_at: new Date().toISOString() } });
      toast(`Batch ${batch.batch_code} recalled — its lineage has been notified`, 'ok');
      refreshView();
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  } });
  return el('div', { class: 'u-mt-12' }, [
    el('p', { class: 'hint', text: 'Recalling notifies the owner, the holder and every '
      + 'organisation with a parent or derived batch, and marks derived batches suspect.' }),
    button,
  ]);
}

/* Where "back" goes. A certifier reaches a batch from Certifications, Compliance or a
 * notification and has no Batches page in its menu, so it goes back where it came from. */
function backLink(readOnly) {
  if (!readOnly) return el('a', { href: '#/batches', text: '← All batches' });
  return el('a', { href: '#/certifications', text: '← Back',
    onClick: (event) => {
      if (window.history.length > 1) {
        event.preventDefault();
        window.history.back();
      }
    } });
}

/* Every shipment of this batch the reader may see (the API lists all of them to anyone who
 * can read the batch), with the receiver's action. */
function shipmentsCard(batch, shipments, holdsIt, { readOnly, shipped }) {
  let none = empty('No shipments', 'This batch has not been shipped yet.');
  if (shipped) {
    // The chain of custody records a shipping event, so "not shipped" would be false.
    none = empty('No shipment details', 'The chain of custody records this batch being '
      + 'shipped, but the shipment details are not shared with your organisation.');
  }
  const rows = shipments.length
    ? table([
      { label: 'SSCC', render: (row) => (readOnly
        ? el('span', { class: 'mono', text: row.sscc })
        : el('a', { href: '#/shipments', class: 'mono', text: row.sscc })) },
      { label: 'Route', render: (row) => `${row.origin_name} → ${row.destination_name}` },
      { label: 'Departed', render: (row) => fmtDate(row.departed_at) },
      { label: 'Status', render: (row) => el('div', {}, [badge(row.status),
        row.arrived_at ? el('div', { class: 'hint', text: fmtDate(row.arrived_at) })
          : arriveControl(row, () => refreshView())]) },
      { label: 'Cold chain', render: (row) => coldChainCell(row) },
    ], shipments)
    : none;
  const canShip = !readOnly && holdsIt && can('supply:write')
    && (BATCH_TRANSITIONS[batch.state] || []).includes('IN_TRANSIT');
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Shipments' }),
    rows,
    canShip ? shipmentForm({ batch, reload: () => refreshView(),
      toggleLabel: 'Ship or hand over this batch' }) : null,
  ]);
}

/* A printable product label: the QR a consumer scans, with the code typed underneath. */
/* Every reader sees the label (its QR code is what a consumer scans), but only the
 * organisation holding the goods is offered to print it: labelling is the holder's job, not
 * an oversight role's, a certifier's or the producer's after a hand-over (round 6). */
function labelCard(batch, context, { canPrint = false } = {}) {
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
      canPrint
        ? el('button', { class: 'primary', text: 'Print label', onClick: () => window.print() })
        : null,
      el('a', { href: `/verify.html?code=${batch.verification_code}`, target: '_blank',
        rel: 'noopener', text: 'Open what the consumer sees ↗' }),
    ]),
  ]);
}

function gmoCell(gmo) {
  if (!gmo) return el('td', { text: 'No GMO lineage' });
  const approvals = gmo.approvals.length
    ? gmo.approvals.map((a) => `${jurisdictionLabel(a.jurisdiction)}: ${humanize(a.status)}`
      + (a.expires_at ? ` until ${fmtDay(a.expires_at)}` : '')).join(' · ')
    : 'no approval on record';
  return el('td', {}, [
    el('div', {}, [el('span', { class: 'mono', text: gmo.event_code }),
      ` — ${gmo.crop_type}, ${gmo.trait}`]),
    el('div', { class: 'hint', text: `Developer ${gmo.developer}. ${approvals}` }),
  ]);
}

export async function render({ id }) {
  if (!id) return empty('No batch selected', 'Choose a batch from the list.');
  let batch;
  let custody;
  let shipments;
  try {
    [batch, custody, shipments] = await Promise.all([
      api(`/supply-chain/batches/${id}`),
      api(`/supply-chain/batches/${id}/custody`),
      api(`/supply-chain/shipments?batch_id=${encodeURIComponent(id)}&page_size=50`)
        .then((page) => page.items || []).catch(() => []),
    ]);
  } catch (error) {
    // A link from a notification or a report can outlive the reader's access (the batch has
    // been handed on since): say so plainly rather than showing a raw error.
    if (error.status !== 404) throw error;
    return el('div', {}, [
      empty('Batch not available', 'Your organisation cannot open this batch. It may have '
        + 'been handed on to another organisation since this link was created.'),
      backLink(session.read()?.role === 'CERTIFIER'),
    ]);
  }
  const context = custody.context || {};
  const orgName = (orgId) => (context.organisations || {})[orgId] || 'another organisation';
  const me = session.read()?.org_id;
  const holdsIt = batch.custodian_org_id === me;
  const isParty = holdsIt || context.owner?.id === me;
  // Why this reader sees the batch (the API says; inferred for an older server). A reader
  // who sees it only because it carries their certificate gets no action they cannot
  // perform: verifying, recording, shipping, claiming and recalling are the parties' (or an
  // oversight role's) to do, and the API refuses them to anyone else.
  const access = batch.viewer_access || (isParty ? 'party' : 'certificate');
  const readOnly = access === 'certificate';
  const isOwner = context.owner?.id === me;
  // Handed to this organisation but still on the road: it is the custodian on record, yet the
  // goods have not reached it. Until it marks them arrived it is offered only that (and the
  // owner keeps its recall), not custody steps, certificate claims or the label (round 6).
  const inTransitToMe = holdsIt && batch.state === 'IN_TRANSIT';
  const openShipmentToMe = shipments.some((row) => row.status === 'IN_TRANSIT'
    && (row.to_org_id || row.org_id) === me);
  const recall = isParty && (!inTransitToMe || isOwner) ? recallControl(batch) : null;
  let nextStep = null;
  if (holdsIt && inTransitToMe) {
    nextStep = openShipmentToMe
      ? el('p', { class: 'hint', text: 'This batch is in transit to you. Mark its shipment '
        + 'arrived in the Shipments card when the goods reach you; its next steps can be '
        + 'recorded after that.' })
      // Shipped by a bare shipping event, with no shipment to mark arrived: book it in here.
      : recordEventPanel(batch, () => refreshView(), { only: ['receiving', 'storing'] });
  } else if (holdsIt) {
    nextStep = recordEventPanel(batch, () => refreshView());
  }
  const shipped = custody.events.some((event) => event.biz_step === 'shipping');

  const timeline = el('ul', { class: 'timeline' }, custody.events.map((event) =>
    el('li', { class: event.anchor_status === 'ANCHORED' ? '' : 'unverified' }, [
      el('div', {}, [
        el('strong', { text: humanize(event.biz_step) }),
        ' — ', el('span', { class: 'hint', text: humanize(event.disposition) }),
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
      { label: 'Type', render: (row) => humanize(row.cert_type) },
      { label: 'Standard', key: 'standard' },
      { label: 'Issuer', key: 'issuer' },
      { label: 'Valid to', render: (row) => fmtDay(row.valid_to) },
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
        toast(`Integrity: ${humanize(result.integrity_status).toLowerCase()}`,
          result.integrity_status === 'VERIFIED' ? 'ok' : 'error');
        verifyResult.replaceChildren(el('div', { class: 'card u-mt-12' }, [
          el('div', { class: 'row' }, [
            badge(result.integrity_status), badge(result.ledger_status),
            result.fabric_status ? el('span', { class: 'hint', text: 'Hyperledger Fabric:' }) : null,
            result.fabric_status ? badge(result.fabric_status) : null,
            el('span', { class: 'hint',
              text: `fraud score ${result.fraud_score} `
                + `(${humanize(result.fraud_level).toLowerCase()})` }),
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
    readOnly ? el('p', { class: 'hint', text: 'Read-only: you can see this batch because it '
      + 'carries your certificate.' }) : null,
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
              inTransitToMe ? el('td', { text: 'In transit to you' })
                : el('td', {}, [context.custodian?.name || '—',
                  holdsIt ? el('span', { class: 'hint', text: ' (your organisation)' }) : null])]),
            el('tr', {}, [rowHeader('Grown at'),
              el('td', { text: context.farm
                ? `${context.farm.name}, ${context.farm.region} ${context.farm.country}` : '—' })]),
            el('tr', {}, [rowHeader('Origin'),
              el('td', { text: batch.origin_region
                ? `${batch.origin_region}, ${batch.origin_country}` : '—' })]),
            el('tr', {}, [rowHeader('Harvested'),
              el('td', { text: fmtDay(batch.harvested_at) })]),
            el('tr', {}, [rowHeader('GMO lineage'), gmoCell(context.gmo)]),
            el('tr', {}, [rowHeader('Ledger transaction'),
              el('td', { class: 'mono', text: batch.tx_id ? batch.tx_id.slice(0, 24) + '…' : '—' })]),
          ]),
        ]),
        shipmentsCard(batch, shipments, holdsIt, { readOnly, shipped }),
        labelCard(batch, context, { canPrint: holdsIt && !inTransitToMe && !readOnly }),
        el('div', { class: 'card' }, [
          el('h2', { text: 'Certifications' }),
          certifications,
          can('supply:write') && isParty && !readOnly && !inTransitToMe
            ? claimPanel(batch, new Set(custody.certifications.map((c) => c.cert_code)),
              Boolean(context.gmo), () => refreshView())
            : null,
        ]),
        can('supply:write') && !readOnly ? el('div', { class: 'card' }, [
          el('h2', { text: 'Record the next step' }),
          holdsIt
            ? nextStep
            : el('p', { class: 'hint', text: `${context.custodian?.name || 'Another organisation'} `
              + 'holds this batch now, so only they can record its next step. You keep read '
              // The recall sentence only where the Recall button is actually offered.
              + `access to its history${recall ? ', and you can still recall it' : ''}.` }),
          recall,
        ]) : null,
        // The verify endpoint is open to the batch's parties and oversight roles only.
        can('supply:verify') && !readOnly ? el('div', { class: 'card' }, [
          el('h2', { text: 'Supply-chain integrity and fraud scoring' }),
          el('p', { class: 'hint', text: 'Runs deterministic fraud rules plus an anomaly '
            + 'model, and cross-checks every anchored record against the ledger.' }),
          verifyButton, verifyResult,
        ]) : null,
      ]),
    ]),
    backLink(readOnly),
  ]);
}
