import { el, api, badge, field, fmtDate, fmtPct, fmtNum, table, toast, can, reasonList,
         titleCase, empty } from '/static/assets/core.js';

export async function render({ id }) {
  if (!id) return empty('No screening selected', 'Choose a screening from the list.');
  const screening = await api(`/biosecurity/screenings/${id}`);

  const summary = el('div', { class: 'grid cols-4' }, [
    el('div', { class: 'tile' }, [
      el('div', { class: 'label', text: 'Verdict' }),
      el('div', { class: 'u-mt-6' }, [badge(screening.verdict)]),
    ]),
    el('div', { class: 'tile' }, [
      el('div', { class: 'label', text: 'Status' }),
      el('div', { class: 'u-mt-6' }, [badge(screening.status)]),
    ]),
    el('div', { class: 'tile' }, [
      el('div', { class: 'label', text: 'Max identity' }),
      el('div', { class: 'value', text: fmtPct(screening.max_identity, 1) }),
      el('div', { class: 'hint', text: `${screening.sequence_length} bases submitted` }),
    ]),
    el('div', { class: 'tile' }, [
      el('div', { class: 'label', text: 'Dual-use flag' }),
      el('div', { class: 'u-mt-6' }, [screening.durc_flag
        ? badge('CRITICAL') : badge('VERIFIED')]),
    ]),
  ]);

  const hits = screening.hits || [];
  const evidence = hits.length
    ? table([
      { label: 'Agent', key: 'agent_name' },
      { label: 'Hazard class', render: (row) => titleCase(row.hazard_class) },
      { label: 'Severity', numeric: true, render: (row) => badge(
        row.severity >= 5 ? 'CRITICAL' : row.severity >= 4 ? 'HIGH' : 'WARNING') },
      { label: 'Identity', numeric: true, render: (row) => fmtPct(row.identity, 1) },
      { label: 'Alignment', numeric: true, render: (row) => `${row.align_length} bp` },
      { label: 'Score', numeric: true, render: (row) => fmtNum(row.score, 0) },
      { label: 'Query span', render: (row) => el('span', { class: 'mono',
        text: `${row.query_start}–${row.query_end}` }) },
      { label: 'Subject span', render: (row) => el('span', { class: 'mono',
        text: `${row.subject_start}–${row.subject_end}` }) },
    ], hits)
    : empty('No significant homology',
      'No alignment met the reporting threshold against any hazard sequence.');

  const parts = [
    el('h1', { text: `Screening: ${screening.name}` }),
    el('p', { class: 'subtitle' }, [
      `Submitted ${fmtDate(screening.created_at)} · engine ${screening.engine_version} · `,
      el('span', { class: 'mono', text: `sequence SHA-256 ${screening.sequence_hash.slice(0, 24)}…` }),
    ]),
    summary,
    el('div', { class: 'card' }, [
      el('h2', { text: 'Why this verdict' }),
      reasonList(screening.reasons && screening.reasons.length
        ? screening.reasons
        : ['No stored rationale for this screening.']),
      el('p', { class: 'hint', text: 'The submitted sequence itself is encrypted at rest and '
        + 'is never returned by the API.' }),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Alignment evidence' }),
      el('p', { class: 'hint', text: 'Each row is the best local alignment against one '
        + 'hazard sequence, with the coordinates a reviewer needs to check it.' }),
      evidence,
    ]),
  ];

  if (screening.review_rationale) {
    parts.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Biosafety review' }),
      el('p', {}, [badge(screening.status), ` reviewed ${fmtDate(screening.reviewed_at)}`]),
      el('p', { text: screening.review_rationale }),
    ]));
  } else if (can('biosecurity:review')
      && ['PENDING_REVIEW', 'BLOCKED'].includes(screening.status)) {
    const rationale = el('textarea', { required: 'required', minlength: '10',
      placeholder: 'Record the reasoning for this decision. It is written to the audit trail.' });
    const message = el('div', { class: 'error-text', role: 'alert' });
    async function decide(decision) {
      if (rationale.value.trim().length < 10) {
        message.textContent = 'A rationale of at least 10 characters is required.';
        return;
      }
      try {
        await api(`/biosecurity/screenings/${screening.id}/review`, {
          method: 'POST', body: { decision, rationale: rationale.value.trim() },
        });
        toast(`Screening ${decision === 'APPROVE' ? 'approved' : 'rejected'}`, 'ok');
        window.location.reload();
      } catch (error) { message.textContent = error.message; }
    }
    parts.push(el('div', { class: 'card' }, [
      el('h2', { text: 'Biosafety review required' }),
      el('p', { class: 'hint', text: 'Only a biosafety officer can release a blocked record, '
        + 'and the decision is audit-logged with its rationale.' }),
      field('Rationale', rationale),
      message,
      el('div', { class: 'row' }, [
        el('button', { class: 'primary', text: 'Approve', onClick: () => decide('APPROVE') }),
        el('button', { class: 'danger', text: 'Reject', onClick: () => decide('REJECT') }),
      ]),
    ]));
  }

  parts.push(el('a', { href: '#/screenings', text: '← All screenings' }));
  return el('div', {}, parts);
}
