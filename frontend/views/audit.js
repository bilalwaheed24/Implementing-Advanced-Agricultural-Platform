import { el, api, badge, fmtDate, toast, can, roleLabel, entityLabel, entityHref, session }
  from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

/* "crop.status" -> "Crop status": the code stays available as the cell's tooltip. */
function actionLabel(action) {
  const words = String(action || '').replace(/[._]/g, ' ').trim().toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/* People's names, where the role may read accounts: one request per page load, shared by
 * every row. Without user:read the role is shown instead of a bare id. */
let usersPromise = null;
let usersFor = null;
function userNames() {
  const me = session.read()?.id || null;
  if (me !== usersFor) { usersPromise = null; usersFor = me; }
  if (!can('user:read')) return Promise.resolve({});
  if (!usersPromise) {
    usersPromise = api('/admin/users?page=1&page_size=200')
      .then((page) => Object.fromEntries((page.items || []).map((u) => [u.id, u.full_name])))
      .catch(() => ({}));
  }
  return usersPromise;
}

function actorCell(row) {
  if (!row.actor_id) return 'System';
  const role = row.actor_role ? roleLabel(row.actor_role) : '';
  const name = el('div', { text: role || 'User' });
  const cell = el('div', {}, [name]);
  userNames().then((names) => {
    if (!names[row.actor_id]) return;
    name.textContent = names[row.actor_id];
    if (role) cell.appendChild(el('div', { class: 'hint', text: role }));
  });
  return cell;
}

function entityCell(row) {
  if (!row.entity_type) return '—';
  const label = entityLabel(row.entity_type);
  const href = entityHref(row.entity_type, row.entity_id);
  const short = row.entity_id ? ` ${row.entity_id.slice(0, 8)}` : '';
  return href
    ? el('a', { href, title: row.entity_id || '' }, [label,
      el('span', { class: 'hint mono', text: short })])
    : el('span', { title: row.entity_id || '' }, [label,
      el('span', { class: 'hint mono', text: short })]);
}

async function verifyCard() {
  try {
    const result = await api('/audit/verify');
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Hash-chain verification' }),
      el('div', { class: 'row' }, [
        result.valid ? badge('VERIFIED') : badge('FAILED'),
        el('span', { class: 'hint', text: `${result.entries} entries, head sequence ${result.head_seq}` }),
        result.anchor_matches ? badge('ANCHORED')
          : el('span', { class: 'badge warning', text: 'Latest entries not yet anchored' }),
      ]),
      !result.valid ? el('p', { class: 'error-text',
        text: `First divergence: ${JSON.stringify(result.first_divergence)}` }) : null,
      el('div', { class: 'row u-mt-8' }, [
        // Anchoring writes to the ledger and needs audit:anchor; exporting is a read and
        // stays available to every role that may read the trail.
        can('audit:anchor') ? el('button', {
          text: 'Anchor current head to the ledger', onClick: async () => {
            try {
              const receipt = await api('/audit/anchor', { method: 'POST' });
              toast(receipt.ok ? `Anchored in block ${receipt.block_number}` : 'Anchoring pending',
                receipt.ok ? 'ok' : 'error');
            } catch (error) { toast(error.message, 'error'); }
          } }) : null,
        el('button', { class: 'secondary', text: 'Export audit trail (JSON)',
          onClick: async (event) => {
            // A plain <a href> cannot carry the Authorization header, so the link always
            // returned 401. Fetch through the API client and hand the browser a blob instead.
            const button = event.currentTarget;
            button.disabled = true;
            const original = button.textContent;
            button.textContent = 'Preparing export…';
            try {
              const data = await api('/audit/export?limit=500');
              const url = URL.createObjectURL(
                new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
              const link = document.createElement('a');
              link.href = url;
              link.download = `absp-audit-trail-${new Date().toISOString().slice(0, 10)}.json`;
              document.body.appendChild(link);
              link.click();
              link.remove();
              URL.revokeObjectURL(url);
              toast('Audit trail exported', 'ok');
            } catch (error) {
              toast(error.message, 'error');
            } finally {
              button.disabled = false;
              button.textContent = original;
            }
          } }),
      ]),
    ]);
  } catch (error) {
    return el('div', { class: 'card' }, [el('p', { class: 'error-text', text: error.message })]);
  }
}

export const render = listView({
  title: 'Audit trail',
  subtitle: 'Append-only, hash-chained. Every entry links to the previous one; altering '
    + 'any record breaks the chain from that point forward.',
  endpoint: '/audit/logs',
  extra: verifyCard,
  filters: [{ key: 'outcome', label: 'Outcome', options: ['SUCCESS', 'FAILURE'] }],
  columns: [
    { label: 'Seq', numeric: true, key: 'seq' },
    { label: 'When', render: (row) => fmtDate(row.created_at) },
    { label: 'Action', render: (row) => el('span', { title: row.action,
      text: actionLabel(row.action) }) },
    { label: 'Actor', render: (row) => actorCell(row) },
    { label: 'Record', render: (row) => entityCell(row) },
    { label: 'Outcome', render: (row) => badge(row.outcome) },
    { label: 'Hash', render: (row) => el('span', { class: 'mono',
      text: row.entry_hash.slice(0, 16) + '…' }) },
  ],
  emptyTitle: 'No audit records',
  emptyMessage: 'Audit records are created automatically by every security-relevant action.',
});
