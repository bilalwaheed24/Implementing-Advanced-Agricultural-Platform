import { el, api, badge, fmtDate, table, titleCase, toast, can, empty } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';

async function orgsCard() {
  try {
    const orgs = await api('/admin/organizations?page_size=20');
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Organisations' }),
      table([
        { label: 'Name', key: 'name' },
        { label: 'Type', render: (row) => titleCase(row.org_type) },
        { label: 'MSP identity', render: (row) => el('span', { class: 'mono', text: row.msp_id }) },
        { label: 'Trusted issuer for',
          render: (row) => (row.trusted_issuer_types || []).map(titleCase).join(', ') || '—' },
      ], orgs.items),
    ]);
  } catch (error) {
    return el('div', { class: 'card' }, [el('p', { class: 'error-text', text: error.message })]);
  }
}

const ROLES = ['ADMIN', 'SECURITY_ANALYST', 'FARM_OPERATOR', 'AGRONOMIST',
              'BIOTECH_RESEARCHER', 'BIOSAFETY_OFFICER', 'SUPPLY_CHAIN_OPERATOR',
              'CERTIFIER', 'REGULATOR'];

function roleCell(row, reload) {
  if (!can('user:write')) return titleCase(row.role);
  return el('div', { class: 'row' }, [
    titleCase(row.role),
    el('button', { text: 'Change', onClick: async () => {
      const next = window.prompt(
        `New role for ${row.email} (one of: ${ROLES.join(', ')}):`, row.role);
      if (!next || next.trim().toUpperCase() === row.role) return;
      try {
        await api(`/admin/users/${row.id}`, { method: 'PATCH',
                                              body: { role: next.trim().toUpperCase() } });
        toast('Role updated — the user will need to sign in again', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }),
  ]);
}

function userActions(row, reload) {
  if (!can('user:write')) return badge(row.status);
  const buttons = [];
  if (row.status === 'PENDING') {
    buttons.push(el('button', { text: 'Approve', onClick: async () => {
      try {
        await api(`/admin/users/${row.id}/approve`, { method: 'POST' });
        toast('User approved', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  if (row.status === 'ACTIVE') {
    buttons.push(el('button', { class: 'danger', text: 'Suspend', onClick: async () => {
      const reason = window.prompt('Reason for suspension:');
      if (!reason) return;
      try {
        await api(`/admin/users/${row.id}/suspend`, { method: 'POST', body: { reason } });
        toast('User suspended', 'ok');
        reload();
      } catch (error) { toast(error.message, 'error'); }
    } }));
  }
  return el('div', { class: 'row' }, [badge(row.status), ...buttons]);
}

export const render = listView({
  title: 'Users and organisations',
  subtitle: 'Privileged roles are created PENDING and require administrator approval.',
  endpoint: '/admin/users',
  extra: orgsCard,
  filters: [{ key: 'status', label: 'Status', options: ['PENDING', 'ACTIVE', 'SUSPENDED'] }],
  columns: [
    { label: 'Name', key: 'full_name' },
    { label: 'Email', render: (row) => el('span', { class: 'mono', text: row.email }) },
    { label: 'Role', render: (row, { reload }) => roleCell(row, reload) },
    { label: 'Joined', render: (row) => fmtDate(row.created_at) },
    { label: 'Last login', render: (row) => fmtDate(row.last_login_at) },
    { label: 'Status', render: (row, { reload }) => userActions(row, reload) },
  ],
  emptyTitle: 'No users found',
  emptyMessage: 'No users match the current filter.',
});
