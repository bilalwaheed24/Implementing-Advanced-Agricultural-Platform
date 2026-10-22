import { el, api, badge, fmtDate, table, titleCase, toast, can, empty, roleLabel, refreshView } from '/static/assets/core.js';
import { listView } from '/static/views/listview.js';
import { createPanel, choiceSelect } from '/static/views/formkit.js';

const ORG_TYPES = [['FARM', 'Farm'], ['SUPPLY', 'Processor / supply chain'],
  ['BIOTECH', 'Biotech developer'], ['REGULATOR', 'Regulator / certifier']];

/* Onboarding a new organisation, e.g. a farm joining the platform. */
function addOrgPanel() {
  const name = el('input', { required: 'required', maxlength: '200',
    placeholder: 'e.g. Prairie Ridge Farms' });
  const type = choiceSelect(ORG_TYPES);
  const msp = el('input', { required: 'required', minlength: '3', maxlength: '40',
    placeholder: 'ledger identity, e.g. PrairieRidgeMSP' });
  const country = el('input', { maxlength: '2', minlength: '2', placeholder: 'e.g. US' });
  return createPanel({
    toggleLabel: 'Add organisation',
    submitLabel: 'Create organisation',
    primary: false,
    hint: 'Creates the organisation and its ledger signing identity. Add its people next.',
    controls: [['Name', name], ['Type', type], ['Ledger identity (MSP)', msp],
      ['Country', country]],
    submit: async () => {
      const created = await api('/admin/organizations', { method: 'POST', body: {
        name: name.value, org_type: type.value, msp_id: msp.value,
        country: country.value ? country.value.toUpperCase() : null } });
      return `Organisation ${created.name} created`;
    },
    onDone: () => refreshView(),
  });
}

/* Onboarding a person into an organisation with a temporary password. */
function addUserPanel(orgs) {
  const email = el('input', { type: 'email', required: 'required', maxlength: '255' });
  const fullName = el('input', { required: 'required', minlength: '2', maxlength: '200' });
  const org = choiceSelect(orgs.map((o) => [o.id, `${o.name} (${titleCase(o.org_type)})`]));
  const roleSelect = choiceSelect(ROLES.map((r) => [r, roleName(r)]), { value: 'FARM_OPERATOR' });
  const password = el('input', { type: 'text', required: 'required', minlength: '12',
    maxlength: '128', placeholder: 'temporary, at least 12 characters' });
  return createPanel({
    toggleLabel: 'Add user',
    submitLabel: 'Create user',
    primary: false,
    hint: 'Ordinary roles can sign in at once. Privileged roles (administrator, security '
      + 'analyst, biosafety officer, certifier, regulator) are created Pending and must be '
      + 'approved below. Give the person the temporary password through a separate channel.',
    controls: [['Email', email], ['Full name', fullName], ['Organisation', org],
      ['Role', roleSelect], ['Temporary password', password]],
    submit: async () => {
      const created = await api('/admin/users', { method: 'POST', body: {
        email: email.value, full_name: fullName.value, org_id: org.value,
        role: roleSelect.value, password: password.value } });
      return `${created.email} created (${titleCase(created.status)})`;
    },
    onDone: () => refreshView(),
  });
}

async function orgsCard() {
  try {
    const orgs = await api('/admin/organizations?page_size=100');
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Organisations' }),
      table([
        { label: 'Name', key: 'name' },
        { label: 'Type', render: (row) => titleCase(row.org_type) },
        { label: 'MSP identity', render: (row) => el('span', { class: 'mono', text: row.msp_id }) },
        { label: 'Trusted issuer for',
          render: (row) => (row.trusted_issuer_types || []).map(titleCase).join(', ') || '—' },
      ], orgs.items),
      el('div', { class: 'row u-toolbar u-mt-12' }, [
        can('org:write') ? addOrgPanel() : null,
        can('user:write') ? addUserPanel(orgs.items) : null,
      ]),
    ]);
  } catch (error) {
    return el('div', { class: 'card' }, [el('p', { class: 'error-text', text: error.message })]);
  }
}

const ROLES = ['ADMIN', 'SECURITY_ANALYST', 'FARM_OPERATOR', 'AGRONOMIST',
              'BIOTECH_RESEARCHER', 'BIOSAFETY_OFFICER', 'SUPPLY_CHAIN_OPERATOR',
              'CERTIFIER', 'REGULATOR'];

function roleName(role) {
  return String(role).toLowerCase().split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
}


function roleCell(row, reload) {
  if (!can('user:write')) return roleLabel(row.role);
  return el('div', { class: 'row' }, [
    roleLabel(row.role),
    // A select, not a free-text prompt: a typo previously reached the API as an invalid role.
    el('select', { 'aria-label': `Role for ${row.email}`, onChange: async (event) => {
      const select = event.currentTarget;
      const next = select.value;
      if (!next || next === row.role) return;
      if (!window.confirm(
        `Change the role of ${row.email} from ${roleName(row.role)} to ${roleName(next)}?\n\n`
        + 'They will be signed out and must sign in again.')) {
        select.value = row.role;
        return;
      }
      select.disabled = true;
      try {
        await api(`/admin/users/${row.id}`, { method: 'PATCH', body: { role: next } });
        toast('Role updated — the user will need to sign in again', 'ok');
        reload();
      } catch (error) {
        toast(error.message, 'error');
        select.value = row.role;
      } finally {
        select.disabled = false;
      }
    } }, ROLES.map((role) => el('option', {
      value: role, text: roleName(role), selected: role === row.role ? '' : null }))),
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
  if (row.status === 'SUSPENDED') {
    buttons.push(el('button', { text: 'Reactivate', onClick: async () => {
      try {
        await api(`/admin/users/${row.id}/approve`, { method: 'POST' });
        toast('User reactivated', 'ok');
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
  subtitle: 'Privileged roles are created Pending and require administrator approval.',
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
