import { el, session, api, rowHeader, titleCase, toast, roleLabel } from '/static/assets/core.js';

export async function render() {
  const me = await api('/auth/me');
  return el('div', {}, [
    el('h1', { text: 'Settings' }),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Profile' }),
      el('table', {}, [
        el('tr', {}, [rowHeader('Name'), el('td', { text: me.full_name })]),
        el('tr', {}, [rowHeader('Email'), el('td', { class: 'mono', text: me.email })]),
        el('tr', {}, [rowHeader('Role'), el('td', { text: roleLabel(me.role) })]),
        el('tr', {}, [rowHeader('Organisation id'),
          el('td', { class: 'mono', text: me.org_id })]),
      ]),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Effective permissions' }),
      el('div', { class: 'row' }, me.permissions.map((permission) =>
        el('span', { class: 'badge neutral mono', text: permission }))),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Session' }),
      el('button', { class: 'danger', text: 'Sign out everywhere', onClick: async () => {
        await api('/auth/logout', { method: 'POST' });
        session.clear();
        window.location.hash = '#/login';
        toast('Signed out', 'ok');
      } }),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'About this deployment' }),
      el('p', { text: 'This is a demonstration deployment. Device fleets, hazard sequences '
        + 'and the training data are simulated, and the platform ledger orders on a single node '
        + '(see Known limitations in the README). Cryptography, access control, audit logging, '
        + 'drone-imagery hashing and the optional Hyperledger Fabric mirror are real.' }),
    ]),
  ]);
}
