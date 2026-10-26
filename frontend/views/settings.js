import { el, session, api, rowHeader, toast, roleLabel, menuHidden } from '/static/assets/core.js';

/* What each permission lets a person do, in their words. The codes are the system's; a
 * reader wants to know "can I approve a GMO event?", not "gmo:approve". */
const CAPABILITIES = {
  'user:read': 'See user accounts', 'user:write': 'Create, approve and suspend users',
  'org:read': 'See organisations', 'org:write': 'Register organisations',
  'farm:read': 'See farms, fields and crops', 'farm:write': 'Register farms and record plantings',
  'device:read': 'See devices', 'device:write': 'Register and configure devices',
  'device:contain': 'Suspend or quarantine a device',
  'telemetry:read': 'See sensor readings and imagery', 'telemetry:write': 'Upload imagery',
  'ai:read': 'See AI analyses', 'ai:run': 'Run AI analyses',
  'alert:read': 'See alerts', 'alert:write': 'Acknowledge and resolve alerts',
  'incident:read': 'See incidents', 'incident:write': 'Manage incidents',
  'biosecurity:read': 'See sequence screenings and CRISPR assessments',
  'biosecurity:submit': 'Submit sequences and gene edits for screening',
  'biosecurity:review': 'Release or reject screenings held for review',
  'hazard:write': 'Curate the hazard database',
  'gmo:read': 'See GMO events and seed lots', 'gmo:write': 'Register GMO events and seed lots',
  'gmo:approve': 'Record regulatory approval of a GMO event',
  'supply:read': 'See batches, products and shipments',
  'supply:write': 'Create batches, record events and hand over custody',
  'supply:verify': 'Run integrity and fraud checks on a batch',
  'cert:read': 'See certifications', 'cert:issue': 'Issue certifications',
  'cert:revoke': 'Revoke certifications',
  'compliance:read': 'See compliance reports', 'compliance:run': 'Run compliance evaluations',
  'blockchain:read': 'Check your records against the ledger',
  'blockchain:explore': 'Browse the whole ledger',
  'audit:read': 'Read the audit trail', 'audit:anchor': 'Anchor the audit trail to the ledger',
  'admin:all': 'Platform administration',
};

/* Grouped by the first part of the code so the list reads by area. */
const AREAS = {
  user: 'People', org: 'People', farm: 'Farming', device: 'Farming', telemetry: 'Farming',
  ai: 'Intelligence', alert: 'Security', incident: 'Security', biosecurity: 'Biosecurity',
  hazard: 'Biosecurity', gmo: 'Biotechnology', supply: 'Supply chain', cert: 'Supply chain',
  compliance: 'Trust', blockchain: 'Trust', audit: 'Trust', admin: 'Administration',
};

/* The menu pages a capability is used on. A capability is listed only when at least one of
 * its pages is in the role's menu (core.js NOT_USEFUL_FOR via menuHidden): a researcher holds
 * ai:read but has no AI Insights page, so "See AI analyses" would promise something the menu
 * does not offer. A permission with no entry
 * here is not tied to a hidden page and is always listed. */
const CAPABILITY_PAGES = {
  'device:read': ['#/devices'], 'device:write': ['#/devices'], 'device:contain': ['#/devices'],
  'telemetry:read': ['#/telemetry', '#/satellite'], 'telemetry:write': ['#/satellite'],
  'ai:read': ['#/ai'], 'ai:run': ['#/ai'],
  'gmo:read': ['#/gmo', '#/seed-lots'], 'gmo:write': ['#/gmo', '#/seed-lots'],
  'supply:read': ['#/batches', '#/products', '#/shipments'],
  'supply:write': ['#/batches', '#/products', '#/shipments'],
  'supply:verify': ['#/batches', '#/fraud'],
};

function capabilityUseful(permission, currentRole) {
  const pages = CAPABILITY_PAGES[permission];
  return !pages || pages.some((path) => !menuHidden(path, currentRole));
}

function capabilityList(permissions, currentRole) {
  const byArea = new Map();
  for (const permission of permissions.filter((p) => capabilityUseful(p, currentRole))) {
    const area = AREAS[permission.split(':')[0]] || 'Other';
    if (!byArea.has(area)) byArea.set(area, []);
    byArea.get(area).push(CAPABILITIES[permission] || permission);
  }
  return el('div', { class: 'grid cols-3' }, [...byArea.entries()].map(([area, items]) =>
    el('div', {}, [
      el('h3', { text: area }),
      el('ul', {}, items.map((text) => el('li', { text }))),
    ])));
}

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
        el('tr', {}, [rowHeader('Organisation'),
          el('td', { text: me.org_name || 'Your organisation' })]),
      ]),
      el('p', { class: 'hint',
        text: 'To change your password or role, ask your platform administrator.' }),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'What your role can do' }),
      capabilityList(me.permissions, me.role),
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
        + 'and the training data are simulated, and the platform ledger runs on a single '
        + 'node rather than a distributed network. Cryptography, access control, audit '
        + 'logging, drone-imagery hashing and the optional Hyperledger Fabric mirror are real.' }),
    ]),
  ]);
}
