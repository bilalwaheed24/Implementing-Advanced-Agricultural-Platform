/* Links from an alert or incident to the record it is about, and to each other.
 *
 * An alert names its source as (entity_type, entity_id). Where that record has its own
 * screen the link opens it; where it only has a list screen the link opens the list; where
 * the role cannot read it (or there is no screen) the type is shown as plain text, so a
 * link never leads to a predictable 403.
 */
import { el, can, shortId, titleCase } from '/static/assets/core.js';

const ENTITY_ROUTES = {
  Device: { permission: 'device:read', href: (id) => `#/device/${id}`, text: 'Device' },
  SequenceScreening: { permission: 'biosecurity:read', href: (id) => `#/screening/${id}`,
    text: 'Screening' },
  CrisprAssessment: { permission: 'biosecurity:read', href: () => '#/crispr',
    text: 'CRISPR assessment' },
  Batch: { permission: 'supply:read', href: (id) => `#/batch/${id}`, text: 'Batch' },
  Farm: { permission: 'farm:read', href: (id) => `#/farm/${id}`, text: 'Farm' },
  Field: { permission: 'farm:read', href: () => '#/farms', text: 'Field' },
  SeedLot: { permission: 'gmo:read', href: () => '#/seed-lots', text: 'Seed lot' },
  GMOEvent: { permission: 'gmo:read', href: () => '#/gmo', text: 'GMO event' },
  GMOApproval: { permission: 'gmo:read', href: () => '#/gmo', text: 'GMO approval' },
  Shipment: { permission: 'supply:read', href: () => '#/shipments', text: 'Shipment' },
  Product: { permission: 'supply:read', href: () => '#/products', text: 'Product' },
  Certification: { permission: 'cert:read', href: () => '#/certifications',
    text: 'Certification' },
  User: { permission: 'user:read', href: () => '#/users', text: 'User' },
};

/* "Device 1a2b3c4d" — or "Field North 40" when the API supplied the record's name — as a
 * link when the role can open it, otherwise as text. */
export function entityLink(entityType, entityId, name = null) {
  if (!entityType) return null;
  const route = ENTITY_ROUTES[entityType];
  const label = `${route ? route.text : titleCase(entityType)} ${name || shortId(entityId)}`;
  if (route && entityId && can(route.permission)) {
    return el('a', { href: route.href(entityId), text: label });
  }
  return el('span', { class: 'hint', text: label });
}

export function incidentLink(incidentId, text = null) {
  if (!incidentId) return null;
  const label = text || `Incident ${shortId(incidentId)}`;
  return can('incident:read') ? el('a', { href: `#/incident/${incidentId}`, text: label })
    : el('span', { class: 'hint', text: label });
}

/* Incidents opened from an alert used to be titled "Incident: <alert title>"; on an
 * incidents screen the prefix only repeats the heading. */
export function incidentTitle(title) {
  return String(title || '').replace(/^Incident:\s*/i, '');
}
