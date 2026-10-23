/* Notification inbox.
 *
 * The header already carried an unread count, but there was nowhere to read what the
 * notifications actually said or to clear them, so the count could only ever grow.
 */
import { el, api, badge, fmtDate, toast, humanize, humanizeText, entityHref, entityLabel,
         empty, loading, errorBox } from '/static/assets/core.js';

const PAGE_SIZE = 50;

/* Tell the shell the unread count changed, so the header badge updates now rather than on
 * its next poll. */
function announceUnreadChanged() {
  window.dispatchEvent(new Event('absp:unread-changed'));
}

/* Where the notification came from: a link to the record when it has a screen this role
 * can open, otherwise its name in words. */
function sourceLink(row) {
  if (!row.entity_type) return null;
  const href = entityHref(row.entity_type, row.entity_id);
  const label = entityLabel(row.entity_type);
  // Mid-sentence: lower-case the first word unless it is an acronym (CRISPR, GMO).
  const first = label.split(' ')[0];
  const inline = first.length > 1 && first === first.toUpperCase()
    ? label : label.charAt(0).toLowerCase() + label.slice(1);
  return href
    ? el('a', { href, text: `Open ${inline}` })
    : el('span', { class: 'hint', text: `Related record: ${label}` });
}

export async function render() {
  const body = el('div', {}, [loading()]);
  const header = el('div', { class: 'row u-toolbar' }, []);
  const state = { page: 1 };

  async function load() {
    body.replaceChildren(loading());
    header.replaceChildren();
    try {
      // The unread total comes from the server, not from counting the rows of one page:
      // with more than a page of notifications that undercounted.
      const [page, count] = await Promise.all([
        api(`/notifications?page=${state.page}&page_size=${PAGE_SIZE}`),
        api('/notifications/unread-count'),
      ]);
      const rows = page.items || [];
      const unread = count.unread;

      header.replaceChildren(
        el('span', { class: unread ? 'badge high' : 'badge neutral',
          text: unread ? `${unread} unread` : 'All read' }),
        el('button', {
          text: 'Mark all as read',
          disabled: unread ? null : 'disabled',
          onClick: async () => {
            try {
              await api('/notifications/read-all', { method: 'POST' });
              toast('All notifications marked as read', 'ok');
              announceUnreadChanged();
              load();
            } catch (error) { toast(error.message, 'error'); }
          },
        }),
      );

      if (!rows.length) {
        body.replaceChildren(empty('No notifications',
          'Alerts routed to your role will appear here.'));
        return;
      }

      const list = el('ul', { class: 'timeline' }, rows.map((row) => el('li', {
        class: row.read_at ? '' : 'unverified',
      }, [
        el('div', { class: 'row' }, [
          badge(row.severity),
          el('strong', { text: humanizeText(row.title) }),
          el('span', { class: 'hint', text: humanize(row.category) }),
        ]),
        el('div', { class: 'when', text: fmtDate(row.created_at) }),
        row.body ? el('div', { class: 'hint', text: humanizeText(row.body) }) : null,
        el('div', { class: 'row' }, [
          sourceLink(row),
          row.read_at
            ? el('span', { class: 'hint', text: `Read ${fmtDate(row.read_at)}` })
            : el('button', { text: 'Mark as read', onClick: async () => {
              try {
                await api(`/notifications/${row.id}/read`, { method: 'POST' });
                announceUnreadChanged();
                load();
              } catch (error) { toast(error.message, 'error'); }
            } }),
        ]),
      ])));

      const pages = Math.max(1, Math.ceil((page.total || 0) / PAGE_SIZE));
      const pager = pages > 1 ? el('div', { class: 'row u-mt-12' }, [
        el('button', { text: 'Newer', disabled: state.page <= 1 ? 'disabled' : null,
          onClick: () => { state.page -= 1; load(); } }),
        el('span', { class: 'hint', text: `Page ${state.page} of ${pages}` }),
        el('button', { text: 'Older', disabled: state.page >= pages ? 'disabled' : null,
          onClick: () => { state.page += 1; load(); } }),
      ]) : null;
      body.replaceChildren(list, pager || '');
    } catch (error) {
      body.replaceChildren(errorBox(error));
    }
  }

  await load();

  return el('div', {}, [
    el('h1', { text: 'Notifications' }),
    el('p', { class: 'subtitle',
      text: 'Alerts are routed to the roles that own the category, scoped to your organisation.' }),
    el('div', { class: 'card' }, [header, body]),
  ]);
}
