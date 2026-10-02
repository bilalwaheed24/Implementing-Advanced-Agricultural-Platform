/* Notification inbox.
 *
 * The header already carried an unread count, but there was nowhere to read what the
 * notifications actually said or to clear them, so the count could only ever grow.
 */
import { el, api, badge, fmtDate, toast, titleCase, empty, loading, errorBox }
  from '/static/assets/core.js';

export async function render() {
  const body = el('div', {}, [loading()]);
  const header = el('div', { class: 'row u-toolbar' }, []);

  async function load() {
    body.replaceChildren(loading());
    header.replaceChildren();
    try {
      const page = await api('/notifications?page=1&page_size=50');
      const rows = page.items || [];
      const unread = rows.filter((row) => !row.read_at);

      header.replaceChildren(
        el('span', { class: unread.length ? 'badge high' : 'badge neutral',
          text: unread.length ? `${unread.length} unread` : 'All read' }),
        el('button', {
          text: 'Mark all as read',
          disabled: unread.length ? null : 'disabled',
          onClick: async () => {
            try {
              await api('/notifications/read-all', { method: 'POST' });
              toast('All notifications marked as read', 'ok');
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

      body.replaceChildren(el('ul', { class: 'timeline' }, rows.map((row) => el('li', {
        class: row.read_at ? '' : 'unverified',
      }, [
        el('div', { class: 'row' }, [
          badge(row.severity),
          el('strong', { text: row.title }),
          el('span', { class: 'hint', text: titleCase(row.category) }),
        ]),
        el('div', { class: 'when', text: fmtDate(row.created_at) }),
        row.body ? el('div', { class: 'hint', text: row.body }) : null,
        el('div', { class: 'row' }, [
          // Where the notification came from, as a link when the entity has a screen.
          row.entity_type === 'Device' && row.entity_id
            ? el('a', { href: `#/device/${row.entity_id}`, text: 'Open device' })
            : row.entity_type
              ? el('span', { class: 'hint', text: `Source: ${titleCase(row.entity_type)}` })
              : null,
          row.read_at
            ? el('span', { class: 'hint', text: `Read ${fmtDate(row.read_at)}` })
            : el('button', { text: 'Mark as read', onClick: async () => {
              try {
                await api(`/notifications/${row.id}/read`, { method: 'POST' });
                load();
              } catch (error) { toast(error.message, 'error'); }
            } }),
        ]),
      ]))));
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
