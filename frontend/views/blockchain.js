import { el, api, badge, fmtDate, table, empty, errorBox, toast } from '/static/assets/core.js';

export async function render() {
  const [stats, verification, blocks, contracts] = await Promise.all([
    api('/blockchain/stats'), api('/blockchain/verify'),
    api('/blockchain/blocks?limit=15'), api('/blockchain/contracts'),
  ]);

  const functionRows = Object.entries(stats.by_function || {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const blockRows = blocks.blocks.map((block) => ({
    number: block.number, transactions: block.transactions.length,
    hash: block.block_hash, timestamp: block.timestamp,
  }));

  const policyRows = Object.entries(contracts.endorsement_policies).map(([fn, policy]) => ({
    fn, rule: policy.rule, orgs: policy.orgs.join(', '),
  }));

  return el('div', {}, [
    el('h1', { text: 'Permissioned ledger explorer' }),
    el('p', { class: 'subtitle' }, [
      el('span', { class: 'demo-flag', text: 'DEMO: single-node ordering' }),
      ' — cryptography (ECDSA P-256, SHA-256, Merkle proofs) is real. See ',
      el('a', { href: 'https://en.wikipedia.org/wiki/Hyperledger', target: '_blank',
        rel: 'noopener', text: 'docs/Blockchain-integration.md', class: 'u-hidden' }),
      'docs/Blockchain-integration.md for the migration path to production Hyperledger Fabric.',
    ]),
    el('div', { class: 'grid cols-4' }, [
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Chain valid' }),
        el('div', { class: 'u-mt-6' },
          [verification.valid ? badge('VERIFIED') : badge('FAILED')])]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Height' }),
        el('div', { class: 'value', text: stats.height })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Transactions' }),
        el('div', { class: 'value', text: stats.transactions })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Signatures verified' }),
        el('div', { class: 'value', text: verification.signatures_verified })]),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Participants' }),
      el('div', { class: 'row' },
        stats.organizations.map((org) => el('span', { class: 'badge info', text: org }))),
    ]),
    el('div', { class: 'grid cols-2' }, [
      el('div', { class: 'card' }, [
        el('h2', { text: 'Recent blocks' }),
        table([
          { label: '#', numeric: true, key: 'number' },
          { label: 'Tx', numeric: true, key: 'transactions' },
          { label: 'Hash', render: (row) => el('span', { class: 'mono',
            text: row.hash.slice(0, 20) + '…' }) },
          { label: 'Time', render: (row) => fmtDate(row.timestamp) },
        ], blockRows),
      ]),
      el('div', { class: 'card' }, [
        el('h2', { text: 'Transactions by chaincode function' }),
        functionRows.length ? table([
          { label: 'Function', key: 'name' },
          { label: 'Count', numeric: true, key: 'count' },
        ], functionRows) : empty('No transactions yet', 'Nothing has been anchored yet.'),
      ]),
    ]),
    el('div', { class: 'card' }, [
      el('h2', { text: 'Endorsement policies' }),
      table([
        { label: 'Function', render: (row) => el('span', { class: 'mono', text: row.fn }) },
        { label: 'Rule', key: 'rule' },
        { label: 'Organisations', key: 'orgs' },
      ], policyRows),
    ]),
  ]);
}
