import { el, api, badge, fmtDate, table, empty, errorBox, toast } from '/static/assets/core.js';

function fabricCard(fabric) {
  if (!fabric) return null;
  if (!fabric.enabled) {
    return el('div', { class: 'card' }, [
      el('h2', { text: 'Hyperledger Fabric network' }),
      el('p', { class: 'hint', text: 'Not connected. Start it with scripts/fabric_up.sh and set '
        + 'FABRIC_BRIDGE_URL to mirror every anchor onto a real two-organisation Fabric network.' }),
    ]);
  }
  const bridge = fabric.bridge || {};
  return el('div', { class: 'card' }, [
    el('h2', { text: 'Hyperledger Fabric network' }),
    el('div', { class: 'grid cols-4' }, [
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Bridge' }),
        el('div', { class: 'u-mt-6' }, [badge(fabric.reachable ? 'CONNECTED' : 'UNAVAILABLE')])]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Channel / chaincode' }),
        el('div', { class: 'mono u-mt-6', text: `${bridge.channel || '—'} / ${bridge.chaincode || '—'}` })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Mirrored (recent)' }),
        el('div', { class: 'value', text: fabric.mirrored_ok ?? 0 })]),
      el('div', { class: 'tile' }, [el('div', { class: 'label', text: 'Mirror failures' }),
        el('div', { class: 'value', text: fabric.mirrored_failed ?? 0 })]),
    ]),
    fabric.recent?.length ? table([
      { label: 'Key', render: (row) => el('span', { class: 'mono', text: row.key }) },
      { label: 'Version', numeric: true, render: (row) => row.version ?? '—' },
      { label: 'Fabric tx', render: (row) => el('span', { class: 'mono',
        text: row.fabric_tx_id ? `${row.fabric_tx_id.slice(0, 16)}…` : '—' }) },
      { label: 'Result', render: (row) => badge(row.ok ? 'ANCHORED' : 'FAILED') },
      { label: 'When', render: (row) => fmtDate(row.at) },
    ], fabric.recent) : el('p', { class: 'hint', text: 'Connected. New anchors appear here.' }),
  ]);
}

export async function render() {
  const [stats, verification, blocks, contracts, fabric] = await Promise.all([
    api('/blockchain/stats'), api('/blockchain/verify'),
    api('/blockchain/blocks?limit=15'), api('/blockchain/contracts'),
    api('/blockchain/fabric').catch(() => null),
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
      el('span', { class: 'demo-flag', text: 'Platform ledger: single-node ordering' }),
      ' — cryptography (ECDSA P-256, SHA-256, Merkle proofs) is real. When the Fabric bridge '
        + 'is connected, every anchor is also written to a Hyperledger Fabric network '
        + '(card below), where two organisations\' peers must endorse it.',
    ]),
    fabricCard(fabric),
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
