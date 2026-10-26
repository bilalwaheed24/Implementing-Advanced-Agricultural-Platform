'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createApp } = require('../lib/app');

const enc = new TextEncoder();
const HASH = 'c'.repeat(64);
const OTHER = 'd'.repeat(64);

// A stand-in for the Fabric contract with the chaincode's observable behaviour.
function fakeContract() {
    const state = {};
    return {
        calls: [],
        async submitTransaction(fn, key, hash, localTx, type, msp) {
            this.calls.push(fn);
            const version = state[key] ? state[key].version + 1 : 1;
            state[key] = { key, contentHash: hash, localTxId: localTx, entityType: type,
                sourceMsp: msp, version, fabricTxId: `ftx${version}` };
            return enc.encode(JSON.stringify(state[key]));
        },
        async evaluateTransaction(fn, key, hash) {
            if (fn === 'VerifyRecord') {
                const r = state[key];
                return enc.encode(JSON.stringify(r ? { key, result: r.contentHash === hash ? 'MATCH' : 'MISMATCH',
                    anchoredHash: r.contentHash } : { key, result: 'NOT_ANCHORED' }));
            }
            if (fn === 'ReadRecord') {
                if (!state[key]) {
                    throw Object.assign(new Error('10 ABORTED'), { details: [{ message: `No anchor for ${key}` }] });
                }
                return enc.encode(JSON.stringify(state[key]));
            }
            return enc.encode(JSON.stringify(state[key] ? [state[key]] : []));
        },
    };
}

async function withServer(fn, token = 'secret-token') {
    const server = createApp(fakeContract(), { channel: 'mychannel' }, token);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
        await fn(base);
    } finally {
        server.close();
    }
}

const auth = { Authorization: 'Bearer secret-token', 'Content-Type': 'application/json' };

test('health is open and describes the network', () => withServer(async (base) => {
    const body = await (await fetch(`${base}/health`)).json();
    assert.equal(body.network, 'hyperledger-fabric');
    assert.equal(body.channel, 'mychannel');
}));

test('every other route needs the bridge token', () => withServer(async (base) => {
    const res = await fetch(`${base}/verify?key=batch:B-1&hash=${HASH}`);
    assert.equal(res.status, 401);
}));

test('anchor then verify: MATCH, then MISMATCH for a changed hash', () => withServer(async (base) => {
    const anchored = await fetch(`${base}/anchor`, { method: 'POST', headers: auth,
        body: JSON.stringify({ key: 'batch:B-1', content_hash: HASH, local_tx_id: 'l1',
            entity_type: 'batch', source_msp: 'FarmMSP' }) });
    assert.equal(anchored.status, 200);
    assert.equal((await anchored.json()).version, 1);
    const match = await (await fetch(`${base}/verify?key=batch:B-1&hash=${HASH}`, { headers: auth })).json();
    assert.equal(match.result, 'MATCH');
    const mismatch = await (await fetch(`${base}/verify?key=batch:B-1&hash=${OTHER}`, { headers: auth })).json();
    assert.equal(mismatch.result, 'MISMATCH');
}));

test('bad input is refused before reaching Fabric', () => withServer(async (base) => {
    const res = await fetch(`${base}/anchor`, { method: 'POST', headers: auth,
        body: JSON.stringify({ key: 'nocolon', content_hash: 'xyz' }) });
    assert.equal(res.status, 422);
    const bad = await fetch(`${base}/anchor`, { method: 'POST', headers: auth, body: '{not json' });
    assert.equal(bad.status, 400);
}));

test('a missing record is a 404, not a server error', () => withServer(async (base) => {
    const res = await fetch(`${base}/records?key=batch:none`, { headers: auth });
    assert.equal(res.status, 404);
}));
