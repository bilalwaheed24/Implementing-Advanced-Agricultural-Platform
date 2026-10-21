/*
 * ABSP anchor chaincode for Hyperledger Fabric.
 *
 * The platform's own permissioned ledger already anchors every traceability record. This
 * chaincode mirrors those anchors (key + SHA-256 content hash) onto a real Fabric network,
 * where the endorsement policy makes peers of two different organisations execute and sign
 * every write. A record changed in PostgreSQL then fails verification against Fabric too,
 * and nobody holding only the platform's keys can rewrite the Fabric copy.
 *
 * Only hashes and identifiers go on chain; business data stays in the platform database.
 */
'use strict';

const { Contract } = require('fabric-contract-api');
const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');

const KEY_PATTERN = /^[a-z_]{2,20}:[A-Za-z0-9._:-]{1,120}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;

function toJson(value) {
    // Deterministic serialisation: every endorsing peer must produce identical bytes.
    return stringify(sortKeysRecursive(value));
}

function txTime(ctx) {
    // The proposal timestamp, not the local clock, so all endorsers agree.
    const ts = ctx.stub.getTxTimestamp();
    const seconds = typeof ts.seconds === 'object' && ts.seconds !== null && 'low' in ts.seconds
        ? ts.seconds.low : Number(ts.seconds);
    return new Date(seconds * 1000).toISOString();
}

class AnchorContract extends Contract {
    constructor() {
        super('AbspAnchor');
    }

    async Info() {
        return toJson({ chaincode: 'absp-anchor', version: '1.0.0',
            purpose: 'Mirror of ABSP traceability anchors (key + SHA-256 content hash)' });
    }

    async AnchorRecord(ctx, key, contentHash, localTxId, entityType, sourceMsp) {
        if (!KEY_PATTERN.test(key)) {
            throw new Error(`Invalid key ${key}: expected <type>:<identifier>`);
        }
        if (!HASH_PATTERN.test(contentHash)) {
            throw new Error('contentHash must be a lowercase SHA-256 hex digest');
        }
        const previousBytes = await ctx.stub.getState(key);
        const previous = previousBytes && previousBytes.length > 0
            ? JSON.parse(previousBytes.toString()) : null;
        const record = {
            key,
            entityType: String(entityType || key.split(':')[0]),
            contentHash,
            localTxId: String(localTxId || ''),
            sourceMsp: String(sourceMsp || ''),
            submittedBy: ctx.clientIdentity.getMSPID(),
            fabricTxId: ctx.stub.getTxID(),
            anchoredAt: txTime(ctx),
            version: previous ? previous.version + 1 : 1,
        };
        await ctx.stub.putState(key, Buffer.from(toJson(record)));
        ctx.stub.setEvent('Anchored', Buffer.from(toJson({ key, contentHash })));
        return toJson(record);
    }

    async ReadRecord(ctx, key) {
        const bytes = await ctx.stub.getState(key);
        if (!bytes || bytes.length === 0) {
            throw new Error(`No anchor for ${key}`);
        }
        return bytes.toString();
    }

    async VerifyRecord(ctx, key, contentHash) {
        const bytes = await ctx.stub.getState(key);
        if (!bytes || bytes.length === 0) {
            return toJson({ key, result: 'NOT_ANCHORED' });
        }
        const record = JSON.parse(bytes.toString());
        return toJson({
            key,
            result: record.contentHash === contentHash ? 'MATCH' : 'MISMATCH',
            anchoredHash: record.contentHash,
            computedHash: contentHash,
            version: record.version,
            fabricTxId: record.fabricTxId,
            anchoredAt: record.anchoredAt,
        });
    }

    async GetHistory(ctx, key) {
        const iterator = await ctx.stub.getHistoryForKey(key);
        const history = [];
        try {
            let result = await iterator.next();
            while (!result.done) {
                if (result.value && result.value.value && result.value.value.length > 0) {
                    history.push(JSON.parse(Buffer.from(result.value.value).toString('utf8')));
                }
                result = await iterator.next();
            }
        } finally {
            await iterator.close();
        }
        return toJson(history);
    }
}

module.exports = AnchorContract;
