/*
 * HTTP front for the Fabric anchor chaincode. The Python API calls this service; this
 * service holds a Fabric identity (an Org1 user) and talks to the peer over the Fabric
 * Gateway gRPC API. Endpoints:
 *
 *   GET  /health                       network, channel, chaincode, identity
 *   POST /anchor                       {key, content_hash, local_tx_id, entity_type, source_msp}
 *   GET  /verify?key=..&hash=..        MATCH | MISMATCH | NOT_ANCHORED, read from Fabric
 *   GET  /records?key=..               the anchored record
 *   GET  /history?key=..               every version of a key (Fabric key history)
 *
 * Every request must carry `Authorization: Bearer <BRIDGE_TOKEN>` when a token is set.
 */
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');

const decoder = new TextDecoder();
const KEY_PATTERN = /^[a-z_]{2,20}:[A-Za-z0-9._:-]{1,120}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const MAX_BODY = 16 * 1024;

function send(res, status, body) {
    const payload = JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload), 'Cache-Control': 'no-store' });
    res.end(payload);
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY) {
                reject(Object.assign(new Error('body too large'), { status: 413 }));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try {
                resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
            } catch {
                reject(Object.assign(new Error('invalid JSON'), { status: 400 }));
            }
        });
        req.on('error', reject);
    });
}

function authorised(req, token) {
    if (!token) {
        return true;
    }
    const given = Buffer.from(String(req.headers.authorization || ''));
    const expected = Buffer.from(`Bearer ${token}`);
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

function fabricError(error) {
    // Surface the chaincode's own message (e.g. "Invalid key") without stack traces.
    const details = (error.details || []).map((d) => d.message).filter(Boolean);
    return details.length ? details.join('; ') : String(error.message || error);
}

/**
 * @param {object} contract  a Fabric Gateway Contract (or a test double with the same methods)
 * @param {object} info      static description shown on /health
 * @param {string} token     shared secret; empty disables auth (local experiments only)
 */
function createApp(contract, info, token) {
    return http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://bridge');
        try {
            if (req.method === 'GET' && url.pathname === '/health') {
                return send(res, 200, { status: 'ok', network: 'hyperledger-fabric', ...info });
            }
            if (!authorised(req, token)) {
                return send(res, 401, { detail: 'missing or invalid bridge token' });
            }
            if (req.method === 'POST' && url.pathname === '/anchor') {
                const body = await readBody(req);
                if (!KEY_PATTERN.test(body.key || '') || !HASH_PATTERN.test(body.content_hash || '')) {
                    return send(res, 422, { detail: 'key must be <type>:<id>; content_hash a SHA-256 hex' });
                }
                const result = await contract.submitTransaction('AnchorRecord', body.key,
                    body.content_hash, String(body.local_tx_id || ''), String(body.entity_type || ''),
                    String(body.source_msp || ''));
                return send(res, 200, JSON.parse(decoder.decode(result)));
            }
            const key = url.searchParams.get('key') || '';
            if (req.method === 'GET' && ['/verify', '/records', '/history'].includes(url.pathname)) {
                if (!KEY_PATTERN.test(key)) {
                    return send(res, 422, { detail: 'key must be <type>:<id>' });
                }
                if (url.pathname === '/verify') {
                    const hash = url.searchParams.get('hash') || '';
                    if (!HASH_PATTERN.test(hash)) {
                        return send(res, 422, { detail: 'hash must be a SHA-256 hex digest' });
                    }
                    const out = await contract.evaluateTransaction('VerifyRecord', key, hash);
                    return send(res, 200, JSON.parse(decoder.decode(out)));
                }
                if (url.pathname === '/records') {
                    try {
                        const out = await contract.evaluateTransaction('ReadRecord', key);
                        return send(res, 200, JSON.parse(decoder.decode(out)));
                    } catch (error) {
                        if (fabricError(error).includes('No anchor')) {
                            return send(res, 404, { detail: `No anchor for ${key}` });
                        }
                        throw error;
                    }
                }
                const out = await contract.evaluateTransaction('GetHistory', key);
                return send(res, 200, { key, history: JSON.parse(decoder.decode(out)) });
            }
            return send(res, 404, { detail: 'not found' });
        } catch (error) {
            const status = error.status || 502;
            return send(res, status, { detail: status === 502
                ? `fabric error: ${fabricError(error)}` : error.message });
        }
    });
}

module.exports = { createApp };
