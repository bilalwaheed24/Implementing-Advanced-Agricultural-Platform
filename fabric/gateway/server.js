/*
 * Start the ABSP Fabric bridge: connect to the test-network peer with an Org1 identity
 * (the same pattern as fabric-samples' application-gateway) and serve lib/app.js.
 *
 *   FABRIC_SAMPLES=~/fabric/fabric-samples BRIDGE_TOKEN=... node server.js
 */
'use strict';

const grpc = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const { createApp } = require('./lib/app');

const env = (name, fallback) => process.env[name] || fallback;
const samples = env('FABRIC_SAMPLES', path.resolve(__dirname, '..', 'fabric-samples'));
const cryptoPath = env('CRYPTO_PATH', path.join(samples, 'test-network', 'organizations',
    'peerOrganizations', 'org1.example.com'));
const config = {
    channel: env('CHANNEL_NAME', 'mychannel'),
    chaincode: env('CHAINCODE_NAME', 'absp-anchor'),
    mspId: env('MSP_ID', 'Org1MSP'),
    peerEndpoint: env('PEER_ENDPOINT', 'localhost:7051'),
    peerHostAlias: env('PEER_HOST_ALIAS', 'peer0.org1.example.com'),
    keyDir: env('KEY_DIRECTORY_PATH', path.join(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'keystore')),
    certDir: env('CERT_DIRECTORY_PATH', path.join(cryptoPath, 'users', 'User1@org1.example.com', 'msp', 'signcerts')),
    tlsCert: env('TLS_CERT_PATH', path.join(cryptoPath, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt')),
    host: env('BRIDGE_HOST', '127.0.0.1'),
    port: Number(env('BRIDGE_PORT', '8300')),
    token: env('BRIDGE_TOKEN', ''),
};

async function firstFile(dir) {
    const files = await fs.readdir(dir);
    if (!files.length) {
        throw new Error(`No files in ${dir}`);
    }
    return path.join(dir, files[0]);
}

async function main() {
    const client = new grpc.Client(config.peerEndpoint,
        grpc.credentials.createSsl(await fs.readFile(config.tlsCert)),
        { 'grpc.ssl_target_name_override': config.peerHostAlias });
    const gateway = connect({
        client,
        identity: { mspId: config.mspId, credentials: await fs.readFile(await firstFile(config.certDir)) },
        signer: signers.newPrivateKeySigner(crypto.createPrivateKey(await fs.readFile(await firstFile(config.keyDir)))),
        hash: hash.sha256,
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
        endorseOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 5000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });
    const contract = gateway.getNetwork(config.channel).getContract(config.chaincode);
    // Fail fast with a clear message if the chaincode is not deployed.
    await contract.evaluateTransaction('Info');

    if (!config.token) {
        console.warn('BRIDGE_TOKEN is not set: the bridge accepts unauthenticated requests');
    }
    const app = createApp(contract, { channel: config.channel, chaincode: config.chaincode,
        mspId: config.mspId, peer: config.peerEndpoint }, config.token);
    app.listen(config.port, config.host, () => {
        console.log(`ABSP Fabric bridge on http://${config.host}:${config.port} `
            + `(channel ${config.channel}, chaincode ${config.chaincode}, ${config.mspId})`);
    });
    const shutdown = () => { app.close(); gateway.close(); client.close(); process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

main().catch((error) => {
    console.error('Fabric bridge failed to start:', error.message);
    if (error.details) {
        console.error(error.details);
    }
    process.exit(1);
});
