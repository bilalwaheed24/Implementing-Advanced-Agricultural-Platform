'use strict';

const sinon = require('sinon');
const { expect } = require('chai');
const { Context } = require('fabric-contract-api');
const { ChaincodeStub, ClientIdentity } = require('fabric-shim');

const AnchorContract = require('../lib/anchorContract');

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function makeContext(mspId = 'Org1MSP') {
    const ctx = new Context();
    const stub = sinon.createStubInstance(ChaincodeStub);
    const states = {};
    const history = {};
    let txCounter = 0;
    stub.putState.callsFake(async (key, value) => {
        states[key] = value;
        (history[key] = history[key] || []).push(value);
    });
    stub.getState.callsFake(async (key) => states[key]);
    stub.getTxID.callsFake(() => `tx${++txCounter}`);
    stub.getTxTimestamp.returns({ seconds: { low: 1792500000, high: 0 }, nanos: 0 });
    stub.getHistoryForKey.callsFake(async (key) => {
        const items = (history[key] || []).map((value) => ({ value }));
        let index = 0;
        return {
            next: async () => (index < items.length
                ? { value: items[index++], done: false } : { done: true }),
            close: async () => {},
        };
    });
    ctx.setChaincodeStub(stub);
    const identity = sinon.createStubInstance(ClientIdentity);
    identity.getMSPID.returns(mspId);
    ctx.setClientIdentity(identity);
    return { ctx, stub };
}

describe('ABSP anchor chaincode', () => {
    let contract;
    let ctx;
    let stub;

    beforeEach(() => {
        contract = new AnchorContract();
        ({ ctx, stub } = makeContext());
    });

    it('anchors a record with the submitting organisation and the Fabric tx id', async () => {
        const record = JSON.parse(await contract.AnchorRecord(
            ctx, 'batch:B-2026-0114', HASH_A, 'localtx1', 'batch', 'FarmMSP'));
        expect(record).to.include({ key: 'batch:B-2026-0114', contentHash: HASH_A,
            submittedBy: 'Org1MSP', sourceMsp: 'FarmMSP', version: 1, fabricTxId: 'tx1' });
        expect(record.anchoredAt).to.equal('2026-10-20T12:40:00.000Z');
        sinon.assert.calledOnce(stub.setEvent);
    });

    it('verifies MATCH for the anchored hash and MISMATCH for a changed record', async () => {
        await contract.AnchorRecord(ctx, 'batch:B-1', HASH_A, 'l1', 'batch', 'FarmMSP');
        expect(JSON.parse(await contract.VerifyRecord(ctx, 'batch:B-1', HASH_A)).result)
            .to.equal('MATCH');
        const tampered = JSON.parse(await contract.VerifyRecord(ctx, 'batch:B-1', HASH_B));
        expect(tampered).to.include({ result: 'MISMATCH', anchoredHash: HASH_A, computedHash: HASH_B });
    });

    it('reports NOT_ANCHORED for an unknown key', async () => {
        expect(JSON.parse(await contract.VerifyRecord(ctx, 'batch:nope', HASH_A)).result)
            .to.equal('NOT_ANCHORED');
    });

    it('keeps every version in the key history', async () => {
        await contract.AnchorRecord(ctx, 'audithead:latest', HASH_A, 'l1', 'audithead', 'RegulatorMSP');
        const second = JSON.parse(await contract.AnchorRecord(
            ctx, 'audithead:latest', HASH_B, 'l2', 'audithead', 'RegulatorMSP'));
        expect(second.version).to.equal(2);
        const history = JSON.parse(await contract.GetHistory(ctx, 'audithead:latest'));
        expect(history.map((h) => h.contentHash)).to.deep.equal([HASH_A, HASH_B]);
    });

    it('produces identical bytes for identical input (endorsers must agree)', async () => {
        const first = makeContext();
        const second = makeContext();
        const a = await contract.AnchorRecord(first.ctx, 'cert:C-1', HASH_A, 'l', 'cert', 'RegulatorMSP');
        const b = await contract.AnchorRecord(second.ctx, 'cert:C-1', HASH_A, 'l', 'cert', 'RegulatorMSP');
        expect(a).to.equal(b);
    });

    it('rejects a malformed key or hash', async () => {
        for (const [key, hash] of [['no-colon', HASH_A], ['batch:B-1', 'xyz'],
            ['batch:B-1', HASH_A.toUpperCase()]]) {
            let error;
            try {
                await contract.AnchorRecord(ctx, key, hash, 'l', 'batch', 'FarmMSP');
            } catch (caught) {
                error = caught;
            }
            expect(error, `${key} ${hash}`).to.be.instanceOf(Error);
        }
    });

    it('fails to read a missing record', async () => {
        let error;
        try {
            await contract.ReadRecord(ctx, 'batch:missing');
        } catch (caught) {
            error = caught;
        }
        expect(error.message).to.contain('No anchor');
    });
});
