/* tslint:disable */
import * as crypto from 'crypto';
import {EncSign, SignResult} from '../src';

import {expect} from 'chai';

describe('Test EncSign', function() {

    this.timeout(100000);

    let prvKey: Buffer;
    let encSign: EncSign;

    before(async () => {
        encSign = new EncSign();
        do {
            prvKey = crypto.randomBytes(32);
        } while (!encSign.isValidPrivate(prvKey));

        // console.log(prvKey.toString('hex'));
    });


    it('Should be able to init', async () => {

        expect(encSign).to.not.be.null;
    });

    it('Private key valid', async () => {

        expect(encSign.isValidPrivate(prvKey)).to.be.true;
    });

    it('Private key not valid', async () => {

        const _prvKey = crypto.randomBytes(32).slice(1);
        expect(encSign.isValidPrivate(_prvKey)).to.be.false;
    });

    it('Private key to Public', async () => {

        const pubKey = encSign.privateToPublic(prvKey);

        expect(pubKey).to.not.be.null;
        expect(pubKey).to.be.length(64);
    });

    it('Public key valid', async () => {

        const pubKey = Buffer.from('04e6075af709d5af38e3f7a290770e32675b70a737cab5c9d8917739ae03a036ad72b33c896d1ef61b6d2a8849926e6eccbc8152fa1988185cd76eebd473cc5179', 'hex');

        expect(pubKey).to.not.be.null;
        expect(encSign.isValidPublic(pubKey, true)).to.be.true;

        const pubKeyNew = encSign.importPublic(pubKey);
        expect(pubKeyNew).to.be.length(64);
    });

    it('Public key to Address', async () => {

        const pubKey = encSign.privateToPublic(prvKey);

        expect(encSign.isValidPublic(pubKey, false)).to.be.true;

        const address = encSign.publicToAddress(pubKey);

        console.log(address.toString('hex'));

        expect(address).to.not.be.null;
        expect(address).to.be.length(20);
    });

    it('Hash', async () => {

        const msg = 'Test message';
        const msgHash = encSign.hash(msg);

        // console.log(msgHash.toString('hex'));

        expect(msgHash).to.not.be.null;
        expect(msgHash).to.be.length(32);
    });

    it('sign', async () => {

        const msg = 'Test message';

        const pubKey = encSign.privateToPublic(prvKey);
        const msgHash = encSign.hash(msg);

        const result: SignResult = encSign.sign(msgHash, prvKey);

        // console.log(result);

        expect(result).to.not.be.null;
    });

    it('verify', async () => {

        const msg = 'Test message';

        const pubKey = encSign.privateToPublic(prvKey);
        const msgHash = encSign.hash(msg);

        const sig: SignResult = encSign.sign(msgHash, prvKey);

        // console.log(sig);

        const isValid = encSign.verify(msgHash, sig, pubKey);

        expect(isValid).to.be.true;
    });

    it('ecrecover', async () => {

        const msg = 'Test message';

        // for(let i = 0; i < 1000; i++) {

            const pubKey = encSign.privateToPublic(prvKey);
            const msgHash = encSign.hash(msg);

            const sign: SignResult = encSign.sign(msgHash, prvKey);

            // console.log(sign);

            const recoverPubKey = encSign.ecrecover(msgHash, sign);

            // console.log(recoverPubKey.toString('hex'));

            expect(recoverPubKey.toString('hex')).to.be.equal(pubKey.toString('hex'));
        // }
    });
});
