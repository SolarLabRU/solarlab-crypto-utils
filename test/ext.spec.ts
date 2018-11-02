/* tslint:disable */
import {EncSign, SignResult} from '../src';

import {expect} from 'chai';

describe('Test EncSign', function () {

    this.timeout(100000);

    const encSign: EncSign = new EncSign();
    const msg = 'hello';
    const msgHash = encSign.hash(msg);
    const prvKey = Buffer.from('615de73b60d4267c09c9fc5b13df18b7035c5692c35b33c222b2262ce37cb873', 'hex');
    const pubKey = encSign.privateToPublic(prvKey);
    const R = 'fefdddf43e04401ec49931c5a558e3cf5e076a6f1557f08db4d85c70b8a0577d';
    const S = '5bfb92fea024b3bf4c0588e3a5ffa8886fee88be999169437798f29d747ffb89';
    const V = 28;

    it('check', () => {

        expect(pubKey.toString('hex')).to.be.equal('59a2d814f5e0341fb81b138206069d20f5263c1e59fb79f03d0e98850994c7448f05a67f4c71e6fc48379fae6936827cf22ec2e535d34612b8df179fd24eabb7');
        expect(msgHash.toString('hex')).to.be.equal('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');


        const sig: SignResult = {
            r: R,
            s: S,
            v: V
        };

        const isValid = encSign.verify(msgHash, sig, pubKey);
        expect(isValid).to.be.true;

        const recoverPublicKey = encSign.ecrecover(msgHash, sig);

        expect(recoverPublicKey).to.not.be.null;
        expect(recoverPublicKey.toString('hex')).to.be.equal(pubKey.toString('hex'));


    });
});
