import * as crypto from 'crypto';
import * as elliptic from 'elliptic';
import {SignResult} from './models/SignResult';

const BN = require('bn.js');

export class EncSign {

    private _ecdsa: elliptic.ec;

    constructor() {
        this._ecdsa = new elliptic.ec(elliptic.curves['p256']);
    }

    /**
     * Returns the public key of a given private key in hex
     * @param {Buffer} privateKey A private key must be 256 bits wide
     * @return {Buffer}
     */
    privateToPublic(privateKey: Buffer): Buffer {
        const key = this._ecdsa.keyFromPrivate(privateKey);
        return Buffer.from(key.getPublic(false).encode().slice(1));
    }

    /**
     * Returns the address of a given public key.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Buffer}
     */
    publicToAddress(publicKey: Buffer, sanitize = false): Buffer {
        if (sanitize && (publicKey.length !== 64)) {
            publicKey = this._ecdsa.keyFromPublic(publicKey).getPublic(false).encode().slice(1);
        }
        const buffer = this.hash(publicKey);
        // Only take the lower 160bits of the hash
        return crypto.createHash('rmd160').update(buffer).digest().slice(-20);
    }

    /**
     * Converts a public key
     * @param {Buffer} publicKey
     * @return {Buffer}
     */
    importPublic(publicKey: Buffer): Buffer {
        if (publicKey.length !== 64) {
            publicKey = Buffer.from(this._ecdsa.keyFromPublic(publicKey).getPublic(false).encode().slice(1));
        }
        return publicKey;
    }

    /**
     * ECDSA sign
     * @param {Buffer} msgHash
     * @param {Buffer} privateKey
     * @return {SignResult}
     */
    sign(msgHash: Buffer, privateKey: Buffer): SignResult {

        if (!this.isValidPrivate(privateKey)) {
            throw new Error('Invalid private key');
        }

        const key = this._ecdsa.keyFromPrivate(privateKey);

        let sig;
        do {
            sig = key.sign(msgHash);
        } while (!key.verify(msgHash, sig));

        return {
            r: sig.r.toString('hex'),
            s: sig.s.toString('hex'),
            v: sig.recoveryParam + 27
        };
    }

    /**
     * ECDSA verify
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @param {Buffer} publicKey
     * @return {Boolean}
     */
    verify(msgHash: Buffer, sig: SignResult | Buffer, publicKey: Buffer): boolean {

        if (!this.isValidPublic(publicKey)) {
            throw new Error('Invalid private key');
        }

        const key = this._ecdsa.keyFromPublic(Buffer.concat([Buffer.from([4]), publicKey]));

        if (Buffer.isBuffer(sig)) {
            sig = this.toSignResult(sig);
        }

        const recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }

        const signature: elliptic.ec.SignatureOptions = {
            r: new BN(Buffer.from(sig.r, 'hex')),
            s: new BN(Buffer.from(sig.s, 'hex')),
            recoveryParam: recovery
        };

        return key.verify(msgHash, signature);
    }

    /**
     * ECDSA public key recovery from signature
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @return {Buffer} publicKey
     */
    ecrecover(msgHash: Buffer, sig: SignResult | Buffer): Buffer {
        if (Buffer.isBuffer(sig)) {
            sig = this.toSignResult(sig);
        }
        const recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }
        const signature: elliptic.ec.SignatureOptions = {
            r: new BN(Buffer.from(sig.r, 'hex')),
            s: new BN(Buffer.from(sig.s, 'hex')),
            recoveryParam: recovery
        };
        const senderPubKey = this._ecdsa.recoverPubKey(msgHash, signature, recovery);
        return Buffer.from(senderPubKey.encode().slice(1));
    }

    /**
     * Returns the sha-256 hash of `message`.
     * @param {String | Buffer} message
     * @returns {Buffer} hash
     */
    hash(message: string | Buffer): Buffer {
        if (typeof message === 'string') {
            message = Buffer.from(message);
        }
        if (message.length <= 0) {
            throw new Error('The message must not be empty!');
        }
        return crypto.createHash('sha256').update(message).digest();
    }

    /**
     * Convert signature format of the `eth_sign` RPC method to signature parameters
     * @param {String} sig
     * @return {SignResult}
     */
    fromRpcSig(sig: string): SignResult {
        if (!sig && sig.length <= 0) {
            throw new Error('Invalid signature length');
        }
        return this.toSignResult(Buffer.from(sig, 'hex'));
    }

    toRpcSig(sig: SignResult): string {
        const recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }

        return Buffer.concat([
            Buffer.from(sig.r, 'hex'),
            Buffer.from(sig.s, 'hex'),
            new BN(sig.v).toBuffer()
        ]).toString('hex');
    }

    /**
     * Checks if the private key
     * @param {Buffer} privateKey
     * @return {Boolean}
     */
    isValidPrivate(privateKey: Buffer): boolean {
        try {
            if (privateKey.length !== 32) {
                return false;
            }

            const bn = new BN(privateKey);
            return bn.cmp(elliptic.curves['p256'].n) < 0 && !bn.isZero();

        } catch (e) {
            console.error(e);
            return false;
        }
    }

    /**
     * Checks if the public key satisfies the rules of the curve secp256k1.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Boolean}
     */
    isValidPublic(publicKey: Buffer, sanitize = false): boolean {
        try {
            if (publicKey.length === 64) {
                const pubKey = this._ecdsa.keyFromPublic(Buffer.concat([Buffer.from([4]), publicKey]));
                return pubKey.validate().result;
            }

            if (!sanitize) {
                return false;
            }

            const key = this._ecdsa.keyFromPublic(publicKey);
            return key.validate().result;
        } catch (e) {
            console.error(e);
            return false;
        }
    }

    private toSignResult(sig: Buffer): SignResult {
        if (sig.length !== 65) {
            throw new Error('Invalid signature length');
        }

        let v = sig[64];
        // support both versions of `eth_sign` responses
        if (v < 27) {
            v += 27;
        }

        return {
            v: v,
            r: sig.slice(0, 32).toString('hex'),
            s: sig.slice(32, 64).toString('hex'),
        };
    }

    /**
     * Checks if the recovery is valid
     * @param {Number} recovery
     * @return {Boolean}
     */
    private isValidSigRecovery(recovery: number): boolean {
        return recovery === 0 || recovery === 1;
    }
}
