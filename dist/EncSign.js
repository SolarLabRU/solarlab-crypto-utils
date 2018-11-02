"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var elliptic = require("elliptic");
var BN = require('bn.js');
var EncSign = /** @class */ (function () {
    function EncSign() {
        this._ecdsa = new elliptic.ec(elliptic.curves['p256']);
    }
    /**
     * Returns the public key of a given private key in hex
     * @param {Buffer} privateKey A private key must be 256 bits wide
     * @return {Buffer}
     */
    EncSign.prototype.privateToPublic = function (privateKey) {
        var key = this._ecdsa.keyFromPrivate(privateKey);
        return Buffer.from(key.getPublic(false).encode().slice(1));
    };
    /**
     * Returns the address of a given public key.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Buffer}
     */
    EncSign.prototype.publicToAddress = function (publicKey, sanitize) {
        if (sanitize === void 0) { sanitize = false; }
        if (sanitize && (publicKey.length !== 64)) {
            publicKey = this._ecdsa.keyFromPublic(publicKey).getPublic(false).encode().slice(1);
        }
        var buffer = this.hash(publicKey);
        // Only take the lower 160bits of the hash
        return crypto.createHash('rmd160').update(buffer).digest().slice(-20);
    };
    /**
     * Converts a public key
     * @param {Buffer} publicKey
     * @return {Buffer}
     */
    EncSign.prototype.importPublic = function (publicKey) {
        if (publicKey.length !== 64) {
            publicKey = Buffer.from(this._ecdsa.keyFromPublic(publicKey).getPublic(false).encode().slice(1));
        }
        return publicKey;
    };
    /**
     * ECDSA sign
     * @param {Buffer} msgHash
     * @param {Buffer} privateKey
     * @return {SignResult}
     */
    EncSign.prototype.sign = function (msgHash, privateKey) {
        if (!this.isValidPrivate(privateKey)) {
            throw new Error('Invalid private key');
        }
        var key = this._ecdsa.keyFromPrivate(privateKey);
        var sig;
        do {
            sig = key.sign(msgHash);
        } while (!key.verify(msgHash, sig));
        return {
            r: sig.r.toString('hex'),
            s: sig.s.toString('hex'),
            v: sig.recoveryParam + 27
        };
    };
    /**
     * ECDSA verify
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @param {Buffer} publicKey
     * @return {Boolean}
     */
    EncSign.prototype.verify = function (msgHash, sig, publicKey) {
        if (!this.isValidPublic(publicKey)) {
            throw new Error('Invalid private key');
        }
        var key = this._ecdsa.keyFromPublic(Buffer.concat([Buffer.from([4]), publicKey]));
        if (Buffer.isBuffer(sig)) {
            sig = this.toSignResult(sig);
        }
        var recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }
        var signature = {
            r: new BN(Buffer.from(sig.r, 'hex')),
            s: new BN(Buffer.from(sig.s, 'hex')),
            recoveryParam: recovery
        };
        return key.verify(msgHash, signature);
    };
    /**
     * ECDSA public key recovery from signature
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @return {Buffer} publicKey
     */
    EncSign.prototype.ecrecover = function (msgHash, sig) {
        if (Buffer.isBuffer(sig)) {
            sig = this.toSignResult(sig);
        }
        var recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }
        var signature = {
            r: new BN(Buffer.from(sig.r, 'hex')),
            s: new BN(Buffer.from(sig.s, 'hex')),
            recoveryParam: recovery
        };
        var senderPubKey = this._ecdsa.recoverPubKey(msgHash, signature, recovery);
        return Buffer.from(senderPubKey.encode().slice(1));
    };
    /**
     * Returns the sha-256 hash of `message`.
     * @param {String | Buffer} message
     * @returns {Buffer} hash
     */
    EncSign.prototype.hash = function (message) {
        if (typeof message === 'string') {
            message = Buffer.from(message);
        }
        if (message.length <= 0) {
            throw new Error('The message must not be empty!');
        }
        return crypto.createHash('sha256').update(message).digest();
    };
    /**
     * Convert signature format of the `eth_sign` RPC method to signature parameters
     * @param {String} sig
     * @return {SignResult}
     */
    EncSign.prototype.fromRpcSig = function (sig) {
        if (!sig && sig.length <= 0) {
            throw new Error('Invalid signature length');
        }
        return this.toSignResult(Buffer.from(sig, 'hex'));
    };
    EncSign.prototype.toRpcSig = function (sig) {
        var recovery = sig.v - 27;
        if (!this.isValidSigRecovery(recovery)) {
            throw new Error('Invalid signature v value');
        }
        return Buffer.concat([
            Buffer.from(sig.r, 'hex'),
            Buffer.from(sig.s, 'hex'),
            new BN(sig.v).toBuffer()
        ]).toString('hex');
    };
    /**
     * Checks if the private key
     * @param {Buffer} privateKey
     * @return {Boolean}
     */
    EncSign.prototype.isValidPrivate = function (privateKey) {
        try {
            if (privateKey.length !== 32) {
                return false;
            }
            var bn = new BN(privateKey);
            return bn.cmp(elliptic.curves['p256'].n) < 0 && !bn.isZero();
        }
        catch (e) {
            console.error(e);
            return false;
        }
    };
    /**
     * Checks if the public key satisfies the rules of the curve secp256k1.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Boolean}
     */
    EncSign.prototype.isValidPublic = function (publicKey, sanitize) {
        if (sanitize === void 0) { sanitize = false; }
        try {
            if (publicKey.length === 64) {
                var pubKey = this._ecdsa.keyFromPublic(Buffer.concat([Buffer.from([4]), publicKey]));
                return pubKey.validate().result;
            }
            if (!sanitize) {
                return false;
            }
            var key = this._ecdsa.keyFromPublic(publicKey);
            return key.validate().result;
        }
        catch (e) {
            console.error(e);
            return false;
        }
    };
    EncSign.prototype.toSignResult = function (sig) {
        if (sig.length !== 65) {
            throw new Error('Invalid signature length');
        }
        var v = sig[64];
        // support both versions of `eth_sign` responses
        if (v < 27) {
            v += 27;
        }
        return {
            v: v,
            r: sig.slice(0, 32).toString('hex'),
            s: sig.slice(32, 64).toString('hex'),
        };
    };
    /**
     * Checks if the recovery is valid
     * @param {Number} recovery
     * @return {Boolean}
     */
    EncSign.prototype.isValidSigRecovery = function (recovery) {
        return recovery === 0 || recovery === 1;
    };
    return EncSign;
}());
exports.EncSign = EncSign;
//# sourceMappingURL=EncSign.js.map