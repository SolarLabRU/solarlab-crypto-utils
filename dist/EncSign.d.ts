/// <reference types="node" />
import { SignResult } from './models/SignResult';
export declare class EncSign {
    private _ecdsa;
    constructor();
    /**
     * Returns the public key of a given private key in hex
     * @param {Buffer} privateKey A private key must be 256 bits wide
     * @return {Buffer}
     */
    privateToPublic(privateKey: Buffer): Buffer;
    /**
     * Returns the address of a given public key.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Buffer}
     */
    publicToAddress(publicKey: Buffer, sanitize?: boolean): Buffer;
    /**
     * Converts a public key
     * @param {Buffer} publicKey
     * @return {Buffer}
     */
    importPublic(publicKey: Buffer): Buffer;
    /**
     * ECDSA sign
     * @param {Buffer} msgHash
     * @param {Buffer} privateKey
     * @return {SignResult}
     */
    sign(msgHash: Buffer, privateKey: Buffer): SignResult;
    /**
     * ECDSA verify
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @param {Buffer} publicKey
     * @return {Boolean}
     */
    verify(msgHash: Buffer, sig: SignResult | Buffer, publicKey: Buffer): boolean;
    /**
     * ECDSA public key recovery from signature
     * @param {Buffer} msgHash
     * @param {SignResult | Buffer} sig
     * @return {Buffer} publicKey
     */
    ecrecover(msgHash: Buffer, sig: SignResult | Buffer): Buffer;
    /**
     * Returns the sha-256 hash of `message`.
     * @param {String | Buffer} message
     * @returns {Buffer} hash
     */
    hash(message: string | Buffer): Buffer;
    /**
     * Convert signature format of the `eth_sign` RPC method to signature parameters
     * @param {String} sig
     * @return {SignResult}
     */
    fromRpcSig(sig: string): SignResult;
    toRpcSig(sig: SignResult): string;
    /**
     * Checks if the private key
     * @param {Buffer} privateKey
     * @return {Boolean}
     */
    isValidPrivate(privateKey: Buffer): boolean;
    /**
     * Checks if the public key satisfies the rules of the curve secp256k1.
     * @param {Buffer} publicKey The two points of an uncompressed key, unless sanitize is enabled
     * @param {Boolean} [sanitize=false] Accept public keys in other formats
     * @return {Boolean}
     */
    isValidPublic(publicKey: Buffer, sanitize?: boolean): boolean;
    private toSignResult;
    /**
     * Checks if the recovery is valid
     * @param {Number} recovery
     * @return {Boolean}
     */
    private isValidSigRecovery;
}
