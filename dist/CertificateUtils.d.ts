/// <reference types="node" />
export declare class CertificateUtils {
    static getPublicKeyFromCertificate(crt: string | Buffer): Buffer;
    static formatCertificate(pem: string): string;
}
