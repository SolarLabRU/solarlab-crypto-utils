const {Certificate} = require('@fidm/x509');

export class CertificateUtils {

    static getPublicKeyFromCertificate(crt: string | Buffer): Buffer {

        if (!Buffer.isBuffer(crt)) {
            crt = CertificateUtils.formatCertificate(crt);
            crt = Buffer.from(crt);
        }

        const cert = Certificate.fromPEM(crt);

        return cert.publicKey.keyRaw;
    }

    static formatCertificate(pem: string): string {

        if (!(pem && pem.length)) {
            return null;
        }

        const regex = /(-----\s*BEGIN ?[^-]+?-----)([\s\S]*)(-----\s*END ?[^-]+?-----)/;
        let matches = pem.match(regex);

        if (!matches || matches.length !== 4) {

            throw new Error(`Invalid row certificate: ${pem}`);
        }

        // remove the first element that is the whole match
        matches.shift();
        // remove LF or CR
        matches = matches.map((element) => {
            return element.trim();
        });

        // make sure '-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----' are in their own lines
        // and that it ends in a new line
        return `${matches.join('\n')}\n`;
    }
}
