"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Certificate = require('@fidm/x509').Certificate;
var CertificateUtils = /** @class */ (function () {
    function CertificateUtils() {
    }
    CertificateUtils.getPublicKeyFromCertificate = function (crt) {
        if (!Buffer.isBuffer(crt)) {
            crt = CertificateUtils.formatCertificate(crt);
            crt = Buffer.from(crt);
        }
        var cert = Certificate.fromPEM(crt);
        return cert.publicKey.keyRaw;
    };
    CertificateUtils.formatCertificate = function (pem) {
        if (!(pem && pem.length)) {
            return null;
        }
        var regex = /(-----\s*BEGIN ?[^-]+?-----)([\s\S]*)(-----\s*END ?[^-]+?-----)/;
        var matches = pem.match(regex);
        if (!matches || matches.length !== 4) {
            throw new Error("Invalid row certificate: " + pem);
        }
        // remove the first element that is the whole match
        matches.shift();
        // remove LF or CR
        matches = matches.map(function (element) {
            return element.trim();
        });
        // make sure '-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----' are in their own lines
        // and that it ends in a new line
        return matches.join('\n') + "\n";
    };
    return CertificateUtils;
}());
exports.CertificateUtils = CertificateUtils;
//# sourceMappingURL=CertificateUtils.js.map