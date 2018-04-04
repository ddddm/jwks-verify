'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
var jwt = require('jsonwebtoken');
var JwtVerifier = /** @class */ (function () {
    function JwtVerifier() {
    }
    JwtVerifier.Verify = function (req, publicKey, jwtIssuer, callback) {
        var header = req.header('Authorization');
        var token = (header && header.replace(/Bearer /, '')) || null;
        if (!token) {
            return callback("JWT token verification error");
        }
        jwt.verify(token, publicKey, { format: 'PKCS8', algorithms: ['RS256'], issuer: jwtIssuer }, function (errVerify, token) {
            if (errVerify) {
                return callback(errVerify);
            }
            return callback(errVerify, token);
        });
    };
    ;
    JwtVerifier.FormatCertificate = function (cert) {
        var beginCert = '-----BEGIN CERTIFICATE-----';
        var endCert = '-----END CERTIFICATE-----';
        cert = cert.replace('\n', '');
        cert = cert.replace(beginCert, '');
        cert = cert.replace(endCert, '');
        var result = beginCert;
        while (cert.length > 0) {
            if (cert.length > 64) {
                result += "\n" + cert.substring(0, 64);
                cert = cert.substring(64, cert.length);
            }
            else {
                result += "\n" + cert;
                cert = '';
            }
        }
        result += "\n" + endCert + "\n";
        return result;
    };
    ;
    return JwtVerifier;
}());
exports.default = JwtVerifier;
