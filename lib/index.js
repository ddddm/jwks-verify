'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
var async = require("async");
var NodeRSA = require("node-rsa");
var request = require("request");
var urlJoin = require("url-join");
var jwt_verifier_1 = require("./jwt-verifier");
var x509 = require('x509.js');
var OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration';
function JwksVerify(options) {
    if (!options) {
        throw new Error('Options are missing.');
    }
    if (!options.issuer) {
        throw new Error('issuer option is missing.');
    }
    var issuer = options.issuer;
    var OIDC_DISCOVERY_URI = urlJoin(issuer, OIDC_DISCOVERY_PATH);
    var publicKey;
    return function (req, res, next) {
        if (req.method.toLowerCase() === 'options' && !req.header('Authorization')) {
            return next();
        }
        if (!publicKey) {
            async.waterfall([
                function (callback) { return request.get(OIDC_DISCOVERY_URI, function (err, discoveryResponse) {
                    if (err) {
                        return callback(err);
                    }
                    return callback(null, JSON.parse(discoveryResponse.body).jwks_uri);
                }); },
                function (jwksUri, callback) { return request.get(jwksUri, function (err, jwksResponse) {
                    if (err) {
                        return callback(err);
                    }
                    return callback(null, JSON.parse(jwksResponse.body).keys[0].x5c[0]);
                }); },
                function (x5c, callback) {
                    var x5cFormatted = jwt_verifier_1.default.FormatCertificate(x5c);
                    var parsedKey = x509.parseCert(x5cFormatted);
                    var key = new NodeRSA();
                    key.importKey({
                        n: new Buffer(parsedKey.publicModulus, 'hex'),
                        e: parseInt(parsedKey.publicExponent, 16)
                    }, 'components-public');
                    publicKey = key.exportKey('public');
                    return callback(null);
                }
            ], function (err) {
                if (err) {
                    res.status(500);
                    return next(new Error('Application configuration error'));
                }
                jwt_verifier_1.default.Verify(req, publicKey, issuer, function (errVerify, token) {
                    if (errVerify) {
                        res.status(401);
                        return next(new Error(errVerify));
                    }
                    req.jwtToken = token;
                    return next();
                });
            });
        }
        else {
            jwt_verifier_1.default.Verify(req, publicKey, issuer, function (errVerify, token) {
                if (errVerify) {
                    res.status(401);
                    return next(new Error(errVerify));
                }
                req.jwtToken = token;
                return next();
            });
        }
    };
}
exports.default = JwksVerify;
;
