'use strict';

import * as express from 'express';
const jwt = require('jsonwebtoken');

export default class JwtVerifier {

  static Verify(req: express.Request, publicKey: string | Buffer, jwtIssuer: string, callback: (err?: any, token?: string) => any) {

    const header = req.header('Authorization');
    const token = (header && header.replace(/Bearer /, '')) || null;

    if (!token) {
      return callback("JWT token verification error");
    }

    jwt.verify(token, publicKey, { format: 'PKCS8', algorithms: ['RS256'], issuer: jwtIssuer }, (errVerify: object, token: string) => {
      if (errVerify) {
        return callback(errVerify);
      }

      return callback(errVerify, token);
    });
  };

  static FormatCertificate(cert: string): string {
    const beginCert = '-----BEGIN CERTIFICATE-----';
    const endCert = '-----END CERTIFICATE-----';

    cert = cert.replace('\n', '');
    cert = cert.replace(beginCert, '');
    cert = cert.replace(endCert, '');

    let result = beginCert;

    while (cert.length > 0) {
      if (cert.length > 64) {
        result += `\n${cert.substring(0, 64)}`;
        cert = cert.substring(64, cert.length);
      } else {
        result += `\n${cert}`;
        cert = '';
      }
    }

    result += `\n${endCert}\n`;

    return result;
  };
}
