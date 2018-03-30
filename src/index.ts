'use strict';

import * as async from 'async';
import * as fs from 'fs';
import * as express from 'express';
import * as NodeRSA from 'node-rsa';
import * as path from 'path';
import * as request from 'request';
import * as urlJoin from 'url-join';
import jwtVerifier from './jwt-verifier';

const x509 = require('x509.js');

const OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration';

export default function JwksVerify(options: any) {
  if (!options) {
    throw new Error('Options are missing.');
  }

  if (!options.issuer) {
    throw new Error('issuer option is missing.');
  }

  const issuer = options.issuer;
  const OIDC_DISCOVERY_URI = urlJoin(issuer, OIDC_DISCOVERY_PATH);

  let publicKey: any;

  return function (req: any, res: express.Response, next: express.NextFunction) {
    if (req.method.toLowerCase() === 'options' && !req.header('Authorization')) {
      return next();
    }

    if (!publicKey) {
      async.waterfall(
        [
          (callback: any) => request.get(OIDC_DISCOVERY_URI, (err: any, discoveryResponse: any) => {
            if (err) {
              return callback(err);
            }

            return callback(null, JSON.parse(discoveryResponse.body).jwks_uri);
          }),
          (jwksUri: any, callback: any) => request.get(jwksUri, (err: any, jwksResponse: any) => {
            if (err) {
              return callback(err);
            }

            return callback(null, JSON.parse(jwksResponse.body).keys[0].x5c[0]);
          }),
           (x5c: any, callback: any) => {
            const x5cFormatted = jwtVerifier.FormatCertificate(x5c);
            const parsedKey = x509.parseCert(x5cFormatted);
            const key = new NodeRSA();

            key.importKey({
              n: new Buffer(parsedKey.publicModulus, 'hex'),
              e: parseInt(parsedKey.publicExponent, 16)
            }, 'components-public');
            publicKey = key.exportKey('public');

            return callback(null);
          }
        ],
        (err: any) => {
          if (err) {
            res.status(500);
            return next(new Error('Application configuration error'));
          }

          jwtVerifier.Verify(req, publicKey, issuer, (errVerify, token) => {
            if (errVerify) {
              res.status(401);
              return next(new Error(errVerify));
            }

            req.jwtToken = token;
            return next();
          });
        }
      );
    } else {
      jwtVerifier.Verify(req, publicKey, issuer, (errVerify, token)  => {
        if (errVerify) {
          res.status(401);
          return next(new Error(errVerify));
        }

        req.jwtToken = token;
        return next();
      });
    }
  };
};