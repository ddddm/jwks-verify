/// <reference types="express" />
/// <reference types="node" />
import * as express from 'express';
export default class JwtVerifier {
    static Verify(req: express.Request, publicKey: string | Buffer, jwtIssuer: string, callback: (err?: any, token?: string) => any): any;
    static FormatCertificate(cert: string): string;
}
