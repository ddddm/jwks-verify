/// <reference types="express" />
import * as express from 'express';
export default function JwksVerify(options: any): (req: any, res: express.Response, next: express.NextFunction) => void;
