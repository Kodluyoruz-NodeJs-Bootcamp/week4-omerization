import session from 'express-session';
import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from 'jsonwebtoken';


//types and interfaces globally declared below

declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: string;
    PORT: string;
    MONGO_URI: string;
  }
}

declare module 'express-session' {
  export interface SessionData {
      user: object;
      isLoggedIn: boolean;
  }
}

declare global {
  namespace Express {
      interface Request {
          user? : Record<string,any>
      }
  }
}


export {}