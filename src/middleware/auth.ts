import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';



const middleware: any = {};

//function to check JWT token
middleware.verifyJWTToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.authToken;

  if (!token) {
    req.flash("error", "Tokenin yok");
    return res.redirect('/login');
  }
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY as string);
    (<any>req).user  = decoded;
  } catch (err) {
    req.flash("error", "Geçersiz token");
    return res.redirect('/login');
  }
  return next();
};

//function to check if user is logged in
middleware.isLoggedIn = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session.isLoggedIn) {
    console.log(req.session.isLoggedIn);
    req.flash("error", "Giriş yapman lazım");
    return res.redirect('/login');
  }
  next();
}


export default middleware;