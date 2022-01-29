
//necessary imports:
import express, { Application, Request, Response, NextFunction } from "express";
import session from 'express-session';
import flash from 'connect-flash';
import path from 'path';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken';
import auth from './middleware/auth';
import 'reflect-metadata';
import { createConnection, getRepository, getConnection, Repository } from "typeorm";
import { User } from "./entity/User";
import { Session } from './entity/Session';
import { TypeormStore } from "connect-typeorm";






//express configurations start
const app: Application = express();
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '/views'));
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(flash());
dotenv.config();
const { TOKEN_KEY, MYSQL_PASS } = process.env;


//session type declared
declare module 'express-session' {
    export interface SessionData {
        user: object;
        isLoggedIn: boolean;
    }
}



//typeorm connection 
createConnection().then(connection => {

    const repository = getConnection().getRepository(Session);


    app.use(
        session({
            resave: false,
            saveUninitialized: false,
            store: new TypeormStore({}).connect(repository),
            secret: "keyboard cat"
        })
    );

    app.use(function (req, res, next) {
        res.locals.currentUser = req.session.user;
        res.locals.error = req.flash("error");
        res.locals.success = req.flash("success");
        next();
    });


    //express configurations end




    // '/' url route renders login page
    app.get('/', async (req: Request, res: Response) => {
        res.render('login');
    });

    // '/login' url route renders login page
    app.get('/login', async (req: Request, res: Response) => {
        res.render('login');
    });

    // '/login' url post route 
    app.post('/login', async (req: Request, res: Response) => {
        try {

            const userRepository = getRepository(User);
            const sessionRepository = getRepository(Session);

            // Get user input
            const { email, password } = req.body;

            // Validate user input
            if (!(email && password)) {
                req.flash("error", "Mail ve şifre girmeniz gerekiyor!");
            }
            // Validate if user exist in our database
            const user = await userRepository.findOne({ email: email });

            if (user && (await bcrypt.compare(password, user.password))) {
                // Create token
                const token = jwt.sign(
                    { user_id: user.id, email },
                    TOKEN_KEY as string,
                    {
                        expiresIn: "2h",
                    }
                );

                // save user token
                user.token = token;

                await userRepository.save(user);

                // token added to cookies
                res.cookie('authToken', token);

                //save sessions
                req.session.isLoggedIn = true;
                req.session.user = user;
                req.session.save((err) => {
                    if (err) {
                        console.log(err);
                    }
                });

                res.redirect('/users');
            } else {
                //if mail or password is wrong, give feedback to user and redirect login page
                req.flash("error", "Mail veya şifre yanlış.");
                res.redirect('/login');
            }

        } catch (err) {
            //if anything goes wrong, give feedback to user and redirect login page
            console.log(err);
            console.log("something gone wrong");
            req.flash("error", "Mail veya şifre yanlış.");
            res.redirect('/login');
        }
    });

    // '/register' url get route 
    app.get('/register', async (req: Request, res: Response) => {
        res.render('register');
    });

    // '/register' url post route 
    app.post('/register', async (req: Request, res: Response) => {
        try {
            // Get user input
            const { first_name, last_name, email, password } = req.body;

            // Validate user input
            if (!(email && password && first_name && last_name)) {
                req.flash("error", "Hepsi doldurulmalı!");
                res.redirect('/register');
            }

            const userRepository = getRepository(User);

            // Validate if user exist in our database
            const oldUser = await userRepository.findOne({ email });


            // check if user already exist
            if (oldUser) {
                req.flash("error", "Bu üye zaten bulunuyor");
                res.redirect('/register');
            }

            //Encrypt user password
            const encryptedPassword = await bcrypt.hash(password, 10);

            // Create user in our database
            const user = new User();
            user.first_name = first_name;
            user.last_name = last_name;
            user.email = email;
            user.password = encryptedPassword;

            // Create token
            const token = jwt.sign(
                { user_id: user.id, email },
                TOKEN_KEY as string,
                {
                    expiresIn: "2h",
                }
            );
            // save user token
            user.token = token;

            await userRepository.save(user);


            req.flash("success", "Başarıyla kaydoldunuz.");
            res.redirect('/login');
        } catch (err) {
            console.log(err);
        }


    });

    // 'logout' get route
    app.get('/logout', async (req: Request, res: Response) => {
        // removes sessions and gives succesful feedback to user
        req.flash("success", "Çıkış yaptınız");
        req.session.destroy(err => {
            console.log(err);
            res.redirect('/');
        })
    });

    // '/users' get route, middlewares check JWT token and session info for authentication
    app.get('/users', [auth.verifyJWTToken, auth.isLoggedIn], async (req: Request, res: Response) => {

        const userRepository = getRepository(User);

        const allUsers = await userRepository.find()
        res.render('users', { users: allUsers });


    });

    // '/user-agreement' get route
    app.get('/user-agreement', async (req: Request, res: Response) => {
        res.render('user-agreement');
    });

    // 404 error page
    app.use((req: Request, res: Response, next: NextFunction) => {
        res.status(404).render('404');
    });






    //express port selection
    try {
        app.listen(3001, (): void => {
            console.log(`Connected successfully on port 3001`);
        });
    } catch (error) {
        console.error(`Error occured: ${error.message}`);
    }



}).catch(error => console.log(error));