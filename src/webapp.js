import express from "express";
import session from 'express-session'
import cookieParser from 'cookie-parser';
import {startDB} from "./db.js";
import {fileURLToPath} from 'url';
import {dirname} from 'path';
import {
    dashboard,
    doLogin,
    doRegisterUser,
    login,
    logout,
    passwordchange,
    usernamechange,
    displaynamechange,
    registerUser,
    token,
    doDisplaynamechange, doUsernamechange, doPasswordchange, getInformation
} from "./controller.js";
import * as bodyParser from "express";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const webapp = express()

webapp.use(cookieParser());
webapp.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}))

webapp.set('view engine', 'pug')
webapp.set('views', __dirname + '/../views')
webapp.use('/css', express.static(__dirname + '/../node_modules/bootstrap/dist/css'))
webapp.use('/js', express.static(__dirname + '/../node_modules/bootstrap/dist/js'))
webapp.use('/favicon.ico', express.static(__dirname + '/../public/images/favicon.ico'))
webapp.use('/images', express.static(__dirname + '/../public/images'))
webapp.use('/scripts', express.static(__dirname + '/../public/javascript'))
webapp.use('/sheets', express.static(__dirname + '/../public/css'))
webapp.use(express.json());
webapp.use(bodyParser.urlencoded({extended: true}));

//
// WEP PAGES
//

webapp.get('/', dashboard)

webapp.get('/info', getInformation)

webapp.get('/register', registerUser)

webapp.post('/register', doRegisterUser)

webapp.get('/logout', logout)

webapp.post('/login', doLogin)

webapp.get('/displaynamechange', displaynamechange)
webapp.get('/usernamechange', usernamechange)
webapp.get('/passwordchange', passwordchange)
webapp.post('/displaynamechange', doDisplaynamechange)
webapp.post('/usernamechange', doUsernamechange)
webapp.post('/passwordchange', doPasswordchange)
webapp.get('/token', token)

webapp.get('/login', login)

webapp.use((req, res, next) => {
    const err = new Error("Die angeforderte Seite konnte nicht gefunden werden.");
    err.status = 404;
    next(err);
});

webapp.use((err, req, res,_next) => {
    const statusCode = err.status || 500;
    let message = err.message || "Internal Server Error";

    if (statusCode === 500) {
        message = "Internal Server Error";
    }
    if(statusCode !== 404&&statusCode !== 400){
        console.log(err)
    }
    res.status(statusCode).render('error', {error: statusCode, message: message})
});

async function start() {
    await startDB().then(() => {
        console.log(`Verbindung zu Redis auf ${process.env.REDIS_HOST}:${process.env.REDIS_PORT} hergestellt.`)
        webapp.listen(80, () =>
            console.log(`Express wurde gestartet.`)
        );
    })
}

start().then(() => {
});
