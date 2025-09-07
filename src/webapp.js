import { admin } from "./controller.js";
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
    auth_request,
    passkeyAdd,
    passkeyManage,
    passkeyRemove,
    doPasskeyRemove,
    doDisplaynamechange,
    doUsernamechange,
    doPasswordchange, 
    getInformation,
    endpointGenerateAuthenticationOptions,
    endpointGenerateRegistrationOptions,
    endpointVerifyAuthenticationResponse,
    endpointVerifyRegistrationResponse
} from "./controller.js";
import { adminPasswordResetView, doAdminPasswordReset, inviteCreateView, inviteCreatePost, inviteDeleteView, inviteDeletePost, inviteRegistrationView, inviteRegistrationPost } from "./controller.js";

import { adminDeleteUserView, adminDeleteUserPost } from "./controller.js";
import * as bodyParser from "express";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const webapp = express()

webapp.use(cookieParser());
webapp.use(session({
    secret: process.env.SECRET,
    resave: true,
    proxy: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}))

webbapp.set('trust proxy', 1) // trust first proxy
webapp.set('view engine', 'pug')
webapp.set('views', __dirname + '/../views')
webapp.use('/css', express.static(__dirname + '/../node_modules/bootstrap/dist/css'))
webapp.use('/js', express.static(__dirname + '/../node_modules/bootstrap/dist/js'))
webapp.use('/webauthn', express.static(__dirname + '/../node_modules/@simplewebauthn/browser/dist/bundle/'))
webapp.use('/favicon.ico', express.static(__dirname + '/../public/images/favicon.ico'))
webapp.use('/images', express.static(__dirname + '/../public/images'))
webapp.use('/scripts', express.static(__dirname + '/../public/javascript'))
webapp.use('/sheets', express.static(__dirname + '/../public/css'))
webapp.use(express.json());
webapp.use(bodyParser.urlencoded({extended: true}));

//
// WEP PAGES
//

webapp.get('/health', (req, res) => {
    res.status(200).send('OK');
});

webapp.get('/auth_request', auth_request)

webapp.get('/', dashboard)

webapp.get('/admin', admin)
webapp.get('/admin/passwordreset/:username', adminPasswordResetView)
webapp.post('/admin/passwordreset/:username', doAdminPasswordReset)

// Admin: Nutzer löschen
webapp.get('/admin/deleteuser/:username', adminDeleteUserView)
webapp.post('/admin/deleteuser/:username', adminDeleteUserPost)

// Einladungslink-System
webapp.get('/admin/invite/create', inviteCreateView)
webapp.post('/admin/invite/create', inviteCreatePost)
webapp.get('/admin/invite/delete/:id', inviteDeleteView)
webapp.post('/admin/invite/delete/:id', inviteDeletePost)
webapp.get('/register/invite', inviteRegistrationView)
webapp.post('/register/invite', inviteRegistrationPost)

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

webapp.get('/passkeymanage', passkeyManage)
webapp.get('/passkeyadd', passkeyAdd)
webapp.get('/passkeyremove', passkeyRemove)
webapp.delete('/passkeyremove', doPasskeyRemove)

webapp.get('/generate-registration-options', endpointGenerateRegistrationOptions)
webapp.post('/verify-registration', endpointVerifyRegistrationResponse)
webapp.get('/generate-authentication-options', endpointGenerateAuthenticationOptions)
webapp.post('/verify-authentication', endpointVerifyAuthenticationResponse)

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
